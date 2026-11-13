// Email-authentication and website DNS check for a Google Workspace + Squarespace domain.
// Runs in the browser (DNS-over-HTTPS) and in Node (tests feed recorded DoH answers).
// No dependencies. Every verdict is computed from the DNS answers; nothing is assumed.

export const SQUARESPACE_A = ["198.185.159.144", "198.185.159.145", "198.49.23.144", "198.49.23.145"];
export const SQUARESPACE_WWW = "ext-cust.squarespace.com";
const GOOGLE_MX = /^(smtp\.google\.com|aspmx\.l\.google\.com|alt[1-4]\.aspmx\.l\.google\.com|aspmx[2-5]\.googlemail\.com)$/;
const TYPE = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

// ---------- DNS-over-HTTPS (JSON API: Google, then Cloudflare) ----------
export function parseDoh(json, type) {
  // Status: 0 NOERROR, 3 NXDOMAIN, anything else is a resolver problem.
  if (!json || typeof json.Status !== "number") return { status: "error", answers: [] };
  if (json.Status === 3) return { status: "nxdomain", answers: [] };
  if (json.Status !== 0) return { status: "error", answers: [], code: json.Status };
  const want = TYPE[type];
  const answers = (json.Answer || []).filter((a) => a.type === want).map((a) => normalise(a.data, type));
  return { status: "ok", answers };
}

function normalise(data, type) {
  if (type === "TXT") {
    // TXT data arrives as one or more quoted strings: "v=DKIM1; k=rsa; p=MIIB" "...rest"
    const parts = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, "$1"));
    return parts.length ? parts.join("") : String(data);
  }
  return String(data).trim().toLowerCase();
}

export function makeDohResolver(fetchImpl = globalThis.fetch, endpoints) {
  const eps = endpoints || [
    (n, t) => [`https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`, {}],
    (n, t) => [`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`, { headers: { accept: "application/dns-json" } }],
  ];
  const cache = new Map();
  return async function resolve(name, type) {
    const key = `${name.toLowerCase()}|${type}`;
    if (cache.has(key)) return cache.get(key);
    let last = { status: "error", answers: [] };
    for (const ep of eps) {
      try {
        const [url, init] = ep(name, type);
        const res = await fetchImpl(url, init);
        if (!res.ok) { last = { status: "error", answers: [], http: res.status }; continue; }
        last = parseDoh(await res.json(), type);
        if (last.status !== "error") break;
      } catch (e) {
        last = { status: "error", answers: [], message: String(e && e.message || e) };
      }
    }
    cache.set(key, last);
    return last;
  };
}

// ---------- SPF evaluation (RFC 7208 limits) ----------
const LOOKUP_TERMS = /^(?:[+\-~?])?(include:|a$|a:|a\/|mx$|mx:|mx\/|ptr$|ptr:|exists:)/i;

export function spfRecords(txts) {
  return txts.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
}

export async function countSpf(domain, record, resolve, ctx = { lookups: 0, voids: 0, errors: [], seen: new Set(), tree: [] }, depth = 0) {
  ctx.seen.add(domain.toLowerCase());
  const terms = record.trim().split(/\s+/).slice(1);
  for (const term of terms) {
    const redirect = /^redirect=(.+)$/i.exec(term);
    const isLookup = LOOKUP_TERMS.test(term);
    if (!isLookup && !redirect) continue;
    ctx.lookups++;
    const include = /^[+\-~?]?include:(.+)$/i.exec(term);
    const target = include ? include[1] : redirect ? redirect[1] : null;
    ctx.tree.push({ depth, term });
    if (!target) continue;
    if (/%\{/.test(target)) continue; // macros are expanded per message; counted, not followed
    if (ctx.seen.has(target.toLowerCase())) { ctx.errors.push(`loop via ${target}`); continue; }
    const r = await resolve(target, "TXT");
    if (r.status === "error") { ctx.errors.push(`could not look up ${target}`); ctx.unknown = true; continue; }
    const recs = spfRecords(r.answers);
    if (r.status === "nxdomain" || r.answers.length === 0) ctx.voids++;
    if (recs.length !== 1) {
      ctx.errors.push(recs.length === 0 ? `${target} has no SPF record (permerror)` : `${target} has ${recs.length} SPF records (permerror)`);
      continue;
    }
    await countSpf(target, recs[0], resolve, ctx, depth + 1);
  }
  return ctx;
}

// ---------- DKIM key size (reads the RSA modulus out of the public key) ----------
function b64ToBytes(b64) {
  const clean = b64.replace(/\s+/g, "");
  if (typeof atob === "function") return Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
  return Uint8Array.from(Buffer.from(clean, "base64"));
}

export function rsaBits(pB64) {
  try {
    const d = b64ToBytes(pB64);
    let i = 0;
    const len = () => {
      let l = d[i++];
      if (l & 0x80) { let n = l & 0x7f; l = 0; while (n--) l = (l << 8) | d[i++]; }
      return l;
    };
    const enter = (tag) => { if (d[i++] !== tag) throw new Error("bad DER"); return len(); };
    enter(0x30);                      // SubjectPublicKeyInfo
    const algLen = enter(0x30); i += algLen; // AlgorithmIdentifier
    enter(0x03); i++;                 // BIT STRING + unused-bits byte
    enter(0x30);                      // RSAPublicKey
    let nLen = enter(0x02);           // modulus INTEGER
    while (d[i] === 0 && nLen > 0) { i++; nLen--; }
    const top = d[i];
    return (nLen - 1) * 8 + (32 - Math.clz32(top));
  } catch {
    // Fall back to the size of the encoded key.
    const n = b64ToBytes(pB64).length;
    return n < 200 ? 1024 : n < 400 ? 2048 : 4096;
  }
}

export function parseTags(rec) {
  const out = {};
  for (const part of rec.split(";")) {
    const m = /^\s*([a-zA-Z]+)\s*=\s*(.*?)\s*$/.exec(part);
    if (m) out[m[1].toLowerCase()] = m[2];
  }
  return out;
}

// ---------- the checks ----------
const row = (key, title, status, summary, extra = {}) => ({ key, title, status, summary, ...extra });

export async function checkDomain(domainIn, resolve, { selector = "google" } = {}) {
  const domain = String(domainIn).trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  const [ns, a, www, mx, txt, dkim, dmarc] = await Promise.all([
    resolve(domain, "NS"), resolve(domain, "A"), resolve(`www.${domain}`, "CNAME"), resolve(domain, "MX"),
    resolve(domain, "TXT"), resolve(`${selector}._domainkey.${domain}`, "TXT"), resolve(`_dmarc.${domain}`, "TXT"),
  ]);
  const results = [];

  if (ns.status === "nxdomain") {
    results.push(row("domain", "Domain", "fail", `${domain} does not exist in public DNS.`));
    return finish(domain, results);
  }

  // DNS host
  results.push(ns.status === "ok" && ns.answers.length
    ? row("dns-host", "Where the records live", "info", `Nameservers: ${ns.answers.map(stripDot).join(", ")}. MX, SPF, DKIM and DMARC are edited there.`, { records: ns.answers.map(stripDot) })
    : row("dns-host", "Where the records live", "unknown", "Could not read the nameservers."));

  // Website
  if (a.status === "error") results.push(row("website", "Website (Squarespace)", "unknown", "Could not read the A records."));
  else {
    const ips = a.answers;
    const onSq = ips.length > 0 && ips.every((ip) => SQUARESPACE_A.includes(ip));
    const wwwTarget = www.answers.map(stripDot)[0] || null;
    const wwwOk = wwwTarget === SQUARESPACE_WWW;
    const status = onSq && wwwOk ? "pass" : "warn";
    const summary = onSq && wwwOk ? "The domain and www both point to Squarespace."
      : ips.length === 0 && !wwwTarget ? "Not connected to a website yet. Fine before launch; Squarespace sets these when the domain is connected."
      : `Root points to ${ips.join(", ") || "nothing"}; www points to ${wwwTarget || "nothing"}. Squarespace expects ${SQUARESPACE_A.join(", ")} and www → ${SQUARESPACE_WWW}.`;
    results.push(row("website", "Website (Squarespace)", status, summary, { records: [ips.length ? ips.join(", ") : "no A record", wwwTarget ? `www → ${wwwTarget}` : "www: no CNAME"] }));
  }

  // MX
  if (mx.status === "error") results.push(row("mx", "MX (incoming mail)", "unknown", "Could not read the MX records."));
  else {
    const recs = mx.answers.map((m) => { const [p, h] = m.split(/\s+/); return { pri: Number(p), host: stripDot(h || "") }; });
    const google = recs.filter((r) => GOOGLE_MX.test(r.host));
    const other = recs.filter((r) => !GOOGLE_MX.test(r.host));
    let st, msg;
    if (!recs.length) { st = "fail"; msg = "No MX record, so mail to contact@ and info@ has nowhere to go. Add MX 1 smtp.google.com."; }
    else if (other.length && google.length) { st = "fail"; msg = `Google plus another provider (${other.map((r) => r.host).join(", ")}). Mail can land in the wrong place; remove the others.`; }
    else if (other.length) { st = "fail"; msg = `Mail goes to ${other.map((r) => r.host).join(", ")}, not Google Workspace.`; }
    else if (google.some((r) => r.host === "smtp.google.com")) { st = "pass"; msg = "Incoming mail goes to Google Workspace (current single record, smtp.google.com)."; }
    else { st = "pass"; msg = "Incoming mail goes to Google Workspace (legacy ASPMX set, which Google still supports)."; }
    results.push(row("mx", "MX (incoming mail)", st, msg, { records: recs.map((r) => `${r.pri} ${r.host}`) }));
  }

  // SPF
  if (txt.status === "error") results.push(row("spf", "SPF (who may send)", "unknown", "Could not read the TXT records."));
  else {
    const recs = spfRecords(txt.answers);
    if (!recs.length) results.push(row("spf", "SPF (who may send)", "fail", "No SPF record. Add TXT @  v=spf1 include:_spf.google.com ~all", { records: [] }));
    else if (recs.length > 1) results.push(row("spf", "SPF (who may send)", "fail", `${recs.length} SPF records. RFC 7208 allows one; with two, SPF fails for every message. Merge them into one.`, { records: recs }));
    else {
      const rec = recs[0];
      const authorisesGoogle = /(^|\s)[+]?(include:|redirect=)_spf\.google\.com(\s|$)/i.test(rec);
      const allMatch = /\s([+\-~?]?)all(\s|$)/i.exec(` ${rec}`);
      const all = allMatch ? allMatch[1] || "+" : undefined; // a bare "all" means +all
      const ctx = await countSpf(domain, rec, resolve);
      const problems = [];
      if (!authorisesGoogle) problems.push("does not include _spf.google.com, so Gmail's own servers are not authorised");
      if (all === "+") problems.push("ends in +all, which authorises every server on the internet");
      if (ctx.lookups > 10) problems.push(`needs ${ctx.lookups} DNS lookups; the limit is 10 (permerror)`);
      if (ctx.voids > 2) problems.push(`${ctx.voids} empty lookups; the limit is 2`);
      problems.push(...ctx.errors.filter((e) => !/could not look up/.test(e)));
      const st = problems.length ? "fail" : ctx.unknown ? "unknown" : all === undefined ? "warn" : "pass";
      const msg = problems.length ? `SPF ${problems.join("; ")}.`
        : ctx.unknown ? "SPF found, but an include could not be looked up right now."
        : all === undefined ? `Authorises Google, but has no closing "all" term. Add ~all. ${ctx.lookups} of 10 lookups used.`
        : `Authorises Google Workspace. ${ctx.lookups} of 10 DNS lookups used, ${10 - ctx.lookups} left for AppFolio, Buildium, a CRM or other senders.`;
      results.push(row("spf", "SPF (who may send)", st, msg, { records: [rec], lookups: ctx.lookups, voids: ctx.voids }));
    }
  }

  // DKIM
  if (dkim.status === "error") results.push(row("dkim", "DKIM (signature)", "unknown", "Could not read the DKIM record."));
  else {
    const rec = dkim.answers.find((t) => /(^|;)\s*p=/i.test(t) || /v=DKIM1/i.test(t));
    if (!rec) results.push(row("dkim", "DKIM (signature)", "fail", `No key at ${selector}._domainkey. Gmail then signs with Google's default domain, which does not align with yours for DMARC. Generate a 2048-bit key in the Admin console.`, { records: [] }));
    else {
      const tags = parseTags(rec);
      if (!tags.p) results.push(row("dkim", "DKIM (signature)", "fail", "The DKIM record has an empty key (p=), which means the key is revoked.", { records: [rec] }));
      else {
        const bits = rsaBits(tags.p);
        const st = bits >= 2048 ? "pass" : "warn";
        const msg = bits >= 2048 ? `${bits}-bit key published at ${selector}._domainkey. Remember to click "Start authentication" in the Admin console.`
          : `${bits}-bit key. It works, but Google recommends 2048-bit when the DNS host supports it.`;
        results.push(row("dkim", "DKIM (signature)", st, msg, { records: [rec.length > 90 ? rec.slice(0, 60) + "…" + rec.slice(-20) : rec], bits }));
      }
    }
  }

  // DMARC
  if (dmarc.status === "error") results.push(row("dmarc", "DMARC (policy)", "unknown", "Could not read the DMARC record."));
  else {
    const recs = dmarc.answers.filter((t) => /^v=DMARC1/i.test(t.trim()));
    if (!recs.length) results.push(row("dmarc", "DMARC (policy)", "warn", "No DMARC record. Gmail requires it only above 5,000 messages a day, but Google recommends it for everyone. Add p=none with a report address once SPF and DKIM have run for 48 hours.", { records: [] }));
    else if (recs.length > 1) results.push(row("dmarc", "DMARC (policy)", "fail", `${recs.length} DMARC records; receivers ignore DMARC when there is more than one.`, { records: recs }));
    else {
      const t = parseTags(recs[0]);
      const p = (t.p || "").toLowerCase();
      if (!["none", "quarantine", "reject"].includes(p)) results.push(row("dmarc", "DMARC (policy)", "fail", "The DMARC record has no valid p= policy.", { records: recs }));
      else {
        const reports = t.rua ? ` Reports go to ${t.rua.replace(/^mailto:/i, "")}.` : " No report address (rua), so nobody sees the results.";
        const msg = p === "none" ? `Monitoring mode (p=none), Google's recommended start.${reports}` : `Enforced (p=${p}).${reports}`;
        results.push(row("dmarc", "DMARC (policy)", t.rua ? "pass" : "warn", msg, { records: recs, policy: p }));
      }
    }
  }
  return finish(domain, results);
}

function stripDot(s) { return String(s).replace(/\.$/, "").toLowerCase(); }

function finish(domain, results) {
  const by = Object.fromEntries(results.map((r) => [r.key, r.status]));
  const ok = (s) => s === "pass" || s === "warn";
  const mailReady = by.mx === "pass" && ok(by.spf) && ok(by.dkim) && by.dmarc !== "fail" && by.dmarc !== "unknown";
  const todo = results.filter((r) => r.status === "fail").map((r) => r.key);
  return { domain, checkedAt: new Date().toISOString(), results, mailReady, todo };
}
