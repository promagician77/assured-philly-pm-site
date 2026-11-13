import { checkDomain, makeDohResolver } from "./js/check-domain.js";

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// ---------------- live check ----------------
const LABEL = { pass: "Ready", warn: "Review", fail: "Fix", unknown: "No answer", info: "Info" };
const ICON = {
  pass: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3v6.5M8 12.6v.4" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
  fail: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
  unknown: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5.6 6a2.5 2.5 0 114 2c-.9.6-1.6 1-1.6 2.2M8 13v.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  info: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 7v5.5M8 3.6v.4" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
};
const ORDER = ["website", "mx", "spf", "dkim", "dmarc", "dns-host", "domain"];

function renderLoading() {
  $("#check-list").innerHTML = ["Website (Squarespace)", "MX (incoming mail)", "SPF (who may send)", "DKIM (signature)", "DMARC (policy)"]
    .map((t) => `<li class="loading"><span class="badge st-unknown">…</span><span class="what">${t}</span><p class="why">Looking it up</p></li>`).join("");
}

function render(report) {
  const rows = [...report.results].sort((a, b) => ORDER.indexOf(a.key) - ORDER.indexOf(b.key));
  const allUnknown = rows.filter((r) => r.key !== "dns-host").every((r) => r.status === "unknown");
  if (allUnknown) {
    $("#check-sum").textContent = "Your browser couldn't reach the public DNS resolvers.";
    $("#check-list").innerHTML = `<li class="check-error">Check your connection and press Check again, or use Google's own <a href="https://toolbox.googleapps.com/apps/checkmx/" target="_blank" rel="noopener">Check MX tool</a> for the same records.</li>`;
    return;
  }
  const fails = rows.filter((r) => r.status === "fail" && r.key !== "website").length;
  const unknown = rows.some((r) => r.status === "unknown");
  let sum;
  if (rows.some((r) => r.key === "domain")) sum = `${report.domain} isn't in public DNS.`;
  else if (report.mailReady) sum = "Email records are in place.";
  else if (fails) sum = `${fails} email record${fails > 1 ? "s" : ""} to add or fix before contact@ sends and receives reliably.`;
  else sum = unknown ? "Some lookups didn't answer. Press Check again." : "Almost there: see the rows marked Review.";
  $("#check-sum").textContent = sum;
  $("#check-list").innerHTML = rows.map((r) => `
    <li data-key="${esc(r.key)}" data-status="${esc(r.status)}">
      <span class="badge st-${esc(r.status)}">${ICON[r.status] || ""}${LABEL[r.status] || r.status}</span>
      <span class="what">${esc(r.title)}</span>
      <p class="why">${esc(r.summary)}</p>
      ${r.records && r.records.length ? `<p class="recs">${r.records.map(esc).join("<br>")}</p>` : ""}
    </li>`).join("");
  $("#check-time").textContent = `Checked at ${new Date(report.checkedAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.`;
}

async function runCheck(domain) {
  document.querySelectorAll("[data-domain]").forEach((el) => (el.textContent = domain));
  $("#check-sum").textContent = "Reading the public DNS records…";
  renderLoading();
  try {
    // A fresh resolver each time, so "Check again" really asks DNS again.
    render(await checkDomain(domain, makeDohResolver()));
  } catch (e) {
    $("#check-sum").textContent = "The check stopped with an error.";
    $("#check-list").innerHTML = `<li class="check-error">${esc(e.message || e)}. Press Check again.</li>`;
  }
}

$("#check-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const d = $("#domain").value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) { $("#check-sum").textContent = "Enter a domain like assuredphillypm.com."; return; }
  $("#domain").value = d;
  runCheck(d);
});
const fromQuery = new URLSearchParams(location.search).get("domain");
if (fromQuery) $("#domain").value = fromQuery;
runCheck($("#domain").value);

// ---------------- measured numbers ----------------
fetch("data/summary.json").then((r) => r.json()).then((S) => {
  const kb = (b) => `${(b / 1024).toFixed(1)} KB`;
  const set = {
    browser: `${S.browser.passed} of ${S.browser.total}`,
    axe: String(S.browser.axe.violations),
    verdicts: `${S.checker.verdicts} of ${S.checker.verdicts}`,
    scenarios: String(S.checker.scenarios),
    gzip: kb(S.snippet.fullGzip),
    chromium: S.env.chromium.replace("chromium-", "build "),
    axever: S.env.axe,
    mutations: `${S.mutations.caught} of ${S.mutations.total}`,
    scenarioline: `${S.checker.passed} of ${S.checker.scenarios} DNS setups`,
  };
  if (S.checker.passed !== S.checker.scenarios) set.verdicts = `${S.checker.rows.filter((r) => r.ok).length} scenarios right out of ${S.checker.scenarios}`;
  document.querySelectorAll("[data-k]").forEach((el) => { if (set[el.dataset.k] !== undefined) el.textContent = set[el.dataset.k]; });
  const li = (ok, name, det) => `<li><span class="tick ${ok ? "" : "no"}" aria-label="${ok ? "passed" : "failed"}">${ok ? "✓" : "✗"}</span><span>${esc(name)}${det ? `<span class="det">${esc(det)}</span>` : ""}</span></li>`;
  $("#browser-results").innerHTML = S.browser.checks.map((c) => li(c.ok, c.name, "")).join("");
  $("#checker-results").innerHTML = S.checker.rows.map((r) => {
    const exp = Object.entries(r.expected).filter(([k]) => !["lookups", "bits"].includes(k)).map(([k, v]) => `${k} ${v}`).join(", ");
    return li(r.ok, r.desc, exp);
  }).join("");
}).catch(() => {});

// ---------------- demo controls ----------------
const frame = $("#demo");
const frameBox = $("#demo-frame");
document.querySelectorAll(".demo-bar button").forEach((b) => b.addEventListener("click", () => {
  const doc = frame.contentDocument;
  const act = b.dataset.act;
  if (act === "lease" && frame.contentWindow) frame.contentWindow.location.hash = "lease";
  if (act === "phone") {
    const on = frameBox.classList.toggle("is-phone");
    b.setAttribute("aria-pressed", String(on));
  }
  if (act === "edit" && doc) {
    const on = doc.body.classList.toggle("sqs-edit-mode-active");
    b.setAttribute("aria-pressed", String(on));
  }
}));

// ---------------- copy buttons ----------------
document.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Copied"; b.classList.add("is-done"); }
  catch { b.textContent = "Select and copy"; }
  setTimeout(() => { b.textContent = "Copy"; b.classList.remove("is-done"); }, 1800);
}));
