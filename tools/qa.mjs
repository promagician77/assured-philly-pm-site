// Browser QA for the static site (desktop + phone). DNS-over-HTTPS requests are answered from
// recorded fixtures so the live-check UI is tested end to end without the network.
// node tools/qa.mjs <site-root> [screenshot-dir]
import { chromium } from "playwright-core";
import { readdirSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { serve } from "./serve.mjs";

const root = process.argv[2] || ".";
const shots = process.argv[3] || "/tmp/site-qa";
mkdirSync(shots, { recursive: true });
const srv = serve(root, 4188);
const { shared, scenarios } = JSON.parse(readFileSync(new URL("./fixtures/zones.json", import.meta.url)));
const byName = Object.fromEntries(scenarios.map((s) => [s.name, s]));
const axePath = ["../node_modules/axe-core/axe.min.js", "../../node_modules/axe-core/axe.min.js"].map((p) => new URL(p, import.meta.url).pathname).find(existsSync);
const ver = readdirSync("/opt/pw-browsers").find((d) => d.startsWith("chromium-"));
const browser = await chromium.launch({ executablePath: `/opt/pw-browsers/${ver}/chrome-linux64/chrome`, args: ["--no-sandbox"] });
let pass = 0, fail = 0;
const check = (name, ok, extra = "") => { ok ? pass++ : fail++; console.log(`${ok ? "ok  " : "FAIL"} ${name} ${extra}`); };

// Answer DoH queries: "assuredphillypm.com" is played as the chosen scenario's zone.
async function routeDns(page, state) {
  await page.route(/https:\/\/(dns\.google\/resolve|cloudflare-dns\.com\/dns-query)\?.*/, async (route) => {
    if (state.offline) return route.abort("internetdisconnected");
    const u = new URL(route.request().url());
    const s = byName[state.scenario];
    const name = u.searchParams.get("name").toLowerCase().replace(/assuredphillypm\.com$/, s.domain).replace(/^(.*\.)?complete\.example$/, (m) => m);
    const type = u.searchParams.get("type");
    const zone = { ...shared, ...s.zone, ...(state.extra ? byName[state.extra].zone : {}) };
    const body = zone[`${name}|${type}`] || { Status: 3 };
    await route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
  });
}
const rows = (page) => page.$$eval("#check-list li[data-key]", (ls) => Object.fromEntries(ls.map((l) => [l.dataset.key, l.dataset.status])));

for (const [tag, vp] of [["desktop", { width: 1360, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
  const ctx = await browser.newContext({ viewport: vp, ...(tag === "mobile" ? { isMobile: true, hasTouch: true, deviceScaleFactor: 2 } : {}) });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://localhost:4188" });
  const page = await ctx.newPage();
  const errors = [];
  const state = { scenario: "not-started" };
  // Network errors during the deliberate offline step are expected; everything else counts.
  page.on("console", (m) => m.type() === "error" && !state.offline && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await routeDns(page, state);
  await page.goto("http://localhost:4188/index.html");
  await page.waitForSelector('#check-list li[data-key="dmarc"]', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelector("#browser-results li"));

  const r1 = await rows(page);
  check(`${tag}: live check, nothing set up yet`, r1.website === "pass" && r1.mx === "fail" && r1.spf === "fail" && r1.dkim === "fail" && r1.dmarc === "warn", JSON.stringify(r1));
  const sum1 = await page.textContent("#check-sum");
  check(`${tag}: summary counts the records to add`, /^3 email records to add or fix/.test(sum1), sum1);
  check(`${tag}: measured numbers filled from summary.json`, await page.$$eval("[data-k]", (els) => els.every((e) => e.textContent.trim().length > 0)));
  check(`${tag}: test result lists rendered`, (await page.$$("#browser-results li")).length === 32 && (await page.$$("#checker-results li")).length === 18);
  const imgs = await page.$$eval("img", (is) => is.map((i) => i.complete && i.naturalWidth > 0));
  check(`${tag}: images load`, imgs.length >= 2 && imgs.every(Boolean), String(imgs.length));
  const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  check(`${tag}: no sideways scroll`, over <= 0, `${over}px`);
  await page.screenshot({ path: `${shots}/${tag}-full.png`, fullPage: true });

  if (tag === "desktop") {
    state.scenario = "complete";
    await page.fill("#domain", "assuredphillypm.com");
    await page.click("#check-form button");
    await page.waitForFunction(() => /in place/.test(document.querySelector("#check-sum").textContent));
    const r2 = await rows(page);
    check("desktop: live check, everything in place", Object.entries(r2).filter(([k]) => k !== "dns-host").every(([, v]) => v === "pass"), JSON.stringify(r2));
    await page.screenshot({ path: `${shots}/desktop-check-complete.png`, clip: { x: 0, y: 0, width: 1360, height: 900 } });

    state.scenario = "two-spf";
    await page.click("#check-form button");
    await page.waitForFunction(() => document.querySelector('#check-list li[data-key="spf"]')?.dataset.status === "fail");
    check("desktop: two SPF records flagged", /2 SPF records/.test(await page.textContent('#check-list li[data-key="spf"]')));

    state.offline = true;
    await page.click("#check-form button");
    await page.waitForFunction(() => /couldn't reach/.test(document.querySelector("#check-sum").textContent));
    check("desktop: resolvers unreachable -> clear message and Check MX link", (await page.$$('#check-list a[href*="checkmx"]')).length === 1);
    await page.waitForTimeout(100);
    state.offline = false;

    await page.fill("#domain", "not a domain");
    await page.click("#check-form button");
    check("desktop: invalid domain explained", /Enter a domain/.test(await page.textContent("#check-sum")));

    // demo
    await page.$eval("#tabs", (s) => s.scrollIntoView());
    const frame = page.frame({ url: /demo\/services\.html/ });
    await frame.waitForSelector('[role="tab"]');
    await page.click('[data-act="lease"]');
    await page.waitForTimeout(250);
    check("demo: 'Open /services#lease' selects Lease in the frame", (await frame.$eval('[role="tab"][aria-selected="true"]', (b) => b.textContent)) === "Lease");
    await page.click('[data-act="edit"]');
    await page.waitForTimeout(200);
    check("demo: editor view shows all sections, no tabs", (await frame.$$('[role="tab"]')).length === 0);
    await page.screenshot({ path: `${shots}/desktop-demo-edit.png`, clip: { x: 0, y: 0, width: 1360, height: 900 } });
    await page.click('[data-act="edit"]');
    await page.waitForTimeout(200);
    check("demo: leaving editor view brings tabs back", (await frame.$$('[role="tab"]')).length === 3);
    await page.click('[data-act="phone"]');
    await page.waitForTimeout(400);
    const w = await page.$eval("#demo-frame", (f) => f.getBoundingClientRect().width);
    check("demo: phone width toggle", Math.round(w) === 375, `${Math.round(w)}px`);
    await page.screenshot({ path: `${shots}/desktop-demo-phone.png`, clip: { x: 0, y: 0, width: 1360, height: 900 } });

    await page.click('.copy[data-copy^="v=spf1"]');
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    check("copy button puts the SPF record on the clipboard", clip === "v=spf1 include:_spf.google.com ~all", clip);

    const dl = await page.request.get("http://localhost:4188/downloads/assured-philly-pm-kit.zip");
    check("kit download served", dl.status() === 200 && (await dl.body()).length > 5000);

    if (axePath) {
      await page.addScriptTag({ path: axePath });
      const axe = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } })).violations.map((v) => `${v.id}:${v.nodes.length}`));
      check("site page: axe WCAG 2.1 A/AA violations = 0", axe.length === 0, axe.join(", "));
    }
  }
  check(`${tag}: no console errors`, errors.length === 0, errors.slice(0, 3).join(" | "));
  await ctx.close();
}
await browser.close();
srv.close();
console.log(`\n${pass}/${pass + fail} site checks passed`);
process.exit(fail ? 1 : 0);
