# Assured Philly PM: pre-build demo site

A static page (no build step) showing three pieces of the Squarespace 7.1 + Google Workspace job,
built and tested before the job starts:

- **Live email-record check** for assuredphillypm.com (website, MX, SPF, DKIM, DMARC). It runs in the
  visitor's browser against Google Public DNS, with Cloudflare as a fallback. Nothing is stored.
- **Buy / Sell / Lease tabs** for Squarespace 7.1 Fluid Engine, shown working in an embedded demo page
  (`demo/services.html`), including what the client sees while editing.
- **Tenant Portal + Owner Portal header buttons** (Squarespace's header has one button; the snippet adds
  the second).

Search engines are kept out by `vercel.json` (`X-Robots-Tag: noindex, nofollow`) and a robots meta tag.

## Deploy

```
npx vercel --prod
```

Run it from this folder (where `index.html` and `vercel.json` are). Framework: none, no build
command, output directory `.`.

## Local preview and QA

```
npm install            # playwright-core and axe-core, only for QA
npm run serve          # http://localhost:4180
npm run qa             # 25 browser checks, desktop and phone
```

QA needs a local Chromium (the script looks in `/opt/pw-browsers`). It answers the DNS-over-HTTPS
requests from recorded fixtures (`tools/fixtures/zones.json`), so it runs without the network.

## Measured

Numbers are read from `data/summary.json`, written by the kit's test run. Tools: headless Chromium build
1243, Playwright 1.65.0, axe-core 4.14.0, Node 22.23.4.

| What | Result |
|---|---|
| Snippet browser checks: tabs, keyboard, deep links, phone widths, editor mode, JavaScript off, header buttons | 32 / 32 pass |
| axe-core WCAG 2.1 A/AA on the demo page with the tabs active | 0 violations (24 rules passed) |
| Layout shift on load, demo page with the snippet | 0 (Google's "good" threshold is under 0.1) |
| Snippet size, tabs + portal buttons together | 14,394 bytes; 4,847 bytes gzipped |
| Email checker: recorded DNS setups (Google Public DNS JSON format, real 2048- and 1024-bit RSA keys) | 18 / 18 scenarios, 49 / 49 expected verdicts |
| Planted bugs the tests must catch | 5 / 5 caught |
| This site's own QA (desktop 1360 px and phone 390 px) | 25 / 25 pass, 0 axe violations, no console errors |

The browser QA also caught one real bug in this site while it was being built: "Check again" re-used
cached DNS answers. Each check now uses a fresh resolver.

## Not measured

- **Inside a real Squarespace account.** The demo page is built from the attributes Squarespace documents
  as stable (section `id` from the anchor link, `data-sqsp-section`, `data-sqsp-block`) and the header
  classes production plugins target. It is not a Squarespace page.
- **The live DNS of assuredphillypm.com.** The build machine has no public DNS access, so the checker
  was tested on recorded fixtures; the live page reads the real records in the visitor's browser.
- **Whether a given browser can reach dns.google and cloudflare-dns.com.** If neither answers, the page
  says so and links to Google's Check MX tool.
- **Gmail delivery** (SPF / DKIM / DMARC PASS in "Show original"). That needs the client's Workspace.
- **Safari and Firefox.** All runs were Chromium.
- **Squarespace's own entrance animations and image loader.** The demo page imitates them; the snippet
  clears leftover animation classes and fires a resize event when a tab opens.
