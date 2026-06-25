# 🦅 GarudaNetra — QR & URL Threat Scanner

A professional, fully client-side cybersecurity web app that **decodes QR codes** and
**analyzes the embedded URLs for phishing and malicious indicators**. Everything runs
locally in the browser — no link or image ever leaves the device.

## Features

- **QR upload** — drag & drop or browse an image; decoded with [jsQR].
- **Live camera scanning** — automatic detection from the device camera.
- **Manual URL analysis** — paste any link to run the full check.
- **Risk score (0–100)** with a clear **Safe / Suspicious / Dangerous** verdict.
- **Threat explanation** — every triggered signal is shown with a plain-English reason
  and its weight, plus the checks that passed.
- **PDF reports** — branded, downloadable threat report per scan ([jsPDF]).
- **Home page** — intro to the app, feature overview, how-it-works, plus a live stats strip and threat-distribution donut.
- **Scan history** — searchable, filterable, per-row view / re-export / delete.
- **Dark / light mode** — remembered between sessions.
- **Responsive modern UI** — works on desktop, tablet, and mobile.

## Detection signals

GarudaNetra evaluates each URL against weighted heuristics used to spot phishing, e.g.
no-HTTPS, raw-IP hosts, `@` tricks, punycode/homograph domains, URL shorteners,
high-risk TLDs, brand impersonation & look-alike domains, sensitive-action keywords,
embedded credentials, non-standard ports, obfuscated encoding, and disguised payloads.
Matched signals add to the 0–100 score:

| Score  | Verdict     |
|--------|-------------|
| 0–34   | Safe        |
| 35–64  | Suspicious  |
| 65–100 | Dangerous   |

## Running it

Just open `index.html` in a browser for upload/manual analysis.

**Camera scanning** requires a secure context (`localhost` or HTTPS). Start a local
server from this folder:

```powershell
python -m http.server 8000
```

Then visit <http://localhost:8000>.

## Project structure

```
index.html          App shell + all views
css/styles.css      Theme tokens, layout, components, responsive rules
js/storage.js       localStorage history + theme persistence
js/analyzer.js      Heuristic phishing analysis engine (risk scoring)
js/scanner.js       QR decoding (file + camera) via jsQR
js/report.js        Branded PDF report generation via jsPDF
js/dashboard.js     Home stats + threat-distribution donut
js/app.js           Routing, theme, scan flow, result + history rendering
```

## Disclaimer

GarudaNetra uses heuristic analysis and is an **assistive tool, not a guarantee**.
Always exercise caution before opening untrusted links.

[jsQR]: https://github.com/cozmo/jsQR
[jsPDF]: https://github.com/parallax/jsPDF
