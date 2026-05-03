# 🎯 BountyKit

> **All-in-one bug bounty recon toolkit — right inside your Firefox sidebar.**

BountyKit is a Firefox extension built for bug bounty hunters and security researchers. Instead of juggling multiple tools, BountyKit passively fingerprints everything as you browse — paths, technologies, cookies, CORS, CSRF, IDOR patterns, SSL/TLS, and more — all in a persistent sidebar that never closes.

---

## ✨ Features

### 🗺️ Recon
- **Path & Endpoint Discovery** — captures every request (XHR, fetch, links, SPA routes)
- **External Request Tracker** — full URL of cross-origin requests with automatic CDN/WAF tagging
- **Subdomain Sniffer** — detects subdomains referenced during browsing
- **Parameter Miner** — collects all URL parameters and the endpoints they appear in

### 🔬 Technology Fingerprinting
- Detects **50+ frameworks and libraries** from JS globals, meta tags, script sources, and response headers
- Identifies frontend (React, Vue, Angular, jQuery...), backend (PHP, Express, Nginx...), CMS (WordPress, Drupal, Shopify...), and analytics tools
- **Passive SSL/TLS detection** — protocol version, certificate CA, expiry, self-signed check, SHA-256 fingerprint
- **Qualys SSL Labs deep scan** — grade (A+ to F), TLS support matrix, vulnerability checks (Heartbleed, POODLE, FREAK, DROWN, Logjam, and more), forward secrecy, HSTS

### 🍪 Client Data
- **Cookie Inspector** — flags missing `HttpOnly`, `Secure`, `SameSite` attributes
- **localStorage & sessionStorage** — full key-value dump
- **postMessage Sniffer** — captures all `postMessage` events with origin tracking

### 🌐 Network Analysis
- **CORS Detector** — flags `Access-Control-Allow-Origin: *` as HIGH risk
- **Redirect Tracer** — logs all 301/302/307/308 redirect chains
- **Error Leaker** — captures 4xx/5xx responses and extracts server info from headers
- **WebSocket Watcher** — monitors WebSocket connections and messages

### 🛡️ Security Analysis
- **Form & CSRF Scanner** — detects all forms, flags missing CSRF tokens
- **CSP Analyzer** — checks for missing or weak Content Security Policy headers
- **GraphQL Detector** — identifies GraphQL endpoints
- **IDOR Candidate Mapper** — flags URLs with numeric IDs, UUIDs, and IDOR-prone patterns
- **Clickjacking Checker** — detects missing `X-Frame-Options` and `frame-ancestors`
- **Prototype Pollution Monitor** — watches for unexpected `Object.prototype` mutations

### ⚡ Active Scans (Manual)
- **Qualys SSL Deep Scan** — runs in background, survives sidebar close
- **Sensitive File Discovery** — probes `.env`, `.git/config`, `phpinfo.php`, `wp-config.php`, `swagger.json`, admin panels, and more

---

## 🖥️ Screenshots

> Sidebar stays open while you browse — no more popup that disappears.

```
┌─────────────────────────────────────┐
│ 🎯 BountyKit    [⚡ New Scan] [⬇] [🗑] │
│ target: target.com                  │
├────┬────────────────────────────────┤
│ 🗺️ │ 🔬 TECHNOLOGY                  │
│ 12 │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  │
│ 🔬 │ [frontend] React  18.2.0       │
│  5 │ [backend]  Nginx  1.24.0       │
│ 🍪 │ [cms]      WordPress detected  │
│  8 │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  │
│ 🌐 │ 🔒 HTTPS  TLS 1.3              │
│  3 │ CA: Let's Encrypt              │
│ 🛡️ │ Valid Until: 2025-09-12        │
│  6 │                                │
│ ── │ ── Deep Scan ──────────────── │
│ ⚡ │ [🔬 Deep Scan via Qualys]      │
│ ⚙️ │                                │
└────┴────────────────────────────────┘
```

---

## 🚀 Installation

### Developer Mode (Firefox Developer Edition — Recommended)

1. Download [Firefox Developer Edition](https://www.mozilla.org/en-US/firefox/developer/)
2. Open `about:config` → set `xpinstall.signatures.required` to `false`
3. Open `about:addons` → click ⚙️ → **Install Add-on From File**
4. Select `manifest.json` from the extracted folder

### Temporary Install (Any Firefox)

1. Open `about:debugging` → **This Firefox**
2. Click **Load Temporary Add-on**
3. Select `manifest.json` from the extracted folder
4. ⚠️ Note: temporary installs are removed when Firefox closes

### Keyboard Shortcut

```
Ctrl + Shift + Y  →  Toggle BountyKit sidebar
```

---

## 📦 What's Inside

```
bountykit/
├── manifest.json     # Extension config (Manifest V2)
├── background.js     # Central engine — passive collection + active scan runners
├── content.js        # Page injection — DOM harvest, storage, forms, WS, postMessage
├── sidebar.html      # Sidebar UI
├── sidebar.js        # UI logic + rendering + export
└── icons/
    └── icon.svg
```

---

## 🔴 Active vs 🟢 Passive Modules

| Module | Mode | Description |
|---|---|---|
| Path Discovery | 🟢 Auto | Intercepts all browser requests |
| External Requests | 🟢 Auto | Cross-origin URLs with CDN/WAF tags |
| Tech Fingerprinting | 🟢 Auto | JS globals, headers, meta tags, script srcs |
| Cookie Inspector | 🟢 Auto | Real-time flag analysis |
| Storage Inspector | 🟢 Auto | localStorage + sessionStorage dump |
| CORS Detector | 🟢 Auto | Passive header analysis |
| CSRF Checker | 🟢 Auto | DOM form scanning |
| IDOR Mapper | 🟢 Auto | Pattern matching on request URLs |
| Clickjack Checker | 🟢 Auto | Header analysis on page load |
| Qualys SSL Deep Scan | 🔴 Manual | Triggers external scan — runs in background |
| Sensitive File Discovery | 🔴 Manual | Sends HEAD requests to common sensitive paths |

---

## ⚠️ Legal & Ethical Use

BountyKit is built for **authorized security testing only**.

- Only use on targets within your bug bounty program scope
- Active scan features (Qualys SSL, Sensitive File Discovery) send external requests — confirm this is allowed under your program's rules
- The Qualys SSL scan uses the [SSL Labs public API](https://www.ssllabs.com/projects/ssllabs-api/) — their [terms of service](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf) apply

---

## 📤 Export

Click **⬇** to export everything to a single `.txt` file:

```
# BountyKit Export — target.com
# Generated: 2026-05-03T10:22:00.000Z

## RECON — PATHS & ENDPOINTS
GET /api/v1/users
GET /api/v1/orders?id=1234

## TECHNOLOGY
[frontend] React | 18.2.0 | JS Global
[backend] Nginx | 1.24.0 | Header: server

## PROTOCOL & SSL/TLS
Scheme: HTTPS
TLS: TLSv1.3
CA: Let's Encrypt
Valid Until: 2025-09-12

## SSL DEEP SCAN (Qualys)
Grade: A+
TLS 1.3: Supported
Heartbleed: Not vulnerable
POODLE: Not vulnerable
...

## SECURITY — FORMS & CSRF
POST /login | CSRF: NO ⚠️ | fields: 3
POST /transfer | CSRF: NO ⚠️ | fields: 4

## SECURITY — IDOR CANDIDATES
/api/v1/users/1337
/api/v1/orders/8842
```

---

## 🗺️ Roadmap

### Phase 1 ✅ (Current)
All passive modules + Qualys SSL deep scan + Sensitive file discovery

### Phase 2 🔜
- CORS Probe (active origin manipulation)
- Auth Bypass Detector
- Cache Poison Detector
- Timing Analyzer
- Race Condition Detector
- Clickjack iframe tester

### Phase 3 🔜
- Report generator (HTML + Markdown)
- Severity scoring per finding
- Custom wordlist for file discovery
- Per-domain scan history

---

## 🛠️ Built With

- Firefox WebExtension APIs (`webRequest`, `cookies`, `sidebarAction`, `tabs`)
- Vanilla JS — zero dependencies
- [Qualys SSL Labs API](https://api.ssllabs.com/api/v3/)
- Fonts: [JetBrains Mono](https://www.jetbrains.com/legalnotice/), [Syne](https://fonts.google.com/specimen/Syne)

---

## 👤 Author

**RedNeutron**

> Built for the community. Hunt responsibly. 🎯

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
