// background.js — BountyKit v1.0
// Central engine: passive data collection + active scan runners

// ══════════════════════════════════
// STATE STORE
// ══════════════════════════════════
const store = {};
// { tabId: { url, origin, recon, technology, clientData, network, security, activeScans } }

function ensureTab(tabId, url) {
  if (!store[tabId]) {
    store[tabId] = {
      url: url || "",
      origin: "",
      recon: {
        paths: new Map(),       // path -> { method, type }
        external: new Map(),    // url -> { url, type, tags[] }
        subdomains: new Set(),
        parameters: new Map(),  // name -> Set of endpoints
        sensitiveFiles: [],
      },
      technology: {
        techs: [],              // { cat, name, version, source }
        protocol: null,
        qualys: null,
      },
      clientData: {
        cookies: [],
        localStorage: [],
        sessionStorage: [],
        postMessages: [],
      },
      network: {
        headers: {},            // url -> { req, res }
        cors: [],
        redirects: [],
        websockets: [],
        errors: [],             // 4xx/5xx responses
        timings: [],
      },
      security: {
        forms: [],
        csp: null,
        graphql: [],
        idors: [],
        prototypePollution: [],
        clickjack: null,
      },
    };
  }
}

function getTab(tabId) {
  ensureTab(tabId);
  return store[tabId];
}

// ══════════════════════════════════
// HELPERS
// ══════════════════════════════════
function extractPath(url) {
  try { const u = new URL(url); return u.pathname + (u.search || ""); } catch { return url; }
}

function isSameOrigin(origin, url) {
  try { return new URL(url).origin === origin; } catch { return false; }
}

function getOrigin(url) {
  try { return new URL(url).origin; } catch { return ""; }
}

// ══════════════════════════════════
// MODULE: TECH FINGERPRINTING
// ══════════════════════════════════
const HEADER_TECH_RULES = [
  { header: "server", regex: /Apache\/?([0-9.]*)/i,        cat: "backend",  name: "Apache" },
  { header: "server", regex: /nginx\/?([0-9.]*)/i,         cat: "backend",  name: "Nginx" },
  { header: "server", regex: /Microsoft-IIS\/?([0-9.]*)/i, cat: "backend",  name: "IIS" },
  { header: "server", regex: /LiteSpeed\/?([0-9.]*)/i,     cat: "backend",  name: "LiteSpeed" },
  { header: "server", regex: /cloudflare/i,                 cat: "backend",  name: "Cloudflare", fixed: "CDN" },
  { header: "server", regex: /openresty\/?([0-9.]*)/i,     cat: "backend",  name: "OpenResty" },
  { header: "server", regex: /gunicorn\/?([0-9.]*)/i,      cat: "backend",  name: "Gunicorn" },
  { header: "x-powered-by", regex: /PHP\/?([0-9.]*)/i,     cat: "backend",  name: "PHP" },
  { header: "x-powered-by", regex: /Express\/?([0-9.]*)/i, cat: "backend",  name: "Express.js" },
  { header: "x-powered-by", regex: /ASP\.NET\s?([0-9.]*)/i,cat: "backend",  name: "ASP.NET" },
  { header: "x-powered-by", regex: /Next\.js\s?([0-9.]*)/i,cat: "frontend", name: "Next.js" },
  { header: "x-powered-by", regex: /Nuxt\s?([0-9.]*)/i,   cat: "frontend", name: "Nuxt.js" },
  { header: "x-generator",  regex: /WordPress\s?([0-9.]*)/i,cat: "cms",     name: "WordPress" },
  { header: "x-drupal-cache",regex: /.*/,                   cat: "cms",      name: "Drupal", fixed: "detected" },
];

const CDN_URL_RULES = [
  { regex: /cloudfront\.net/i,        label: "CDN: AWS CloudFront" },
  { regex: /akamaiedge\.net/i,        label: "CDN: Akamai" },
  { regex: /fastly\.net/i,            label: "CDN: Fastly" },
  { regex: /cdn\.jsdelivr\.net/i,     label: "CDN: jsDelivr" },
  { regex: /cdnjs\.cloudflare\.com/i, label: "CDN: Cloudflare" },
  { regex: /cloudflare\.com/i,        label: "CDN/WAF: Cloudflare" },
  { regex: /azureedge\.net/i,         label: "CDN: Azure" },
  { regex: /gstatic\.com/i,           label: "CDN: Google Static" },
  { regex: /unpkg\.com/i,             label: "CDN: unpkg" },
  { regex: /sucuri\.net/i,            label: "CDN/WAF: Sucuri" },
];

const WAF_HEADER_RULES = [
  { header: "cf-ray",             label: "WAF/CDN: Cloudflare" },
  { header: "x-sucuri-id",        label: "WAF: Sucuri" },
  { header: "x-imperva-session",  label: "WAF: Imperva" },
  { header: "x-iinfo",            label: "WAF: Imperva" },
  { header: "x-firewall-protection", label: "WAF detected" },
  { header: "x-protected-by",    label: "WAF: Protected-By" },
];

function addTech(tabId, cat, name, version, source) {
  const techs = store[tabId].technology.techs;
  const exists = techs.find(t => t.name === name);
  if (!exists) techs.push({ cat, name, version: version || "detected", source });
  else if (version && exists.version === "detected") exists.version = version;
}

// ══════════════════════════════════
// MODULE: SECURITY HEADERS (CSP)
// ══════════════════════════════════
const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "permissions-policy",
  "referrer-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

// ══════════════════════════════════
// INTERCEPT: webRequest.onBeforeRequest
// ══════════════════════════════════
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type, documentUrl } = details;
    if (tabId < 0) return;

    ensureTab(tabId, url);
    const tab = store[tabId];

    // Set origin from main_frame
    if (type === "main_frame") {
      tab.origin = getOrigin(url);
      tab.url = url;
    }

    const origin = tab.origin;
    const path = extractPath(url);
    const apiTypes = ["xmlhttprequest", "fetch"];
    const mainTypes = ["main_frame", "sub_frame"];

    // ── Recon: paths ──
    if (origin && isSameOrigin(origin, url) && !mainTypes.includes(type)) {
      if (path && path !== "/") {
        tab.recon.paths.set(path, { method: details.method || "GET", type });
      }
    }

    // ── Recon: external ──
    if (origin && !isSameOrigin(origin, url) && origin !== "") {
      if (!tab.recon.external.has(url)) {
        const entry = { url, type, tags: [] };
        CDN_URL_RULES.forEach(r => { if (r.regex.test(url)) entry.tags.push(r.label); });
        tab.recon.external.set(url, entry);
      }
    }

    // ── Recon: subdomains ──
    try {
      const u = new URL(url);
      const originHost = new URL(origin || url).hostname;
      const rootDomain = originHost.split(".").slice(-2).join(".");
      if (u.hostname !== originHost && u.hostname.endsWith(rootDomain)) {
        tab.recon.subdomains.add(u.hostname);
      }
    } catch {}

    // ── Recon: parameters ──
    try {
      const u = new URL(url);
      u.searchParams.forEach((val, key) => {
        if (!tab.recon.parameters.has(key)) tab.recon.parameters.set(key, new Set());
        tab.recon.parameters.get(key).add(path);
      });
    } catch {}

    // ── Security: IDOR patterns ──
    const idorPatterns = [
      /\/(\d{3,})(\/|$|\?)/,
      /[?&](id|user_id|account|order|doc|file|record)=(\d+|[a-f0-9-]{8,})/i,
      /\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i,
    ];
    idorPatterns.forEach(p => {
      if (p.test(url) && !tab.security.idors.find(i => i.url === url)) {
        tab.security.idors.push({ url, path, type, pattern: p.source });
      }
    });

    // ── Security: GraphQL ──
    if (/graphql|\/gql/i.test(url) && !tab.security.graphql.find(g => g.url === url)) {
      tab.security.graphql.push({ url, type });
    }
  },
  { urls: ["<all_urls>"] }
);

// ══════════════════════════════════
// INTERCEPT: webRequest.onHeadersReceived
// ══════════════════════════════════
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, responseHeaders, type, statusCode } = details;
    if (tabId < 0) return;
    ensureTab(tabId);
    const tab = store[tabId];

    const hMap = {};
    responseHeaders.forEach(h => { hMap[h.name.toLowerCase()] = h.value || ""; });

    // ── Technology: header fingerprinting ──
    if (type === "main_frame") {
      HEADER_TECH_RULES.forEach(rule => {
        const val = hMap[rule.header];
        if (!val) return;
        const match = val.match(rule.regex);
        if (match) addTech(tabId, rule.cat, rule.name, rule.fixed || match[1] || "detected", `Header: ${rule.header}`);
      });

      // ── Security: missing headers check ──
      const secHeaders = {};
      SECURITY_HEADERS.forEach(h => { secHeaders[h] = hMap[h] || null; });
      tab.security.csp = {
        present: !!hMap["content-security-policy"],
        value: hMap["content-security-policy"] || null,
        headers: secHeaders,
      };

      // ── Protocol detection ──
      browser.webRequest.getSecurityInfo(details.requestId, { certificateChain: true })
        .then(sec => {
          if (!sec) return;
          const proto = {
            scheme: "https", tlsVersion: sec.protocolVersion || null,
            isSecure: sec.state === "secure",
            isSelfSigned: false, isUntrusted: !!sec.isUntrusted,
            isDomainMismatch: !!sec.isDomainMismatch,
            isNotValidAtThisTime: !!sec.isNotValidAtThisTime,
            certSubject: null, certIssuer: null,
            certValidFrom: null, certValidTo: null,
            certFingerprint: null, caKnown: null, warning: null,
          };
          const certs = sec.certificates;
          if (certs?.length) {
            const leaf = certs[0];
            proto.certSubject = leaf.subject || null;
            proto.certIssuer  = leaf.issuer  || null;
            if (leaf.issuer === leaf.subject) { proto.isSelfSigned = true; proto.warning = "Self-signed certificate"; }
            proto.caKnown = identifyCA(leaf.issuer);
            if (leaf.validity) {
              proto.certValidFrom = leaf.validity.start ? new Date(leaf.validity.start).toISOString().split("T")[0] : null;
              proto.certValidTo   = leaf.validity.end   ? new Date(leaf.validity.end).toISOString().split("T")[0]   : null;
              if (leaf.validity.end) {
                const days = Math.floor((leaf.validity.end - Date.now()) / 86400000);
                if (days < 0)  proto.warning = "Certificate EXPIRED!";
                else if (days < 30) proto.warning = `Expiring in ${days} day(s)!`;
              }
            }
            if (leaf.fingerprint?.sha256) proto.certFingerprint = leaf.fingerprint.sha256;
          }
          tab.technology.protocol = proto;
        }).catch(() => {});

      // ── Network: CORS ──
      const acao = hMap["access-control-allow-origin"];
      if (acao) {
        tab.network.cors.push({
          url, acao,
          acac: hMap["access-control-allow-credentials"] || null,
          acam: hMap["access-control-allow-methods"] || null,
          risk: acao === "*" ? "high" : acao ? "medium" : "low",
        });
      }

      // ── Security: Clickjack check ──
      const xfo = hMap["x-frame-options"];
      const csp = hMap["content-security-policy"];
      const hasFrameProtection = xfo || (csp && /frame-ancestors/i.test(csp));
      tab.security.clickjack = {
        url,
        vulnerable: !hasFrameProtection,
        xFrameOptions: xfo || null,
        cspFrameAncestors: csp ? (csp.match(/frame-ancestors[^;]*/i)?.[0] || null) : null,
      };
    }

    // ── Network: error leaker ──
    if (statusCode >= 400) {
      tab.network.errors.push({
        url, statusCode, type,
        server: hMap["server"] || null,
        poweredBy: hMap["x-powered-by"] || null,
        contentType: hMap["content-type"] || null,
      });
    }

    // ── Network: redirects ──
    if ([301,302,303,307,308].includes(statusCode)) {
      const location = hMap["location"] || null;
      tab.network.redirects.push({ from: url, to: location, statusCode, type });
    }

    // ── External: CDN/WAF via headers ──
    const origin = tab.origin;
    if (origin && !isSameOrigin(origin, url)) {
      const entry = tab.recon.external.get(url);
      if (entry) {
        WAF_HEADER_RULES.forEach(r => {
          if (hMap[r.header] && !entry.tags.includes(r.label)) entry.tags.push(r.label);
        });
        if (hMap["cf-ray"] && !entry.tags.includes("WAF/CDN: Cloudflare")) entry.tags.push("WAF/CDN: Cloudflare");
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ── Tab navigation: reset on new page ──
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    // Keep store but reset per-page data
    if (store[tabId]) {
      const s = store[tabId];
      s.url = changeInfo.url;
      s.origin = getOrigin(changeInfo.url);
      s.recon.paths = new Map();
      s.recon.external = new Map();
      s.recon.subdomains = new Set();
      s.recon.parameters = new Map();
      s.network.cors = [];
      s.network.redirects = [];
      s.network.errors = [];
      s.network.websockets = [];
      s.security.forms = [];
      s.security.csp = null;
      s.security.graphql = [];
      s.security.idors = [];
      s.security.clickjack = null;
      s.technology.techs = [];
      s.technology.protocol = null;
      s.clientData.cookies = [];
      s.clientData.localStorage = [];
      s.clientData.sessionStorage = [];
      s.clientData.postMessages = [];

      // Handle plain HTTP
      if (changeInfo.url.startsWith("http://")) {
        s.technology.protocol = { scheme: "http", isSecure: false, warning: "⚠️ No encryption — plain HTTP" };
      }
    }
  }
});

// ══════════════════════════════════
// MESSAGES FROM content.js
// ══════════════════════════════════
browser.runtime.onMessage.addListener((message, sender) => {
  const tabId = sender.tab?.id ?? -1;
  if (tabId < 0) return;
  ensureTab(tabId);
  const tab = store[tabId];

  switch (message.type) {
    case "CONTENT_TECHS":
      message.techs.forEach(({ cat, name, version, source }) => addTech(tabId, cat, name, version, source));
      break;

    case "CONTENT_LINKS":
      message.paths.forEach(p => {
        if (p && p !== "/") tab.recon.paths.set(p, { method: "GET", type: "link" });
      });
      break;

    case "CONTENT_ROUTE":
      if (message.path && message.path !== "/") {
        tab.recon.paths.set(message.path, { method: "GET", type: "route" });
      }
      break;

    case "CONTENT_FORMS":
      message.forms.forEach(f => tab.security.forms.push(f));
      break;

    case "CONTENT_STORAGE":
      tab.clientData.localStorage    = message.localStorage    || [];
      tab.clientData.sessionStorage  = message.sessionStorage  || [];
      break;

    case "CONTENT_POSTMESSAGE":
      tab.clientData.postMessages.push(message.data);
      break;

    case "CONTENT_PROTO_POLLUTION":
      if (message.findings?.length) {
        tab.security.prototypePollution.push(...message.findings);
      }
      break;

    case "CONTENT_WEBSOCKET":
      tab.network.websockets.push(message.data);
      break;
  }
});

// ══════════════════════════════════
// MESSAGES FROM sidebar.js
// ══════════════════════════════════
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {

    case "GET_STATE": {
      const tabId = message.tabId;
      ensureTab(tabId);
      const s = store[tabId];
      sendResponse({
        url: s.url,
        recon: {
          paths:       Array.from(s.recon.paths.entries()).map(([p, v]) => ({ path: p, ...v })),
          external:    Array.from(s.recon.external.values()),
          subdomains:  Array.from(s.recon.subdomains),
          parameters:  Array.from(s.recon.parameters.entries()).map(([k, v]) => ({ name: k, endpoints: Array.from(v) })),
        },
        technology:  {
          techs:    s.technology.techs,
          protocol: s.technology.protocol,
          qualys:   s.technology.qualys,
        },
        clientData:  {
          cookies:        s.clientData.cookies,
          localStorage:   s.clientData.localStorage,
          sessionStorage: s.clientData.sessionStorage,
          postMessages:   s.clientData.postMessages,
        },
        network: {
          cors:       s.network.cors,
          redirects:  s.network.redirects,
          errors:     s.network.errors,
          websockets: s.network.websockets,
        },
        security: {
          forms:              s.security.forms,
          csp:                s.security.csp,
          graphql:            s.security.graphql,
          idors:              s.security.idors,
          prototypePollution: s.security.prototypePollution,
          clickjack:          s.security.clickjack,
        },
      });
      return true;
    }

    case "GET_COOKIES": {
      browser.cookies.getAll({ url: store[message.tabId]?.url || "" })
        .then(cookies => {
          if (store[message.tabId]) store[message.tabId].clientData.cookies = cookies;
          sendResponse(cookies);
        })
        .catch(() => sendResponse([]));
      return true;
    }

    case "CLEAR_STATE": {
      delete store[message.tabId];
      sendResponse({ ok: true });
      return true;
    }

    case "START_QUALYS": {
      const { hostname, tabId } = message;
      ensureTab(tabId);
      store[tabId].technology.qualys = { status: "starting", hostname, result: null, error: null, progress: "Requesting scan..." };
      sendResponse({ ok: true });
      runQualysScan(hostname, tabId);
      return true;
    }

    case "GET_QUALYS": {
      ensureTab(message.tabId);
      sendResponse(store[message.tabId].technology.qualys || null);
      return true;
    }
  }
});

browser.tabs.onRemoved.addListener(tabId => delete store[tabId]);

// ══════════════════════════════════
// QUALYS ENGINE
// ══════════════════════════════════
async function runQualysScan(hostname, tabId) {
  const BASE = "https://api.ssllabs.com/api/v3/analyze";
  let retries = 0;

  function setState(patch) {
    if (store[tabId]) store[tabId].technology.qualys = { ...store[tabId].technology.qualys, ...patch };
  }

  async function poll(first) {
    if (!store[tabId] || store[tabId].technology.qualys?.hostname !== hostname) return;
    try {
      const url = first
        ? `${BASE}?host=${encodeURIComponent(hostname)}&all=done`
        : `${BASE}?host=${encodeURIComponent(hostname)}&all=done&fromCache=on`;
      const res = await fetch(url);
      if (!res.ok) {
        if ((res.status === 529 || res.status === 503) && retries < 4) {
          retries++;
          const wait = retries * 12;
          setState({ status: "retrying", progress: `Qualys busy — retrying in ${wait}s (${retries}/4)` });
          setTimeout(() => poll(false), wait * 1000);
          return;
        }
        if (res.status === 429) { setState({ status: "error", error: "Rate limited (429). Wait a few minutes." }); return; }
        if (res.status === 400) { setState({ status: "error", error: "Invalid hostname." }); return; }
        setState({ status: "error", error: `Qualys API error (HTTP ${res.status})` });
        return;
      }
      const data = await res.json();
      if (data.status === "READY") {
        if (!data.endpoints?.length) { setState({ status: "error", error: "No endpoints found." }); return; }
        setState({ status: "done", result: data, progress: null, error: null });
        return;
      }
      if (data.status === "ERROR") { setState({ status: "error", error: data.statusMessage || "Scan error" }); return; }
      const statusMap = { IN_PROGRESS: "Analyzing SSL...", DNS: "Resolving DNS...", IN_QUEUE: "Queued..." };
      setState({ status: "scanning", progress: statusMap[data.status] || data.status });
      setTimeout(() => poll(false), 5000);
    } catch (e) {
      setState({ status: "error", error: "Network error — cannot reach Qualys." });
    }
  }
  poll(true);
}

// ══════════════════════════════════
// SENSITIVE FILE ACTIVE SCAN
// ══════════════════════════════════
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== "RUN_SENSITIVE_FILES") return;
  const { origin, tabId } = message;
  ensureTab(tabId);

  const FILES = [
    ".env", ".env.local", ".env.backup", ".git/config", ".git/HEAD",
    "backup.zip", "backup.tar.gz", "db.sql", "database.sql",
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml", ".DS_Store", "web.config",
    "config.php", "configuration.php", "wp-config.php",
    "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "swagger.json", "openapi.json", "api-docs/", "graphql",
  ];

  const results = [];
  let done = 0;

  FILES.forEach(async (file) => {
    try {
      const url = `${origin}/${file}`;
      const res = await fetch(url, { method: "HEAD", credentials: "omit" });
      results.push({ file, url, status: res.status, found: res.status < 400 });
    } catch {
      results.push({ file, url: `${origin}/${file}`, status: 0, found: false });
    }
    done++;
    if (done === FILES.length) {
      store[tabId].recon.sensitiveFiles = results.filter(r => r.found);
      sendResponse({ results });
    }
  });
  return true;
});

// ══════════════════════════════════
// KNOWN CA IDENTIFIER
// ══════════════════════════════════
function identifyCA(issuer) {
  if (!issuer) return null;
  const i = issuer.toLowerCase();
  if (i.includes("let's encrypt") || i.includes("letsencrypt")) return "Let's Encrypt";
  if (i.includes("digicert"))     return "DigiCert";
  if (i.includes("comodo") || i.includes("sectigo")) return "Sectigo/Comodo";
  if (i.includes("globalsign"))   return "GlobalSign";
  if (i.includes("geotrust"))     return "GeoTrust";
  if (i.includes("verisign"))     return "VeriSign";
  if (i.includes("entrust"))      return "Entrust";
  if (i.includes("godaddy"))      return "GoDaddy";
  if (i.includes("amazon") || i.includes("amazontrust")) return "Amazon Trust Services";
  if (i.includes("microsoft"))    return "Microsoft";
  if (i.includes("google"))       return "Google Trust Services";
  if (i.includes("cloudflare"))   return "Cloudflare";
  if (i.includes("zerossl"))      return "ZeroSSL";
  return "Unknown CA";
}

// ── Toggle sidebar via browser action click ──
browser.browserAction.onClicked.addListener(() => {
  browser.sidebarAction.toggle();
});
