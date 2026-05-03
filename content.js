// content.js — BountyKit
// Runs in every page, harvests DOM data passively

// ══════════════════════════════════
// 1. TECHNOLOGY FINGERPRINTING (JS globals)
// ══════════════════════════════════
const JS_GLOBALS = [
  { g: "jQuery",    name: "jQuery",      cat: "frontend", v: () => window.jQuery?.fn?.jquery },
  { g: "React",     name: "React",       cat: "frontend", v: () => window.React?.version },
  { g: "Vue",       name: "Vue.js",      cat: "frontend", v: () => window.Vue?.version },
  { g: "angular",   name: "AngularJS",   cat: "frontend", v: () => window.angular?.version?.full },
  { g: "Alpine",    name: "Alpine.js",   cat: "frontend", v: () => window.Alpine?.version },
  { g: "htmx",      name: "htmx",        cat: "frontend", v: () => window.htmx?.version },
  { g: "Backbone",  name: "Backbone.js", cat: "frontend", v: () => window.Backbone?.VERSION },
  { g: "Ember",     name: "Ember.js",    cat: "frontend", v: () => window.Ember?.VERSION?.string },
  { g: "Svelte",    name: "Svelte",      cat: "frontend", v: () => null },
  { g: "axios",     name: "Axios",       cat: "frontend", v: () => window.axios?.VERSION },
  { g: "moment",    name: "Moment.js",   cat: "frontend", v: () => window.moment?.version },
  { g: "gsap",      name: "GSAP",        cat: "frontend", v: () => window.gsap?.version },
  { g: "Chart",     name: "Chart.js",    cat: "frontend", v: () => window.Chart?.version },
  { g: "THREE",     name: "Three.js",    cat: "frontend", v: () => window.THREE?.REVISION },
  { g: "d3",        name: "D3.js",       cat: "frontend", v: () => window.d3?.version },
  { g: "wp",        name: "WordPress",   cat: "cms",      v: () => null },
  { g: "Drupal",    name: "Drupal",      cat: "cms",      v: () => window.Drupal?.version },
  { g: "Shopify",   name: "Shopify",     cat: "cms",      v: () => null },
  { g: "ga",        name: "Google Analytics (UA)", cat: "frontend", v: () => null },
  { g: "gtag",      name: "Google Analytics (GA4)", cat: "frontend", v: () => null },
  { g: "fbq",       name: "Facebook Pixel", cat: "frontend", v: () => null },
  { g: "Sentry",    name: "Sentry",      cat: "frontend", v: () => window.Sentry?.SDK_VERSION },
  { g: "Intercom",  name: "Intercom",    cat: "frontend", v: () => null },
  { g: "Hotjar",    name: "Hotjar",      cat: "frontend", v: () => null },
  { g: "mixpanel",  name: "Mixpanel",    cat: "frontend", v: () => null },
];

const techs = [];
JS_GLOBALS.forEach(({ g, name, cat, v }) => {
  try {
    if (window[g] !== undefined) {
      let ver = "detected";
      try { ver = v() || "detected"; } catch {}
      techs.push({ cat, name, version: ver, source: "JS Global" });
    }
  } catch {}
});

// Meta generator
const metaGen = document.querySelector("meta[name='generator']");
if (metaGen?.content) {
  const c = metaGen.content;
  const checks = [
    [/WordPress\s?([0-9.]*)/i, "WordPress", "cms"],
    [/Drupal\s?([0-9.]*)/i,   "Drupal",    "cms"],
    [/Joomla!?\s?([0-9.]*)/i, "Joomla",    "cms"],
    [/Wix\.com/i,             "Wix",       "cms"],
    [/Squarespace/i,          "Squarespace","cms"],
    [/Ghost\s?([0-9.]*)/i,    "Ghost",     "cms"],
    [/Hugo\s?([0-9.]*)/i,     "Hugo",      "cms"],
    [/Jekyll\s?([0-9.]*)/i,   "Jekyll",    "cms"],
    [/Next\.js\s?([0-9.]*)/i, "Next.js",   "frontend"],
    [/Gatsby\s?([0-9.]*)/i,   "Gatsby",    "frontend"],
  ];
  checks.forEach(([rx, name, cat]) => {
    const m = c.match(rx);
    if (m) techs.push({ cat, name, version: m[1] || "detected", source: "Meta generator" });
  });
}

// Script src patterns
const SCRIPT_PATTERNS = [
  [/jquery[.-]?([0-9.]+)/i,     "jQuery",      "frontend"],
  [/react[.-]([0-9.]+)/i,       "React",       "frontend"],
  [/vue[.-]([0-9.]+)/i,         "Vue.js",      "frontend"],
  [/angular[.-]([0-9.]+)/i,     "Angular",     "frontend"],
  [/bootstrap[.-]([0-9.]+)/i,   "Bootstrap",   "frontend"],
  [/wp-content|wp-includes/i,   "WordPress",   "cms"],
  [/sites\/default\/files/i,    "Drupal",      "cms"],
  [/cdn\.shopify\.com/i,        "Shopify",     "cms"],
  [/static\.squarespace\.com/i, "Squarespace", "cms"],
  [/gtag\/js/i,                 "Google Analytics (GA4)", "frontend"],
  [/connect\.facebook\.net/i,   "Facebook Pixel", "frontend"],
  [/sentry[.-]([0-9.]+)/i,      "Sentry",      "frontend"],
];

document.querySelectorAll("script[src], link[href]").forEach(el => {
  const src = el.src || el.href || "";
  SCRIPT_PATTERNS.forEach(([rx, name, cat]) => {
    const m = src.match(rx);
    if (m && !techs.find(t => t.name === name)) {
      techs.push({ cat, name, version: m[1] || "detected", source: `Script: ${src.split("/").pop()?.substring(0, 40)}` });
    }
  });
});

if (techs.length) browser.runtime.sendMessage({ type: "CONTENT_TECHS", techs });

// ══════════════════════════════════
// 2. LINK HARVESTING
// ══════════════════════════════════
function harvestLinks() {
  const paths = new Set();
  document.querySelectorAll("a[href]").forEach(el => {
    try {
      const u = new URL(el.href, location.href);
      if (u.origin === location.origin && u.pathname !== "/") paths.add(u.pathname + u.search);
    } catch {}
  });
  document.querySelectorAll("form[action]").forEach(el => {
    try {
      const u = new URL(el.action, location.href);
      if (u.origin === location.origin) paths.add(u.pathname);
    } catch {}
  });
  if (paths.size) browser.runtime.sendMessage({ type: "CONTENT_LINKS", paths: Array.from(paths) });
}

// ══════════════════════════════════
// 3. FORM HARVESTING (CSRF detection)
// ══════════════════════════════════
function harvestForms() {
  const forms = [];
  document.querySelectorAll("form").forEach((form, idx) => {
    const inputs = [];
    form.querySelectorAll("input, select, textarea").forEach(inp => {
      inputs.push({
        name:  inp.name  || inp.id || `field_${idx}`,
        type:  inp.type  || inp.tagName.toLowerCase(),
        value: inp.type === "hidden" ? inp.value : null,
      });
    });
    const csrfFields = inputs.filter(i =>
      /csrf|token|nonce|_token|authenticity/i.test(i.name)
    );
    forms.push({
      action:     form.action || location.href,
      method:     form.method?.toUpperCase() || "GET",
      inputCount: inputs.length,
      inputs,
      hasCsrf:    csrfFields.length > 0,
      csrfField:  csrfFields[0]?.name || null,
    });
  });
  if (forms.length) browser.runtime.sendMessage({ type: "CONTENT_FORMS", forms });
}

// ══════════════════════════════════
// 4. STORAGE INSPECTOR
// ══════════════════════════════════
function harvestStorage() {
  const ls = [], ss = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      ls.push({ key: k, value: localStorage.getItem(k) });
    }
  } catch {}
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      ss.push({ key: k, value: sessionStorage.getItem(k) });
    }
  } catch {}
  browser.runtime.sendMessage({ type: "CONTENT_STORAGE", localStorage: ls, sessionStorage: ss });
}

// ══════════════════════════════════
// 5. POSTMESSAGE SNIFFER
// ══════════════════════════════════
window.addEventListener("message", (e) => {
  browser.runtime.sendMessage({
    type: "CONTENT_POSTMESSAGE",
    data: {
      origin: e.origin,
      data:   typeof e.data === "object" ? JSON.stringify(e.data).substring(0, 300) : String(e.data).substring(0, 300),
      time:   Date.now(),
    }
  });
}, true);

// ══════════════════════════════════
// 6. SPA ROUTE DETECTION
// ══════════════════════════════════
function hookHistory(method) {
  const orig = history[method];
  history[method] = function(...args) {
    const r = orig.apply(this, args);
    const path = args[2];
    if (path) {
      try {
        const u = new URL(String(path), location.href);
        browser.runtime.sendMessage({ type: "CONTENT_ROUTE", path: u.pathname + u.search });
      } catch {}
    }
    return r;
  };
}
hookHistory("pushState");
hookHistory("replaceState");
window.addEventListener("hashchange", () => {
  browser.runtime.sendMessage({ type: "CONTENT_ROUTE", path: location.pathname + location.search + location.hash });
});

// ══════════════════════════════════
// 7. WEBSOCKET WATCHER
// ══════════════════════════════════
const OrigWS = window.WebSocket;
window.WebSocket = function(url, protocols) {
  const ws = new OrigWS(url, protocols);
  const entry = { url, messages: [], opened: Date.now() };
  ws.addEventListener("message", (e) => {
    entry.messages.push({ data: String(e.data).substring(0, 200), time: Date.now() });
    browser.runtime.sendMessage({ type: "CONTENT_WEBSOCKET", data: { ...entry } });
  });
  browser.runtime.sendMessage({ type: "CONTENT_WEBSOCKET", data: entry });
  return ws;
};
window.WebSocket.prototype = OrigWS.prototype;

// ══════════════════════════════════
// 8. PROTOTYPE POLLUTION MONITOR
// ══════════════════════════════════
const safeProps = new Set(Object.getOwnPropertyNames(Object.prototype));
setTimeout(() => {
  const findings = [];
  Object.getOwnPropertyNames(Object.prototype).forEach(prop => {
    if (!safeProps.has(prop)) {
      findings.push({ prop, value: String(Object.prototype[prop]).substring(0, 100) });
    }
  });
  if (findings.length) browser.runtime.sendMessage({ type: "CONTENT_PROTO_POLLUTION", findings });
}, 3000);

// ══════════════════════════════════
// RUN HARVESTS
// ══════════════════════════════════
const MutObs = new MutationObserver(() => { harvestLinks(); harvestForms(); });
MutObs.observe(document.documentElement, { childList: true, subtree: true });

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    harvestLinks();
    harvestForms();
    harvestStorage();
  });
} else {
  harvestLinks();
  harvestForms();
  harvestStorage();
}
