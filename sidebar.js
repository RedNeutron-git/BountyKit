// sidebar.js — BountyKit v1.0

let activeTabId = null;
let currentState = null;
let autoRefresh = true;
let refreshTimer = null;
let qualysScanHost = null;

// ══════════════════════════════════
// INIT
// ══════════════════════════════════
document.addEventListener("DOMContentLoaded", async () => {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tabs[0]) return;
  activeTabId = tabs[0].id;

  await refresh();
  bindNav();
  bindActions();
  startAutoRefresh();

  // Re-fetch when active tab changes
  browser.tabs.onActivated.addListener(async (info) => {
    activeTabId = info.tabId;
    await refresh();
  });

  browser.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
    if (tabId === activeTabId && changeInfo.status === "complete") {
      setTimeout(refresh, 800);
    }
  });
});

// ══════════════════════════════════
// DATA REFRESH
// ══════════════════════════════════
async function refresh() {
  try {
    const [state, cookies] = await Promise.all([
      browser.runtime.sendMessage({ type: "GET_STATE", tabId: activeTabId }),
      browser.runtime.sendMessage({ type: "GET_COOKIES", tabId: activeTabId }),
    ]);
    currentState = state;
    if (currentState && cookies) currentState.clientData.cookies = cookies;
    renderAll();
  } catch (e) {
    console.error("BountyKit refresh error:", e);
  }
}

function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  if (autoRefresh) refreshTimer = setInterval(refresh, 3000);
}

// ══════════════════════════════════
// RENDER ALL
// ══════════════════════════════════
function renderAll() {
  if (!currentState) return;
  const s = currentState;

  // Target URL
  try {
    document.getElementById("targetUrl").textContent = new URL(s.url).hostname;
  } catch { document.getElementById("targetUrl").textContent = s.url || "—"; }

  // Counts
  const reconCount  = s.recon.paths.length + s.recon.external.length + s.recon.subdomains.length;
  const techCount   = s.technology.techs.length;
  const clientCount = s.clientData.cookies.length + s.clientData.localStorage.length + s.clientData.sessionStorage.length;
  const netCount    = s.network.cors.length + s.network.redirects.length + s.network.errors.length;
  const secCount    = s.security.forms.filter(f => !f.hasCsrf).length +
                      s.security.idors.length +
                      (s.security.clickjack?.vulnerable ? 1 : 0);

  // Nav badges
  setNavBadge("recon",    reconCount);
  setNavBadge("tech",     techCount);
  setNavBadge("client",   clientCount);
  setNavBadge("network",  netCount);
  setNavBadge("security", secCount);

  // Panel counts
  document.getElementById("pc-recon").textContent    = reconCount;
  document.getElementById("pc-tech").textContent     = techCount;
  document.getElementById("pc-client").textContent   = clientCount;
  document.getElementById("pc-network").textContent  = netCount;
  document.getElementById("pc-security").textContent = s.security.forms.length + s.security.idors.length;

  // Render all sections
  renderPaths(s.recon.paths);
  renderExternal(s.recon.external);
  renderSimpleList("subdomains", s.recon.subdomains, h => h, () => "subdomain");
  renderParams(s.recon.parameters);
  renderTechs(s.technology.techs);
  renderProtocol(s.technology.protocol, s.technology.qualys);
  renderCookies(s.clientData.cookies);
  renderStorage("localstorage",   s.clientData.localStorage);
  renderStorage("sessionstorage", s.clientData.sessionStorage);
  renderPostMessages(s.clientData.postMessages);
  renderCors(s.network.cors);
  renderRedirects(s.network.redirects);
  renderErrors(s.network.errors);
  renderWebSockets(s.network.websockets);
  renderForms(s.security.forms);
  renderCSP(s.security.csp);
  renderSimpleList("graphql", s.security.graphql, i => i.url, i => `type: ${i.type}`);
  renderIDORs(s.security.idors);
  renderClickjack(s.security.clickjack);
  renderSimpleList("protopollution", s.security.prototypePollution, i => i.prop, i => `value: ${i.value}`);

  resumeQualysIfNeeded(s.technology.qualys);
}

function setNavBadge(panel, count) {
  const el = document.getElementById(`nb-${panel}`);
  if (!el) return;
  if (count > 0) {
    el.textContent = count > 99 ? "99+" : count;
    el.classList.add("visible");
  } else {
    el.classList.remove("visible");
  }
}

// ══════════════════════════════════
// RENDER HELPERS
// ══════════════════════════════════
function setBadge(id, count) {
  const el = document.getElementById(`sb-${id}`);
  if (el) el.textContent = count;
}

function makeRow(text, meta, copyText) {
  const div = document.createElement("div");
  div.className = "row-item";
  div.innerHTML = `
    <div class="row-main">
      <div class="row-text">${text}</div>
      ${meta ? `<div class="row-meta">${meta}</div>` : ""}
    </div>
    <button class="row-copy">copy</button>
  `;
  div.querySelector(".row-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(copyText || text.replace(/<[^>]+>/g, ""));
    const btn = div.querySelector(".row-copy");
    btn.textContent = "✓"; btn.classList.add("copied");
    setTimeout(() => { btn.textContent = "copy"; btn.classList.remove("copied"); }, 1200);
  });
  return div;
}

function emptyState(msg) {
  const d = document.createElement("div");
  d.className = "empty-state";
  d.textContent = msg || "— nothing detected yet —";
  return d;
}

function badge(text, cls) {
  return `<span class="badge badge-${cls}">${text}</span>`;
}

// ══════════════════════════════════
// RECON RENDERERS
// ══════════════════════════════════
function renderPaths(paths) {
  setBadge("paths", paths.length);
  const body = document.getElementById("sb-body-paths");
  body.innerHTML = "";
  if (!paths.length) { body.appendChild(emptyState()); return; }
  paths.slice(0, 300).forEach(({ path, method, type }) => {
    const methodBadge = badge(method || "GET", "method");
    const typeBadge   = type === "route" ? badge("SPA", "info") : type === "link" ? badge("link", "tag") : "";
    body.appendChild(makeRow(`${methodBadge}${typeBadge} ${path}`, null, path));
  });
  if (paths.length > 300) {
    const more = document.createElement("div");
    more.className = "empty-state";
    more.textContent = `+ ${paths.length - 300} more paths`;
    body.appendChild(more);
  }
}

function renderExternal(external) {
  setBadge("external", external.length);
  const body = document.getElementById("sb-body-external");
  body.innerHTML = "";
  if (!external.length) { body.appendChild(emptyState()); return; }
  external.forEach(({ url, type, tags }) => {
    const tagHtml = (tags || []).map(t => {
      const cls = t.toLowerCase().includes("waf") ? "waf" : "cdn";
      return badge(t, cls);
    }).join("");
    body.appendChild(makeRow(url, `${badge(type || "req", "tag")} ${tagHtml}`, url));
  });
}

function renderParams(params) {
  setBadge("params", params.length);
  const body = document.getElementById("sb-body-params");
  body.innerHTML = "";
  if (!params.length) { body.appendChild(emptyState()); return; }
  params.forEach(({ name, endpoints }) => {
    body.appendChild(makeRow(name, `Found in: ${endpoints.slice(0,3).join(", ")}${endpoints.length > 3 ? " ..." : ""}`, name));
  });
}

function renderSimpleList(id, items, textFn, metaFn) {
  setBadge(id, items.length);
  const body = document.getElementById(`sb-body-${id}`);
  body.innerHTML = "";
  if (!items.length) { body.appendChild(emptyState()); return; }
  items.forEach(item => {
    body.appendChild(makeRow(textFn(item), metaFn(item), textFn(item)));
  });
}

// ══════════════════════════════════
// TECHNOLOGY
// ══════════════════════════════════
const CAT_COLORS = { frontend: "info", backend: "medium", cms: "low", security: "high" };

function renderTechs(techs) {
  setBadge("techs", techs.length);
  const body = document.getElementById("sb-body-techs");
  body.innerHTML = "";
  if (!techs.length) { body.appendChild(emptyState()); return; }

  const groups = {};
  techs.forEach(t => { (groups[t.cat] = groups[t.cat] || []).push(t); });

  Object.entries(groups).forEach(([cat, items]) => {
    const header = document.createElement("div");
    header.style.cssText = "padding:5px 14px 2px;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-dim)";
    header.textContent = cat.toUpperCase();
    body.appendChild(header);

    items.forEach(t => {
      const ver = badge(t.version, CAT_COLORS[t.cat] || "tag");
      body.appendChild(makeRow(`${t.name} ${ver}`, t.source, `${t.name} ${t.version}`));
    });
  });
}

function renderProtocol(proto, qualys) {
  setBadge("protocol", proto ? proto.scheme?.toUpperCase() : "—");
  const body = document.getElementById("sb-body-protocol");
  body.innerHTML = "";

  if (!proto) {
    body.appendChild(emptyState("Visit a site to detect protocol"));
  } else {
    const grid = document.createElement("div");
    grid.className = "proto-grid";

    if (proto.warning) grid.appendChild(protoCard("⚠️ Warning", proto.warning, "warn full", "warn"));

    const isHTTPS = proto.scheme === "https";
    grid.appendChild(protoCard("Protocol", isHTTPS ? "🔒 HTTPS" : "⚠️ HTTP", isHTTPS ? "safe" : "warn", isHTTPS ? "green" : "red"));
    if (proto.tlsVersion) {
      const ok = /1\.[23]/.test(proto.tlsVersion);
      grid.appendChild(protoCard("TLS Version", proto.tlsVersion, ok ? "" : "warn", ok ? "blue" : "warn"));
    }
    grid.appendChild(protoCard("Self-Signed", proto.isSelfSigned ? "⚠️ YES" : "✅ No", proto.isSelfSigned ? "warn" : "", proto.isSelfSigned ? "red" : "green"));
    if (proto.caKnown)      grid.appendChild(protoCard("CA", proto.caKnown, "", "blue"));
    if (proto.certSubject)  grid.appendChild(protoCard("Subject", proto.certSubject, "full", "blue"));
    if (proto.certValidTo)  grid.appendChild(protoCard("Valid Until", proto.certValidTo, proto.isNotValidAtThisTime ? "warn" : "", proto.isNotValidAtThisTime ? "red" : ""));
    if (proto.certFingerprint) {
      const fp = proto.certFingerprint.substring(0,24) + "...";
      const card = protoCard("SHA-256", fp, "full", "");
      card.style.cursor = "pointer";
      card.addEventListener("click", () => navigator.clipboard.writeText(proto.certFingerprint));
      grid.appendChild(card);
    }
    body.appendChild(grid);
  }

  // Qualys deep scan section
  const div = document.createElement("div");
  div.className = "divider"; div.innerHTML = "<span>Deep Scan</span>";
  body.appendChild(div);

  const qSection = document.createElement("div");
  qSection.id = "qualys-proto-section";
  qSection.style.padding = "0 0 8px";

  const hostname = currentState?.url ? new URL(currentState.url).hostname : "";

  if (qualys?.status === "done" && qualys.result) {
    renderQualysResult(qSection, qualys.result);
  } else if (qualys?.status === "error") {
    qSection.innerHTML = `<div class="qualys-error">❌ ${qualys.error}</div>`;
    appendRetryBtn(qSection, hostname);
  } else if (qualys && ["starting","scanning","retrying"].includes(qualys.status)) {
    showQualysLoading(qSection, qualys.progress);
  } else {
    const btn = document.createElement("button");
    btn.className = "scan-btn blue";
    btn.style.margin = "4px 14px 4px";
    btn.innerHTML = "🔬 Deep Scan via Qualys SSL Labs";
    btn.addEventListener("click", () => startQualys(hostname, qSection));
    qSection.appendChild(btn);
    const note = document.createElement("div");
    note.className = "scan-note";
    note.textContent = "⚠️ Only use on targets you have permission to test.";
    qSection.appendChild(note);
  }

  body.appendChild(qSection);
}

function protoCard(label, value, cardClass, valueClass) {
  const d = document.createElement("div");
  d.className = `proto-card ${cardClass || ""}`.trim();
  d.innerHTML = `<div class="proto-label">${label}</div><div class="proto-value ${valueClass || ""}">${value || "—"}</div>`;
  return d;
}

// ══════════════════════════════════
// CLIENT DATA
// ══════════════════════════════════
function renderCookies(cookies) {
  setBadge("cookies", cookies.length);
  const body = document.getElementById("sb-body-cookies");
  body.innerHTML = "";
  if (!cookies.length) { body.appendChild(emptyState()); return; }
  cookies.forEach(c => {
    const flags = [
      c.httpOnly ? badge("HttpOnly", "low")   : badge("NO HttpOnly", "high"),
      c.secure   ? badge("Secure", "low")     : badge("NO Secure", "medium"),
      c.sameSite ? badge(c.sameSite, "info")  : badge("NO SameSite", "medium"),
    ].join("");
    body.appendChild(makeRow(`${c.name}`, `${flags} domain: ${c.domain}`, `${c.name}=${c.value}`));
  });
}

function renderStorage(id, items) {
  setBadge(id, items.length);
  const body = document.getElementById(`sb-body-${id}`);
  body.innerHTML = "";
  if (!items.length) { body.appendChild(emptyState()); return; }
  items.forEach(({ key, value }) => {
    const v = value && value.length > 80 ? value.substring(0, 80) + "…" : (value || "");
    body.appendChild(makeRow(key, v, `${key}: ${value}`));
  });
}

function renderPostMessages(msgs) {
  setBadge("postmessages", msgs.length);
  const body = document.getElementById("sb-body-postmessages");
  body.innerHTML = "";
  if (!msgs.length) { body.appendChild(emptyState("No postMessage events detected")); return; }
  msgs.forEach(m => {
    body.appendChild(makeRow(m.origin || "unknown origin", m.data?.substring(0, 100), `${m.origin}: ${m.data}`));
  });
}

// ══════════════════════════════════
// NETWORK
// ══════════════════════════════════
function renderCors(cors) {
  setBadge("cors", cors.length);
  const body = document.getElementById("sb-body-cors");
  body.innerHTML = "";
  if (!cors.length) { body.appendChild(emptyState()); return; }
  cors.forEach(c => {
    const risk = c.acao === "*" ? badge("HIGH RISK", "high") : badge("Review", "medium");
    body.appendChild(makeRow(
      `${risk} ACAO: ${c.acao}`,
      `URL: ${c.url.substring(0, 60)} | ACAC: ${c.acac || "none"}`,
      c.url
    ));
  });
}

function renderRedirects(redirects) {
  setBadge("redirects", redirects.length);
  const body = document.getElementById("sb-body-redirects");
  body.innerHTML = "";
  if (!redirects.length) { body.appendChild(emptyState()); return; }
  redirects.forEach(r => {
    body.appendChild(makeRow(
      `${badge(r.statusCode, "info")} → ${r.to || "—"}`,
      `From: ${r.from?.substring(0, 60)}`,
      r.to || r.from
    ));
  });
}

function renderErrors(errors) {
  setBadge("errors", errors.length);
  const body = document.getElementById("sb-body-errors");
  body.innerHTML = "";
  if (!errors.length) { body.appendChild(emptyState()); return; }
  errors.forEach(e => {
    const cls = e.statusCode >= 500 ? "high" : "medium";
    body.appendChild(makeRow(
      `${badge(e.statusCode, cls)} ${e.url.substring(0, 60)}`,
      [e.server && `server: ${e.server}`, e.poweredBy && `powered-by: ${e.poweredBy}`].filter(Boolean).join(" | "),
      e.url
    ));
  });
}

function renderWebSockets(ws) {
  setBadge("websockets", ws.length);
  const body = document.getElementById("sb-body-websockets");
  body.innerHTML = "";
  if (!ws.length) { body.appendChild(emptyState("No WebSocket connections detected")); return; }
  ws.forEach(w => {
    body.appendChild(makeRow(
      w.url,
      `${w.messages?.length || 0} messages`,
      w.url
    ));
  });
}

// ══════════════════════════════════
// SECURITY
// ══════════════════════════════════
function renderForms(forms) {
  setBadge("forms", forms.length);
  const body = document.getElementById("sb-body-forms");
  body.innerHTML = "";
  if (!forms.length) { body.appendChild(emptyState()); return; }
  forms.forEach(f => {
    const csrf = f.hasCsrf
      ? badge("CSRF token ✅", "low")
      : badge("NO CSRF TOKEN ⚠️", "high");
    body.appendChild(makeRow(
      `${badge(f.method, "method")} ${f.action.substring(0, 50)}`,
      `${csrf} — ${f.inputCount} fields${f.csrfField ? ` | token: ${f.csrfField}` : ""}`,
      f.action
    ));
  });
}

function renderCSP(csp) {
  setBadge("csp", csp ? (csp.present ? "✅" : "⚠️") : "—");
  const body = document.getElementById("sb-body-csp");
  body.innerHTML = "";
  if (!csp) { body.appendChild(emptyState("Navigate to a site to analyze CSP")); return; }

  const headers = csp.headers || {};
  const IMPORTANT = [
    ["content-security-policy",    "CSP"],
    ["strict-transport-security",  "HSTS"],
    ["x-frame-options",            "X-Frame-Options"],
    ["x-content-type-options",     "X-Content-Type-Options"],
    ["permissions-policy",         "Permissions-Policy"],
    ["referrer-policy",            "Referrer-Policy"],
    ["cross-origin-opener-policy", "COOP"],
    ["cross-origin-resource-policy","CORP"],
  ];

  IMPORTANT.forEach(([key, label]) => {
    const val = headers[key];
    const present = !!val;
    const b = present ? badge("present", "low") : badge("MISSING ⚠️", "high");
    body.appendChild(makeRow(`${b} ${label}`, val ? val.substring(0, 80) : null, val || label));
  });
}

function renderIDORs(idors) {
  setBadge("idors", idors.length);
  const body = document.getElementById("sb-body-idors");
  body.innerHTML = "";
  if (!idors.length) { body.appendChild(emptyState("No IDOR patterns detected")); return; }
  idors.forEach(i => {
    body.appendChild(makeRow(
      i.path || i.url.substring(0, 80),
      `type: ${i.type} | pattern: ${i.pattern?.substring(0, 40)}`,
      i.url
    ));
  });
}

function renderClickjack(cj) {
  setBadge("clickjack", cj ? (cj.vulnerable ? "⚠️" : "✅") : "—");
  const body = document.getElementById("sb-body-clickjack");
  body.innerHTML = "";
  if (!cj) { body.appendChild(emptyState("Navigate to a site to check")); return; }

  if (cj.vulnerable) {
    body.appendChild(makeRow(
      `${badge("VULNERABLE", "high")} No frame protection detected`,
      "X-Frame-Options and frame-ancestors CSP are both missing.",
      "Clickjacking: VULNERABLE"
    ));
  } else {
    const protection = cj.xFrameOptions
      ? `X-Frame-Options: ${cj.xFrameOptions}`
      : `CSP frame-ancestors: ${cj.cspFrameAncestors}`;
    body.appendChild(makeRow(
      `${badge("Protected", "low")} ${protection}`,
      null,
      protection
    ));
  }
}

// ══════════════════════════════════
// QUALYS ENGINE (sidebar side)
// ══════════════════════════════════
async function startQualys(hostname, container) {
  if (!hostname) return;
  qualysScanHost = hostname;
  await browser.runtime.sendMessage({ type: "START_QUALYS", hostname, tabId: activeTabId });
  showQualysLoading(container, "Requesting scan from Qualys...");
  pollQualysInSidebar(container, hostname);
}

function showQualysLoading(container, status) {
  container.innerHTML = `
    <div class="qualys-loading">
      <div class="qualys-spinner"></div>
      <div class="qualys-status" id="q-status">${status || "Scanning..."}</div>
      <div class="qualys-timer">Scan runs in background — safe to close sidebar</div>
    </div>
  `;
}

async function pollQualysInSidebar(container, hostname) {
  async function check() {
    let q;
    try { q = await browser.runtime.sendMessage({ type: "GET_QUALYS", tabId: activeTabId }); } catch { return; }
    if (!q || q.hostname !== hostname) return;

    const statusEl = document.getElementById("q-status");
    if (statusEl && q.progress) statusEl.textContent = q.progress;

    if (q.status === "done") { renderQualysResult(container, q.result); return; }
    if (q.status === "error") {
      container.innerHTML = `<div class="qualys-error">❌ ${q.error}</div>`;
      appendRetryBtn(container, hostname);
      return;
    }
    setTimeout(check, 3000);
  }
  check();
}

function resumeQualysIfNeeded(qualys) {
  if (!qualys) return;
  if (["starting","scanning","retrying"].includes(qualys.status)) {
    const container = document.getElementById("qualys-proto-section");
    if (container && !container.querySelector(".qualys-spinner")) {
      showQualysLoading(container, qualys.progress);
      pollQualysInSidebar(container, qualys.hostname);
    }
  }
}

function appendRetryBtn(container, hostname) {
  const btn = document.createElement("button");
  btn.className = "scan-btn blue";
  btn.style.margin = "8px 14px 4px";
  btn.innerHTML = "🔄 Retry";
  btn.addEventListener("click", () => startQualys(hostname, container));
  container.appendChild(btn);
}

function renderQualysResult(container, data) {
  container.innerHTML = "";
  const ep = data.endpoints?.[0];
  if (!ep) return;
  const d = ep.details || {};
  const grade = ep.grade || "?";
  const gradeColor = { "A+":"#34d399","A":"#34d399","A-":"#34d399","B":"#fbbf24","C":"#fb923c","F":"#f87171" }[grade] || "#94a3b8";
  const scanned = data.startTime ? new Date(data.startTime).toISOString().replace("T"," ").split(".")[0] : "—";

  // Grade hero
  const hero = document.createElement("div");
  hero.className = "qualys-grade-hero";
  hero.innerHTML = `
    <div class="qualys-grade" style="color:${gradeColor};border-color:${gradeColor}">${grade}</div>
    <div>
      <div class="qualys-grade-label">SSL Labs Grade</div>
      <div class="qualys-grade-host">${data.host}</div>
      <div class="qualys-grade-time">Scanned: ${scanned}</div>
    </div>
  `;
  container.appendChild(hero);

  // Grid
  const grid = document.createElement("div");
  grid.className = "proto-grid";

  // TLS support
  const protos = d.protocols || [];
  const tlsLines = ["1.3","1.2","1.1","1.0"].map(ver => {
    const ok = protos.some(p => p.name === "TLS" && p.version === ver);
    const bad = ver === "1.0" || ver === "1.1";
    return `<span style="color:${ok ? (bad?"#fbbf24":"#34d399") : "#475569"}">${ok?"✅":"❌"} TLS ${ver}</span>`;
  }).join("<br>");
  const tlsCard = document.createElement("div");
  tlsCard.className = "proto-card full";
  tlsCard.innerHTML = `<div class="proto-label">TLS Support</div><div class="proto-value" style="font-size:10px;line-height:1.8">${tlsLines}</div>`;
  grid.appendChild(tlsCard);

  // FS + HSTS
  const fs = d.forwardSecrecy;
  grid.appendChild(protoCard("Forward Secrecy", fs>=2?"✅ Yes":fs===1?"⚠️ Partial":"❌ No", fs>=2?"safe":fs===1?"":"warn", fs>=2?"green":fs===1?"warn":"red"));
  const hsts = d.hstsPolicy;
  grid.appendChild(protoCard("HSTS", hsts?.status==="present"?"✅ Yes":"❌ No", hsts?.status==="present"?"safe":"warn", hsts?.status==="present"?"green":"red"));

  // Vulns
  const vulns = [
    ["heartbleed","Heartbleed"],["poodle","POODLE"],["poodleTls","POODLE TLS"],
    ["freak","FREAK"],["logjam","Logjam"],["drownVulnerable","DROWN"],
    ["ticketbleed","Ticketbleed"],["zombiePoodle","Zombie POODLE"],
  ];
  const vulnLines = vulns.filter(([k]) => d[k]!==undefined).map(([k,l]) => {
    const v = d[k]===true||d[k]===2||(typeof d[k]==="number"&&d[k]>0);
    return `<span style="color:${v?"#f87171":"#34d399"}">${v?"🔴":"🟢"} ${l}</span>`;
  }).join("<br>");
  if (vulnLines) {
    const vc = document.createElement("div");
    vc.className = "proto-card full";
    vc.innerHTML = `<div class="proto-label">Vulnerabilities</div><div class="proto-value" style="font-size:10px;line-height:1.8">${vulnLines}</div>`;
    grid.appendChild(vc);
  }

  container.appendChild(grid);

  const rescan = document.createElement("button");
  rescan.className = "scan-btn blue";
  rescan.style.margin = "6px 14px 4px";
  rescan.innerHTML = "🔄 Rescan";
  rescan.addEventListener("click", () => startQualys(data.host, container));
  container.appendChild(rescan);
}

// ══════════════════════════════════
// ACTIVE SCAN: Sensitive Files
// ══════════════════════════════════
document.getElementById("btnSensitiveFiles")?.addEventListener("click", async () => {
  const origin = currentState?.url ? new URL(currentState.url).origin : null;
  if (!origin) return;

  const resultsDiv = document.getElementById("sensitive-results");
  resultsDiv.innerHTML = `<div class="qualys-loading"><div class="qualys-spinner"></div><div class="qualys-status">Probing sensitive files...</div></div>`;

  const response = await browser.runtime.sendMessage({
    type: "RUN_SENSITIVE_FILES", origin, tabId: activeTabId
  });

  resultsDiv.innerHTML = "";
  const found = response?.results?.filter(r => r.found) || [];
  const notFound = response?.results?.filter(r => !r.found) || [];

  if (found.length === 0) {
    resultsDiv.appendChild(emptyState("✅ No sensitive files found"));
  } else {
    found.forEach(r => {
      resultsDiv.appendChild(makeRow(
        `${badge(r.status, r.status < 300 ? "high" : "medium")} ${r.file}`,
        r.url, r.url
      ));
    });
  }

  const summary = document.createElement("div");
  summary.className = "empty-state";
  summary.textContent = `Scanned ${response?.results?.length || 0} paths — ${found.length} found, ${notFound.length} not found`;
  resultsDiv.appendChild(summary);
});

// ══════════════════════════════════
// NAVIGATION
// ══════════════════════════════════
function bindNav() {
  // Icon nav
  document.querySelectorAll(".nav-btn[data-panel]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`panel-${btn.dataset.panel}`)?.classList.add("active");
    });
  });

  // Dashboard items
  document.querySelectorAll(".dash-item[data-nav]").forEach(item => {
    item.addEventListener("click", () => {
      const panel = item.dataset.nav;
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      document.querySelector(`.nav-btn[data-panel="${panel}"]`)?.classList.add("active");
      document.getElementById(`panel-${panel}`)?.classList.add("active");
    });
  });

  // Section collapsing
  document.querySelectorAll(".section-title").forEach(title => {
    title.addEventListener("click", () => {
      const sec = title.dataset.sec;
      const body = document.getElementById(`sb-body-${sec}`);
      if (!body) return;
      title.classList.toggle("collapsed");
      body.classList.toggle("hidden");
    });
  });

  // Settings toggles
  document.querySelectorAll(".toggle").forEach(tog => {
    tog.addEventListener("click", () => {
      tog.classList.toggle("on");
      if (tog.id === "tog-autorefresh") {
        autoRefresh = tog.classList.contains("on");
        startAutoRefresh();
      }
    });
  });
}

// ══════════════════════════════════
// TOP BAR ACTIONS
// ══════════════════════════════════
function bindActions() {
  // ⚡ New Scan — clear data + reload page
  document.getElementById("btnNewScan").addEventListener("click", async () => {
    await browser.runtime.sendMessage({ type: "CLEAR_STATE", tabId: activeTabId });
    currentState = null;
    // Reload the active tab
    await browser.tabs.reload(activeTabId);
    // Wait a moment then refresh sidebar data
    setTimeout(refresh, 1500);
  });

  document.getElementById("btnClear").addEventListener("click", async () => {
    await browser.runtime.sendMessage({ type: "CLEAR_STATE", tabId: activeTabId });
    currentState = null;
    await refresh();
  });

  document.getElementById("btnExport").addEventListener("click", exportAll);
  document.getElementById("btnExportFull")?.addEventListener("click", exportAll);
}

// ══════════════════════════════════
// EXPORT
// ══════════════════════════════════
function exportAll() {
  if (!currentState) return;
  const s = currentState;
  const host = s.url ? new URL(s.url).hostname : "export";
  const lines = [];

  lines.push(`# BountyKit Export — ${host}`);
  lines.push(`# Generated: ${new Date().toISOString()}`);
  lines.push(`# Target: ${s.url || "—"}`);
  lines.push("");

  // Recon
  lines.push("## RECON — PATHS & ENDPOINTS");
  s.recon.paths.forEach(p => lines.push(`${p.method} ${p.path}`));
  lines.push("");

  lines.push("## RECON — EXTERNAL REQUESTS");
  s.recon.external.forEach(e => lines.push(`${e.url} [${(e.tags||[]).join(", ")}]`));
  lines.push("");

  lines.push("## RECON — SUBDOMAINS");
  s.recon.subdomains.forEach(s => lines.push(s));
  lines.push("");

  lines.push("## RECON — PARAMETERS");
  s.recon.parameters.forEach(p => lines.push(`${p.name} | endpoints: ${p.endpoints.join(", ")}`));
  lines.push("");

  // Technology
  lines.push("## TECHNOLOGY");
  s.technology.techs.forEach(t => lines.push(`[${t.cat}] ${t.name} | ${t.version} | ${t.source}`));
  lines.push("");

  // Protocol
  const p = s.technology.protocol;
  if (p) {
    lines.push("## PROTOCOL & SSL/TLS");
    lines.push(`Scheme: ${p.scheme?.toUpperCase()}`);
    if (p.tlsVersion)     lines.push(`TLS: ${p.tlsVersion}`);
    if (p.caKnown)        lines.push(`CA: ${p.caKnown}`);
    if (p.certSubject)    lines.push(`Subject: ${p.certSubject}`);
    if (p.certValidTo)    lines.push(`Valid Until: ${p.certValidTo}`);
    if (p.certFingerprint)lines.push(`SHA-256: ${p.certFingerprint}`);
    if (p.warning)        lines.push(`Warning: ${p.warning}`);
    lines.push("");
  }

  // Qualys
  const q = s.technology.qualys;
  if (q?.status === "done" && q.result) {
    const ep = q.result.endpoints?.[0];
    const d  = ep?.details || {};
    lines.push("## SSL DEEP SCAN (Qualys)");
    lines.push(`Grade: ${ep?.grade || "?"}`);
    lines.push(`Host: ${q.result.host}`);
    lines.push(`Scanned: ${q.result.startTime ? new Date(q.result.startTime).toISOString() : "—"}`);
    const protos = d.protocols || [];
    ["1.3","1.2","1.1","1.0"].forEach(v => {
      lines.push(`TLS ${v}: ${protos.some(p => p.name==="TLS"&&p.version===v) ? "Supported" : "Not supported"}`);
    });
    lines.push(`Forward Secrecy: ${d.forwardSecrecy>=2?"Yes":d.forwardSecrecy===1?"Partial":"No"}`);
    lines.push(`HSTS: ${d.hstsPolicy?.status==="present"?"Yes":"No"}`);
    lines.push("");
  }

  // Client data
  lines.push("## CLIENT DATA — COOKIES");
  s.clientData.cookies.forEach(c => {
    lines.push(`${c.name} | HttpOnly:${c.httpOnly} | Secure:${c.secure} | SameSite:${c.sameSite||"none"} | domain:${c.domain}`);
  });
  lines.push("");

  lines.push("## CLIENT DATA — localStorage");
  s.clientData.localStorage.forEach(i => lines.push(`${i.key}: ${i.value?.substring(0, 100)}`));
  lines.push("");

  // Network
  lines.push("## NETWORK — CORS");
  s.network.cors.forEach(c => lines.push(`${c.acao} | ACAC:${c.acac||"no"} | ${c.url}`));
  lines.push("");

  lines.push("## NETWORK — REDIRECTS");
  s.network.redirects.forEach(r => lines.push(`${r.statusCode} ${r.from} → ${r.to}`));
  lines.push("");

  lines.push("## NETWORK — ERRORS");
  s.network.errors.forEach(e => lines.push(`${e.statusCode} ${e.url}`));
  lines.push("");

  // Security
  lines.push("## SECURITY — FORMS & CSRF");
  s.security.forms.forEach(f => {
    lines.push(`${f.method} ${f.action} | CSRF:${f.hasCsrf?"YES":"NO"} | fields:${f.inputCount}`);
  });
  lines.push("");

  lines.push("## SECURITY — IDOR CANDIDATES");
  s.security.idors.forEach(i => lines.push(i.url));
  lines.push("");

  lines.push("## SECURITY — GRAPHQL");
  s.security.graphql.forEach(g => lines.push(g.url));
  lines.push("");

  if (s.security.clickjack) {
    lines.push("## SECURITY — CLICKJACKING");
    lines.push(`Vulnerable: ${s.security.clickjack.vulnerable ? "YES ⚠️" : "No"}`);
    lines.push(`X-Frame-Options: ${s.security.clickjack.xFrameOptions || "missing"}`);
    lines.push("");
  }

  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bountykit_${host}_${Date.now()}.txt`;
  a.click();
}
