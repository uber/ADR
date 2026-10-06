const root = document.querySelector("#app");
const state = { csrf: "", status: null, route: location.pathname, ...sessionQueryState(location.search) };
const glyphs = {
  home: "M3 10 12 3l9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1Z",
  sessions: "M4 4h16v12H9l-5 4Zm4 4h8M8 12h5",
  inventory: "m12 3 9 5-9 5-9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5",
  shield: "m12 3 8 3v6c0 5-5 8-8 10-3-2-8-5-8-10V6Zm-4 9 3 3 5-6",
  packageBlock: "m12 3 8 4v10l-8 4-8-4V7Zm-8 4 8 5 8-5M12 12v9M8 5l8 5M3 21 21 3",
  key: "M15 3a6 6 0 1 1-4.8 9.6L3 20v-5l6.2-6.2A6 6 0 0 1 15 3Zm2 4h.01",
  bell: "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9ZM9 21h6",
  settings: "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6",
  arrow: "M7 17 17 7M7 7h10v10",
  chevron: "m9 5 7 7-7 7",
  plus: "M12 5v14M5 12h14",
  play: "m7 4 14 8-14 8Z",
  pause: "M8 5v14M16 5v14",
  refresh: "M20 7a9 9 0 1 0 1 8M20 2v6h-6",
  folder: "M3 5h6l3 3h9v12H3Z",
  file: "M5 3h9l5 5v13H5Zm9 0v6h5M8 13h8M8 17h6",
  lock: "M6 10h12v11H6Zm2 0V7a4 4 0 0 1 8 0v3",
  check: "m5 12 4 4L19 6",
  close: "m6 6 12 12M6 18 18 6",
  search: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm5 12 6 6",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4v6l4 2",
  terminal: "m4 6 6 6-6 6M13 18h7",
  trash: "M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7M14 10v7",
  download: "M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4",
  copy: "M9 9h12v12H9ZM3 15V3h12",
  alert: "m12 3 10 18H2Zm0 6v5m0 3v1",
  activity: "M2 12h5l3-8 4 16 3-8h5",
  moon: "M20 14A9 9 0 0 1 10 3a9 9 0 1 0 10 11Z",
};
function icon(name, cls = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("class", `icon ${cls}`);
  svg.setAttribute("aria-hidden", "true"); svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor"); svg.setAttribute("stroke-width", "1.7");
  svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
  const path = document.createElementNS(svg.namespaceURI, "path");
  path.setAttribute("d", glyphs[name] || glyphs.activity); svg.append(path); return svg;
}
function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "class") node.className = value;
    else if (key === "checked" || key === "disabled") node[key] = Boolean(value);
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false)
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
function button(text, action, { variant = "secondary", symbol = "", ...attrs } = {}) {
  return el("button", { type: "button", class: `button ${variant}`, onClick: action, ...attrs },
    symbol && icon(symbol), text);
}
function tag(text, tone = "neutral") { return el("span", { class: `tag ${tone}` }, text); }
function muted(text) { return el("span", { class: "muted" }, text); }
function number(value) { return new Intl.NumberFormat().format(value || 0); }
function time(value) {
  const date = new Date(value);
  return !value || Number.isNaN(+date) ? "Not yet" : date.toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}
function ago(value) {
  if (!value) return "Not yet";
  const n = Math.max(0, (Date.now() - new Date(value)) / 1000);
  if (!Number.isFinite(n)) return "Unknown";
  return n < 60 ? "just now" : n < 3600 ? `${Math.floor(n / 60)}m ago` :
    n < 86400 ? `${Math.floor(n / 3600)}h ago` : `${Math.floor(n / 86400)}d ago`;
}
function shortPath(value) {
  if (!value) return "Project not reported";
  return value.split("/").filter(Boolean).slice(-2).join("/") || value;
}
function sourceName(value) {
  const names = state.status?.sources || {};
  return Object.hasOwn(names, value) ? names[value] : (typeof value === "string" && value ? value : "Agent");
}
function sourceMark(source) {
  return el("span", { class: `source-mark source-${Object.hasOwn(state.status?.sources || {}, source) ? source : "unknown"}` },
    sourceName(source).slice(0, 1).toUpperCase());
}
function notice(message, error = false) {
  const item = el("div", { class: `toast ${error ? "error" : ""}`, role: error ? "alert" : "status" },
    icon(error ? "alert" : "check"), el("span", {}, message));
  const notifications = document.querySelector("#notifications");
  while (notifications.children.length >= 2) notifications.firstElementChild.remove();
  notifications.append(item); setTimeout(() => item.remove(), 6000);
}
async function api(path, { method = "GET", body, timeout = 15000 } = {}, retryCsrf = true) {
  const response = await fetch(`/api${path}`, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-ADR-CSRF": state.csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    // Recover only from a CSRF rejection made before the operation ran. Never
    // replay a timeout, network error, or other potentially completed mutation.
    if (retryCsrf && !["GET", "HEAD"].includes(method) &&
      response.status === 403 && data.detail?.code === "csrf_mismatch") {
      state.csrf = (await api("/auth/session")).csrf;
      return api(path, { method, body, timeout }, false);
    }
    const detail = typeof data.detail === "string" ? data.detail :
      (typeof data.detail?.message === "string" ? data.detail.message : `Request failed (${response.status})`);
    throw new Error(detail);
  }
  return data;
}
async function perform(action, success) {
  try { const result = await action(); if (success) notice(success); await loadStatus(); return result; }
  catch (error) { notice(error.message, true); throw error; }
}
async function loadStatus() {
  state.status = await api("/status"); updateChrome(); return state.status;
}
let pendingView = null, scrollSaveQueued = false;
if ("scrollRestoration" in history) history.scrollRestoration = "manual";
function rememberView() {
  const page = document.querySelector("#page");
  if (pendingView || !page) return;
  history.replaceState({ ...history.state, adrView: {
    route: state.route, x: window.scrollX, y: window.scrollY,
    search: state.search, source: state.source, offset: state.offset,
    sessionFocus: state.route.startsWith("/sessions") ? focusedControl(page) : null,
    disclosures: [...page.querySelectorAll("details[data-view-key][open]")].map(node => node.dataset.viewKey),
  } }, "", location.href);
}
window.addEventListener("scroll", () => {
  if (pendingView || scrollSaveQueued) return;
  scrollSaveQueued = true;
  requestAnimationFrame(() => { scrollSaveQueued = false; rememberView(); });
}, { passive: true });
window.addEventListener("pagehide", rememberView);
function navigate(path, { focus = "" } = {}) {
  rememberView();
  const destination = new URL(path, location.href);
  if (destination.pathname + destination.search !== location.pathname + location.search)
    history.pushState({}, "", destination.pathname + destination.search + destination.hash);
  state.route = destination.pathname;
  if (state.route === "/sessions" || state.route.startsWith("/sessions/"))
    Object.assign(state, sessionQueryState(destination.search));
  else state.offset = 0;
  pendingView = { route: state.route, x: 0, y: 0, focus };
  render();
}
window.addEventListener("popstate", event => {
  state.route = location.pathname;
  const saved = event.state?.adrView;
  if (state.route === "/sessions" || state.route.startsWith("/sessions/"))
    Object.assign(state, sessionQueryState(location.search));
  pendingView = { route: state.route, x: saved?.x || 0, y: saved?.y || 0,
    disclosures: saved?.disclosures || [], restore: true, focus: saved?.sessionFocus?.selector || "" };
  render();
});
function routeClick(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey ||
    event.shiftKey || event.altKey || event.currentTarget.target === "_blank") return;
  event.preventDefault(); navigate(event.currentTarget.getAttribute("href"));
}
function link(text, href, cls = "") {
  return el("a", { href, class: cls, onClick: routeClick }, text);
}
function empty(title, text, action) {
  return el("div", { class: "empty" }, el("span", { class: "empty-icon" }, icon("activity")),
    el("h3", {}, title), el("p", {}, text), action);
}
function card(title, subtitle, ...content) {
  return el("section", { class: "card" },
    el("div", { class: "card-heading" }, el("div", {}, el("h2", {}, title), subtitle && el("p", {}, subtitle))),
    ...content);
}
function pageHeading(eyebrow, title, subtitle, ...actions) {
  return el("div", { class: "page-heading" },
    el("div", {}, el("span", { class: "eyebrow" }, eyebrow), el("h1", {}, title), el("p", {}, subtitle)),
    el("div", { class: "actions" }, ...actions));
}
function shell() {
  const nav = [
    ["INSIGHTS", [
      ["/", "home", "Overview"], ["/sessions", "sessions", "Sessions"],
      ["/inventory", "inventory", "AI inventory"],
      ["/reviews", "activity", "Security reviews"],
    ]],
    ["PROTECTION", [
      ["/protection", "shield", "File protection"], ["/threats", "packageBlock", "Malicious artifacts"],
      ["/credentials", "key", "Credential vault"],
    ]],
  ];
  const sidebar = el("aside", { class: "sidebar" },
    el("div", { class: "brand" }, el("img", { src: "/assets/icon.svg", alt: "", width: 36, height: 36 }),
      el("div", {}, el("strong", {}, "ADR"), el("span", {}, "Agent Security and Observability"))),
    ...nav.map(([label, items]) => el("nav", { "aria-label": label },
      el("div", { class: "nav-label" }, label),
      ...items.map(([href, symbol, text]) => el("a", {
        href, "data-route": href, class: "nav-item", title: text,
        onClick: routeClick,
      }, icon(symbol), text, href === "/credentials" && el("span", { id: "approval-count", class: "count" }, "0"))))),
    el("div", { class: "sidebar-bottom" },
      el("a", { href: "/settings", "data-route": "/settings", class: "nav-item",
        title: "Settings", onClick: routeClick }, icon("settings"), "Settings"),
      el("div", { class: "local-note" }, icon("lock"), el("div", {},
        el("strong", {}, "Stored on this device."), el("span", {}, "Agent reviews share only what you approve."))))),
    topbar = el("header", { class: "topbar" },
      el("div", { class: "running-status" }, el("span", { class: "status-dot" }),
        el("strong", {}, "ADR is running"), el("span", { id: "collection-label", class: "muted" }),
        el("span", { id: "view-status", class: "view-status", role: "status", "aria-live": "polite" })),
      el("div", { class: "topbar-actions" },
        button("Refresh", () => render(), { variant: "quiet", symbol: "refresh", title: "Refresh this view" }),
        button("Start capture", toggleCapture, { id: "capture-toggle", symbol: "play" })));
  root.replaceChildren(el("a", { href: "#page", class: "skip-link", onClick: event => {
    event.preventDefault(); document.querySelector("#page").focus({ preventScroll: true });
  } }, "Skip to content"), sidebar, el("div", { class: "workspace" }, topbar,
    el("main", { id: "page", tabindex: "-1" })));
  updateChrome();
}
function updateChrome() {
  if (!state.status) return;
  document.querySelectorAll("[data-route]").forEach(node => {
    const href = node.dataset.route;
    node.classList.toggle("active", href === "/" ? state.route === "/" : state.route.startsWith(href));
    node.setAttribute("aria-current", node.classList.contains("active") ? "page" : "false");
  });
  const label = document.querySelector("#collection-label");
  if (label) label.textContent = state.status.collector.recording ?
    (state.status.collector.phase === "collecting" ? "Collecting local activity…" : "Local capture on") : "Capture paused";
  const toggle = document.querySelector("#capture-toggle");
  if (toggle) toggle.replaceChildren(icon(state.status.collector.recording ? "pause" : "play"),
    document.createTextNode(state.status.collector.recording ? "Pause capture" : "Start capture"));
  const count = document.querySelector("#approval-count");
  if (count) { count.textContent = state.status.pending; count.hidden = !state.status.pending; }
  const hooks = new Map(state.status.hooks.map(hook => [hook.harness, hook]));
  document.querySelectorAll("[data-hook-report]").forEach(node => {
    node.textContent = ago(hooks.get(node.dataset.hookReport)?.last_event?.timestamp);
  });
}
function hookConnectionState(hooks) {
  return JSON.stringify(hooks.map(hook => ({ ...hook, last_event: Boolean(hook.last_event) })));
}
async function toggleCapture() {
  const toggle = document.querySelector("#capture-toggle");
  toggle.disabled = true;
  try {
    await perform(() => api(`/collector/${state.status.collector.recording ? "pause" : "start"}`, { method: "POST" }));
    if (state.route === "/") await render();
  } catch { /* perform already displayed the error; leave the control usable. */ }
  finally { toggle.disabled = false; }
}
function metric(label, value, footnote, symbol) {
  return el("div", { class: "metric" }, el("div", { class: "metric-label" }, label, icon(symbol)),
    el("strong", { class: "metric-value" }, number(value)), el("span", {}, footnote));
}
function sessionQueryState(search = "") {
  const params = new URLSearchParams(search);
  const date = params.get("date") || "";
  return {
    search: (params.get("q") || "").slice(0, 200), source: params.get("source") || "",
    project: params.get("project") || "", date: ["today", "week", "month", "custom"].includes(date) ? date : "",
    from: params.get("from") || "", to: params.get("to") || "",
    sort: params.get("sort") === "newest" ? "newest" : "relevance",
    offset: Math.min(100000, Math.max(0, Number.parseInt(params.get("offset"), 10) || 0)),
  };
}
function sessionsURL(view = state, identifier = "") {
  const params = new URLSearchParams();
  for (const [key, value] of [
    ["q", view.search], ["source", view.source], ["project", view.project], ["date", view.date],
    ["from", view.date === "custom" ? view.from : ""], ["to", view.date === "custom" ? view.to : ""],
    ["sort", view.search && view.sort === "newest" ? "newest" : ""], ["offset", view.offset || ""],
  ]) if (value) params.set(key, value);
  const query = params.toString();
  return `/sessions${identifier ? "/" + encodeURIComponent(identifier) : ""}${query ? "?" + query : ""}`;
}
function sessionLink(identifier) {
  return state.route.startsWith("/sessions") ? sessionsURL(state, identifier) : `/sessions/${encodeURIComponent(identifier)}`;
}
function sessionTerms(query) {
  return [...new Set((query.toLocaleLowerCase().match(/[\p{L}\p{N}_]+/gu) || []))].slice(0, 32);
}
function markedSessionText(text, query = "") {
  const fragment = document.createDocumentFragment(), terms = sessionTerms(query);
  const value = String(text ?? "");
  if (!terms.length) { fragment.append(value); return fragment; }
  const expression = new RegExp(terms.map(term => term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "giu");
  let position = 0, count = 0;
  for (const match of value.matchAll(expression)) {
    // Bound highlight nodes, not the visible/stored text.
    if (++count > 500) break;
    fragment.append(value.slice(position, match.index), el("mark", {}, match[0]));
    position = match.index + match[0].length;
  }
  fragment.append(value.slice(position));
  return fragment;
}
function sessionProjectName(project) {
  return project ? project.replaceAll("\\", "/").split("/").filter(Boolean).at(-1) || project : "Project not reported";
}
function sessionDateLabel(value, full = false) {
  const date = new Date(value);
  if (!value || Number.isNaN(+date)) return "Date not reported";
  return date.toLocaleString([], full ? { dateStyle: "medium", timeStyle: "short" } :
    { month: "short", day: "numeric", ...(date.getFullYear() !== new Date().getFullYear() ? { year: "numeric" } : {}) });
}
function sessionDateBounds(view) {
  const bounds = {}, now = new Date();
  if (view.date && view.date !== "custom") {
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    if (view.date === "week") start.setDate(start.getDate() - 6);
    if (view.date === "month") start.setDate(start.getDate() - 29);
    const end = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    bounds.since = start.toISOString(); bounds.before = end.toISOString();
  } else if (view.date === "custom") {
    for (const [key, value] of [["since", view.from], ["before", view.to]]) {
      if (!value) continue;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error("Choose valid start and end dates.");
      const [year, month, day] = value.split("-").map(Number), date = new Date(year, month - 1, day);
      if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day)
        throw new Error("Choose valid start and end dates.");
      if (key === "before") date.setDate(date.getDate() + 1);
      bounds[key] = date.toISOString();
    }
    if (bounds.since && bounds.before && bounds.since >= bounds.before)
      throw new Error("The end date must be on or after the start date.");
  }
  return bounds;
}
function sessionRow(item, { query = "" } = {}) {
  const preview = item.preview, excerpt = preview?.text || item.snippet;
  return el("a", { class: "session-row", href: sessionLink(item.id), onClick: routeClick,
    "aria-label": `${item.title || "Untitled session"}, ${item.project || "Project not reported"}, ${sourceName(item.source)}, ${sessionDateLabel(item.occurred_at)}` },
    sourceMark(item.source), el("div", { class: "session-main" },
      el("div", { class: "session-row-context" },
        el("span", { class: "session-project", title: item.project || "", translate: "no" },
          icon("folder"), sessionProjectName(item.project)),
        el("span", { class: "session-agent" }, sourceName(item.source))),
      el("div", { class: "session-row-title" }, el("strong", {}, markedSessionText(item.title || "Untitled session", query)),
        item.kind === "subagent" && tag("Sub-agent"),
        (item.kind === "fork" || item.forked_from) && tag("Fork")),
      excerpt && el("p", { class: "search-snippet" },
        el("span", { class: "session-preview-label" }, preview?.label || "Matching passage"),
        markedSessionText(excerpt, query)),
      el("div", { class: "session-row-foot" },
        el("time", { datetime: item.occurred_at, title: sessionDateLabel(item.occurred_at, true) }, sessionDateLabel(item.occurred_at)),
        el("span", {}, `${number(item.message_count)} messages`),
        Boolean(item.partial) && el("span", { class: "session-partial" }, "Partial capture"))),
    icon("chevron"));
}
function sessionChildren(item) {
  if (!item.child_count) return null;
  const body = el("div", { class: "session-children-body" });
  let loaded = false, loading = false, offset = 0;
  const load = async () => {
    if (loading) return;
    loading = true;
    body.querySelector(".children-more")?.remove();
    const progress = el("p", { class: "muted small", role: "status" }, "Loading sub-agent sessions…");
    body.append(progress);
    try {
      const data = await api(`/sessions/${encodeURIComponent(item.id)}/children?limit=30&offset=${offset}`);
      progress.remove();
      body.append(...data.items.map(sessionFamily));
      loaded = true; offset = data.next_offset;
      if (offset !== null) body.append(button("Show more sub-agents", load, { class: "button quiet children-more" }));
    } catch (error) {
      progress.replaceChildren(document.createTextNode(error.message), " ",
        button("Try again", () => { progress.remove(); load(); }, { variant: "quiet" }));
    } finally { loading = false; }
  };
  const details = el("details", { class: "session-children", "data-view-key": `children:${item.id}`,
    onToggle: () => { if (details.open && !loaded) load(); } },
  el("summary", {}, icon("chevron"),
    `${number(item.child_count)} sub-agent ${item.child_count === 1 ? "session" : "sessions"}`), body);
  details.restoreDisclosure = load;
  return details;
}
function sessionFamily(item, options = {}) {
  return el("div", { class: "session-family" }, sessionRow(item, options),
    (options.query || options.showRelations) && (item.parent || item.forked_from) && el("div", { class: "session-result-relation" },
      link(`${item.parent ? "Parent" : "Forked from"}: ${(item.parent || item.forked_from).title}`,
        sessionLink((item.parent || item.forked_from).id))),
    sessionChildren(item));
}
function activityChart(days) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 640 172"); svg.setAttribute("class", "activity-chart");
  svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Sessions updated per day, in UTC");
  const values = new Map(days.map(row => [row.day, row.sessions]));
  const dates = Array.from({ length: 14 }, (_, index) => {
    const date = new Date(); date.setUTCDate(date.getUTCDate() - 13 + index); return date.toISOString().slice(0, 10);
  });
  const maximum = Math.max(1, ...dates.map(date => values.get(date) || 0));
  for (let index = 0; index < 14; index++) {
    const count = values.get(dates[index]) || 0, height = count ? 8 + count / maximum * 116 : 3;
    const rect = document.createElementNS(ns, "rect");
    for (const [key, value] of Object.entries({ x: 9 + index * 45, y: 136 - height, width: 25, height, rx: 5 }))
      rect.setAttribute(key, value);
    rect.setAttribute("class", count ? "chart-bar" : "chart-bar empty-bar");
    const title = document.createElementNS(ns, "title"); title.textContent = `${dates[index]}: ${count} sessions`;
    rect.append(title); svg.append(rect);
    if (index % 3 === 0 || index === 13) {
      const text = document.createElementNS(ns, "text");
      text.setAttribute("x", 21 + index * 45); text.setAttribute("y", "160"); text.setAttribute("text-anchor", "middle");
      text.textContent = new Date(`${dates[index]}T12:00:00Z`).toLocaleDateString([], { month: "short", day: "numeric" });
      svg.append(text);
    }
  }
  return svg;
}
async function overview() {
  const data = await api("/overview"), totals = data.totals;
  const intro = !state.status.settings.onboarding_complete ?
    el("section", { class: "welcome card" },
      el("div", {}, el("h2", {}, "Your agents, on your terms."),
        el("p", {}, "Find previous work, protect the files that matter, and use credentials without putting their values in chat."),
        el("p", { class: "muted small" }, "Start with readable local logs. Capture stays on this device. Optional security reviews share approved evidence through your agent.")),
      el("div", { class: "actions" },
        button("Set up device access", () => navigate("/settings"), { symbol: "settings" }),
        button("Start local capture", async () => {
          await api("/collector/start", { method: "POST" });
          await api("/settings", { method: "PATCH", body: { onboarding_complete: true } });
          await loadStatus(); render();
        }, { variant: "primary", symbol: "play" }))) : null;
  const sources = new Map(data.sources.map(row => [row.source, row]));
  const diagnostics = new Map((state.status.collector.diagnostics || []).map(row => [row.source, row]));
  const agents = card("Your agents", "Collection and protection are separate capabilities.",
    el("div", { class: "agent-list" }, ...Object.entries(state.status.sources).map(([key, name]) => {
      const known = sources.get(key), health = diagnostics.get(key);
      const bad = ["partial", "failed"].includes(health?.status);
      return el("div", { class: "agent-row" }, sourceMark(key), el("div", {},
        el("strong", {}, name), el("span", { class: "muted small" }, known ? `${known.sessions} sessions` : "No captured sessions")),
      tag(bad ? "Needs attention" : known ? "Observed" : "Not observed", bad ? "amber" : known ? "green" : "neutral"));
    })));
  const actions = card("A little more peace of mind", "Small guardrails, on your terms.",
    el("div", { class: "action-list" },
      button("Choose files to protect", () => navigate("/protection"), { variant: "card-action", symbol: "shield" }),
      button("Add a credential", () => navigate("/credentials"), { variant: "card-action", symbol: "key" })));
  const warnings = state.status.collector.error ? el("div", { class: "banner warning", role: "status" },
    icon("alert"), el("div", {}, el("strong", {}, "Collection needs attention"), el("p", {}, state.status.collector.error))) : null;
  return [
    pageHeading("INSIGHTS", "Your agents, at a glance", "Understand the activity on your device. Stay in control of what comes next."),
    intro, warnings,
    el("div", { class: "metric-grid" },
      metric("Conversations", totals.conversations,
        `${number(totals.sessions)} captured sessions · ${number(totals.subagents)} sub-agents`, "sessions"),
      metric("Tool calls", totals.tools, "From the latest session snapshots", "terminal"),
      metric("Saved file rules", totals.rules, !state.status.protection.enabled ? "Protection paused" :
        state.status.hooks.some(item => item.installed) ? "Ready for connected hooks" : "Not active · connect an agent", "shield"),
      metric("Vault credentials", totals.credentials, "Use accounts without sharing keys", "key")),
    totals.pending > 0 && el("div", { class: "banner warning" }, icon("key"),
      link(`${totals.pending} credential request${totals.pending === 1 ? " needs" : "s need"} your approval`, "/credentials")),
    el("div", { class: "two-column" },
      card("The shape of your work", "Sessions updated each day · UTC · last 14 days", activityChart(data.days)),
      actions),
    el("div", { class: "two-column wide-left" },
      card("Recent sessions", "Pick up the context, not just the last message.",
        data.recent.length ? el("div", {}, ...data.recent.map(sessionFamily)) :
          empty("Your first session will appear here", "Start capture, then use a supported coding agent.",
            button("Start capture", () => perform(() => api("/collector/start", { method: "POST" })), { symbol: "play" })),
        data.recent.length ? link("View all sessions", "/sessions", "card-footer-link") : null),
      agents),
    el("div", { class: "page-footnote" }, icon("lock"), "Collected history stays on this device. No LLM key is needed for Insights."),
  ];
}
async function sessionsPage() {
  const view = sessionQueryState(location.search);
  const filtered = Boolean(view.search || view.source || view.project || view.date);
  let data = null, failure = "", facetFailure = false;
  const facetsPromise = api("/sessions/filters").catch(() => {
    facetFailure = true; return { sources: [], projects: [] };
  });
  try {
    const params = new URLSearchParams({
      source: view.source, limit: "30", offset: String(view.offset), ...sessionDateBounds(view),
    });
    if (view.project) params.set("project", view.project);
    if (view.search) { params.set("q", view.search); params.set("sort", view.sort); }
    else params.set("grouped", String(!filtered));
    data = await api(`${view.search ? "/history/search" : "/sessions"}?${params}`);
  } catch (error) { failure = error.message; }
  const facets = await facetsPromise;
  const apply = (changes = {}, focus = "#session-search") => {
    submit.disabled = true; submit.textContent = "Searching…";
    form.setAttribute("aria-busy", "true");
    const updated = { ...view, search: search.value.trim(), offset: 0, ...changes };
    if (updated.search !== view.search) updated.offset = 0;
    navigate(sessionsURL(updated), { focus });
  };
  const search = el("input", {
    id: "session-search", name: "session_search", type: "search", value: view.search, maxlength: 200,
    placeholder: "Find a fix, file, or decision…", autocomplete: "off", spellcheck: "false",
    "aria-describedby": "session-search-help", "aria-keyshortcuts": "/",
    onInput: () => { clearSearch.hidden = !search.value; draft.hidden = search.value.trim() === view.search; },
    onSearch: () => { if (!search.value && view.search) apply({ search: "" }); },
    onKeyDown: event => {
      if (event.key === "Escape" && !event.isComposing && search.value) {
        event.preventDefault(); search.value = ""; apply({ search: "" });
      }
    },
  });
  const clearSearch = button("", () => { search.value = ""; apply({ search: "" }); }, {
    class: "button session-clear-input", symbol: "close", "aria-label": "Clear search", title: "Clear search (Escape)",
    hidden: !view.search,
  });
  const draft = el("span", { class: "session-search-draft", hidden: true }, "Press Enter to search");
  const submit = el("button", { type: "submit", class: "button primary sessions-submit" }, icon("search"), "Search");
  const sources = [...new Set([...Object.keys(state.status.sources || {}), ...facets.sources, view.source])].filter(Boolean);
  const source = el("select", {
    id: "session-source", name: "session_source", autocomplete: "off",
    onChange: () => apply({ source: source.value }, "#session-source"),
  }, el("option", { value: "" }, "All agents"),
  ...sources.map(value => el("option", { value }, sourceName(value))));
  source.value = view.source;
  const projectOptions = [...facets.projects];
  if (view.project && !projectOptions.some(item => item.project === view.project))
    projectOptions.push({ project: view.project });
  const project = el("select", {
    id: "session-project", name: "session_project", autocomplete: "off", title: view.project || "All projects",
    onChange: () => apply({ project: project.value }, "#session-project"),
  }, el("option", { value: "" }, "All projects"),
  ...projectOptions.map(item => el("option", { value: item.project, title: item.project },
    `${sessionProjectName(item.project)} — ${item.project}`)));
  project.value = view.project;
  const dateOptions = { "": "Any time", today: "Today", week: "Past 7 days", month: "Past 30 days", custom: "Choose dates…" };
  const date = el("select", {
    id: "session-date", name: "session_date", autocomplete: "off",
    onChange: () => apply({ date: date.value }, date.value === "custom" ? "#session-from" : "#session-date"),
  }, ...Object.entries(dateOptions).map(([value, label]) => el("option", { value }, label)));
  date.value = view.date;
  const sort = el("select", {
    id: "session-sort", name: "session_sort", "aria-label": "Sort search results", autocomplete: "off",
    onChange: () => apply({ sort: sort.value }, "#session-sort"),
  }, el("option", { value: "relevance" }, "Best match"), el("option", { value: "newest" }, "Newest first"));
  sort.value = view.sort;
  const labeledSelect = (text, control, extra = "") => el("div", { class: `session-filter ${extra}` },
    el("label", { for: control.id }, text), selectControl(control));
  const from = el("input", {
    id: "session-from", name: "session_from", type: "date", value: view.from, autocomplete: "off",
    max: view.to || undefined, onChange: () => apply({ from: from.value }, "#session-from"),
  });
  const to = el("input", {
    id: "session-to", name: "session_to", type: "date", value: view.to, autocomplete: "off",
    min: view.from || undefined, onChange: () => apply({ to: to.value }, "#session-to"),
  });
  const form = el("form", {
    class: "sessions-search-panel", role: "search", "aria-label": "Search captured sessions", "aria-busy": "false",
    onSubmit: event => { event.preventDefault(); apply(); },
  },
  el("label", { for: "session-search", class: "sessions-search-label" }, "Search your captured work"),
  el("div", { class: "sessions-search-line" },
    el("div", { class: "sessions-search-input" }, icon("search"), search, clearSearch), submit),
  el("div", { class: "sessions-search-help", id: "session-search-help" },
    el("span", {}, "Search messages and tool output across agents. All words must match."),
    draft, el("span", { class: "session-shortcut", "aria-hidden": "true" }, el("kbd", {}, "/"), " to search")),
  el("div", { class: "sessions-filter-row" },
    labeledSelect("Agent", source), labeledSelect("Project", project, "session-project-filter"),
    labeledSelect("Updated", date)),
  view.date === "custom" && el("div", { class: "session-date-range" },
    el("div", { class: "session-filter" }, el("label", { for: from.id }, "From"), from),
    el("div", { class: "session-filter" }, el("label", { for: to.id }, "Through"), to),
    el("p", { class: "small muted" }, "Includes both dates, in your local timezone.")),
  facetFailure && el("p", { class: "small muted", role: "status" },
    "Project choices couldn’t load. Your search still works; refresh to try again."));
  const chips = [];
  const chip = (label, changes) => button(label, () => apply(changes), {
    class: "button session-filter-chip", symbol: "close", "aria-label": `Remove ${label} filter`,
  });
  if (view.search) chips.push(chip(`Search: ${view.search}`, { search: "" }));
  if (view.source) chips.push(chip(`Agent: ${sourceName(view.source)}`, { source: "" }));
  if (view.project) chips.push(chip(`Project: ${sessionProjectName(view.project)}`, { project: "" }));
  if (view.date) chips.push(chip(view.date === "custom" ?
    `Dates: ${view.from || "Any start"} to ${view.to || "Any end"}` : dateOptions[view.date], { date: "", from: "", to: "" }));
  const clearAll = () => apply({ ...sessionQueryState(""), offset: 0 });
  const results = el("section", { class: "sessions-results", "aria-labelledby": "sessions-results-title" });
  if (failure) {
    results.append(el("div", { class: "session-search-error", role: "alert", tabindex: "-1" },
      icon("alert"), el("div", {}, el("h2", { id: "sessions-results-title" }, "Search couldn’t finish"),
        el("p", {}, failure), el("p", { class: "small" }, "Your search and filters are kept. Adjust them or try again."),
        button("Try again", () => apply(), { symbol: "refresh" }))));
  } else {
    const noun = filtered ? "session" : "conversation";
    results.append(el("div", { class: "sessions-results-heading" },
      el("div", {},
        el("h2", { id: "sessions-results-title", tabindex: "-1" },
          view.search ? "Search results" : filtered ? "Filtered sessions" : "Recent conversations"),
        el("p", { role: "status", "aria-live": "polite", "aria-atomic": "true" },
          `${number(data.total)} ${noun}${data.total === 1 ? "" : "s"}${filtered ? " found" : ""}`,
          el("span", {}, filtered ? "Matching sub-agents included" : "Newest first"))),
      view.search && selectControl(sort)));
    if (data.items.length) {
      results.append(el("ol", { class: "session-results-list", role: "list" },
        ...data.items.map(item => el("li", {}, sessionFamily(item, { query: view.search, showRelations: filtered })))));
    } else {
      results.append(empty(filtered ? "No sessions match yet" : "Your work will be here",
        filtered ? "Try fewer words, another project, or a wider date range. Search looks in captured history, not uncaptured agent logs." :
          "Capture a conversation with a supported agent, then return here to find the answers, files, and decisions you worked on.",
        filtered ? button("Clear search and filters", clearAll) :
          state.status.collector.recording ? link("Check capture settings", "/settings", "button secondary") :
            button("Start capture", async () => { await toggleCapture(); render(); }, { symbol: "play" })));
    }
    if (data.total > 30 || view.offset) {
      results.append(el("nav", { class: "pagination session-pagination", "aria-label": "Sessions pages" },
        el("span", { class: "muted" }, data.items.length ?
          `${number(view.offset + 1)}–${number(view.offset + data.items.length)} of ${number(data.total)}` : "No results on this page"),
        el("div", { class: "actions" },
          button("Previous", () => apply({ offset: Math.max(0, view.offset - 30) }, "#sessions-results-title"),
            { disabled: view.offset === 0 }),
          button("Next", () => apply({ offset: data.next_offset }, "#sessions-results-title"),
            { disabled: data.next_offset === null }))));
    }
  }
  return [el("div", { class: "sessions-page" },
    el("header", { class: "sessions-heading" }, el("div", {}, el("h1", {}, "Sessions"),
      el("p", {}, "Pick up the thread. Find the useful answer, whichever agent you used.")),
    el("span", { class: "sessions-private-note" }, icon("lock"), "Captured on this device")),
    form,
    chips.length > 0 && el("div", { class: "session-active-filters", "aria-label": "Applied filters" },
      ...chips, button("Clear all", clearAll, { variant: "quiet" })),
    results)];
}
function expandableText(text, className = "", { query = "", key = "" } = {}) {
  const value = typeof text === "string" ? text : JSON.stringify(text ?? "", null, 2);
  const makeContent = () => el("pre", { class: `message-text ${className}`, tabindex: value.length >= 800 ? "0" : undefined },
    markedSessionText(value, query));
  if (value.length < 800) return makeContent();
  const positions = sessionTerms(query).map(term => value.toLocaleLowerCase().indexOf(term)).filter(index => index >= 0);
  const start = positions.length ? Math.max(0, Math.min(...positions) - 70) : 0;
  const excerpt = `${start ? "…" : ""}${value.slice(start, start + 280)}…`;
  const details = el("details", { class: "expandable", "data-view-key": key || undefined },
    el("summary", {}, markedSessionText(excerpt, query), el("span", {}, `Show all ${number(value.length)} characters`)));
  let loaded = false;
  const load = () => { if (!loaded) { details.append(makeContent()); loaded = true; } };
  details.addEventListener("toggle", () => { if (details.open) load(); });
  details.restoreDisclosure = load;
  return details;
}
function conversationBlocks(messages, setupMessageIndexes = []) {
  const blocks = [], setup = new Map(), setupIndexes = new Set(setupMessageIndexes);
  for (const [index, message] of messages.entries()) {
    const entries = Array.isArray(message.tools) ? message.tools.map((tool, toolIndex) => ({ tool, toolIndex }))
      .filter(({ tool }) => tool && typeof tool === "object") : [];
    const tools = entries.map(({ tool }) => tool);
    const text = message.content;
    if (setupIndexes.has(index) && !tools.length) {
      const key = JSON.stringify([message.role, text]);
      if (!setup.has(key)) setup.set(key, { message, count: 0, index });
      setup.get(key).count++;
      continue;
    }
    const placeholder = typeof text === "string" && /^\[Assistant decided to use a tool\]$/.test(text.trim());
    if (text && !(message.role === "assistant" && tools.length && placeholder)) blocks.push({ kind: "message", message, index });
    if (tools.length) {
      const positions = entries.map(({ toolIndex }) => ({ messageIndex: index, toolIndex }));
      const previous = blocks[blocks.length - 1];
      if (previous?.kind === "tools") { previous.tools.push(...tools); previous.positions.push(...positions); }
      else blocks.push({ kind: "tools", tools: [...tools], positions });
    }
  }
  if (setup.size) blocks.unshift({ kind: "setup", entries: [...setup.values()] });
  return blocks;
}
function setupBundle(entries, query = "") {
  const count = entries.reduce((total, entry) => total + entry.count, 0);
  const body = el("div", { class: "setup-body" });
  let loaded = false;
  const load = () => {
    if (loaded) return;
    loaded = true;
    body.append(el("p", { class: "muted small" },
      "Instructions and environment details. Every original occurrence remains in the captured data and export."),
    ...entries.map(({ message, count: occurrences, index }) => el("details", {
      class: "setup-entry", id: `message-${index}`, "data-view-key": `setup:${index}`, tabindex: "-1",
    },
      el("summary", {}, message.role === "user" ? "Environment and setup" : "Agent instructions",
        occurrences > 1 && tag(`${number(occurrences)} occurrences`)),
      expandableText(message.content || "", "", { query, key: `text:${index}` }))));
  };
  const details = el("details", { class: "setup-bundle", "data-view-key": "session-setup",
    onToggle: () => { if (details.open) load(); } },
  el("summary", {}, icon("settings"), el("strong", {}, "Session setup"),
    muted(`${number(count)} ${count === 1 ? "entry" : "entries"} · ${number(entries.length)} unique`)), body);
  details.restoreDisclosure = load;
  return details;
}
function toolBundle(tools, { query = "", positions = [], key = "" } = {}) {
  const names = [...new Set(tools.map(tool => tool.tool_name || "Tool"))];
  const body = el("div", { class: "tool-bundle-body" });
  let loaded = false;
  const load = () => {
    if (loaded) return;
    loaded = true;
    body.append(...tools.map((tool, index) => {
      const position = positions[index] || { messageIndex: 0, toolIndex: index };
      const id = `tool-${position.messageIndex}-${position.toolIndex}`;
      return el("details", { class: "tool-call", id, "data-view-key": id, tabindex: "-1" },
        el("summary", {}, icon("terminal"), el("strong", {}, markedSessionText(tool.tool_name || "Tool", query)),
          tool.server_name && tag(tool.server_name), tool.status && tag(tool.status, tool.status === "error" ? "red" : "neutral")),
        el("div", { class: "tool-body" }, el("h3", {}, "Input"),
          expandableText(tool.arguments ?? {}, "", { query, key: `${id}:input` }),
          tool.result !== null && tool.result !== undefined && el("h3", {}, "Output"),
          tool.result !== null && tool.result !== undefined && expandableText(tool.result, "", { query, key: `${id}:output` }),
          tool.error && el("div", { class: "error-text" }, markedSessionText(tool.error, query))));
    }));
  };
  const details = el("details", { class: "tool-bundle", "data-view-key": key || undefined,
    onToggle: () => { if (details.open) load(); } },
    el("summary", {}, el("span", { class: "tool-bundle-icon" }, icon("terminal")),
      el("div", {}, el("strong", {}, `${tools.length} tool ${tools.length === 1 ? "call" : "calls"}`),
        el("span", {}, names.slice(0, 4).join(" · ") + (names.length > 4 ? ` · +${names.length - 4} more` : ""))),
      el("span", { class: "tool-bundle-hint" }, "Show tool work"), icon("chevron")), body);
  details.restoreDisclosure = load;
  return details;
}
async function sessionPage(identifier) {
  const item = await api(`/sessions/${encodeURIComponent(identifier)}`);
  const messages = item.payload.chat_history || [];
  const blocks = conversationBlocks(messages, item.presentation?.setup_message_indexes || []);
  const restoring = pendingView?.restore || (!pendingView && Boolean(document.querySelector(".session-detail")));
  const params = new URLSearchParams(location.search);
  let query = params.has("find") ? params.get("find") : state.search;
  let matches = [], selected = -1;
  const passages = [];
  for (const [blockIndex, block] of blocks.entries()) {
    if (block.kind === "setup") {
      for (const entry of block.entries) passages.push({
        id: `message-${entry.index}`, text: String(entry.message.content || ""), container: "session-setup",
      });
    } else if (block.kind === "message") passages.push({
      id: `message-${block.index}`, text: String(block.message.content || ""),
    });
    else for (const [index, tool] of block.tools.entries()) {
      const position = block.positions[index];
      passages.push({ id: `tool-${position.messageIndex}-${position.toolIndex}`, text: JSON.stringify(tool),
        container: `tools:${blockIndex}` });
    }
  }
  const conversation = el("section", { class: "conversation", "aria-label": "Captured conversation" });
  const resultStatus = el("span", { class: "transcript-match-status", role: "status", "aria-live": "polite", "aria-atomic": "true" });
  const updateStatus = () => {
    previous.disabled = next.disabled = !matches.length;
    resultStatus.textContent = query ? matches.length ?
      `${number(selected + 1)} of ${number(matches.length)} matching passages` :
      "No matching passages. Your search may match the title or project." : "Search messages and tool output";
  };
  const reveal = (passage, focus = false) => {
    if (passage.container) {
      const container = conversation.querySelector(`[data-view-key="${CSS.escape(passage.container)}"]`);
      if (container) { container.open = true; container.restoreDisclosure?.(); }
    }
    const target = conversation.querySelector(`#${CSS.escape(passage.id)}`);
    if (!target) return;
    conversation.querySelectorAll(".current-passage").forEach(node => node.classList.remove("current-passage"));
    target.classList.add("current-passage");
    if (target.matches("details")) { target.open = true; target.restoreDisclosure?.(); }
    for (const details of target.querySelectorAll("details.expandable")) {
      if (!query || sessionTerms(query).some(term => details.textContent.toLocaleLowerCase().includes(term))) {
        details.open = true; details.restoreDisclosure?.();
      }
    }
    if (focus) target.focus({ preventScroll: true });
    (target.querySelector("pre mark") || target).scrollIntoView({ block: "center", behavior: "instant" });
  };
  const jump = (index, focus = false) => {
    if (!matches.length) return;
    selected = (index + matches.length) % matches.length;
    updateStatus(); reveal(matches[selected], focus);
  };
  const previous = button("Previous", () => jump(selected - 1), {
    variant: "quiet", "aria-label": "Previous matching passage",
  });
  const next = button("Next", () => jump(selected + 1), {
    variant: "quiet", "aria-label": "Next matching passage",
  });
  const find = el("input", {
    id: "transcript-find", name: "transcript_find", type: "search", value: query, maxlength: 200,
    autocomplete: "off", spellcheck: "false", placeholder: "Find words in this session…",
    "aria-keyshortcuts": "/", onInput: () => { clear.hidden = !find.value; },
    onKeyDown: event => {
      if (event.key === "Escape" && !event.isComposing) {
        event.preventDefault(); find.value = ""; applyFind();
      }
    },
    onSearch: () => { if (!find.value) applyFind(); },
  });
  const clear = button("", () => { find.value = ""; applyFind(); find.focus(); }, {
    class: "button session-clear-input", symbol: "close", "aria-label": "Clear session search", hidden: !query,
  });
  const draw = () => {
    const openKeys = [...conversation.querySelectorAll("details[data-view-key][open]")].map(node => node.dataset.viewKey);
    conversation.replaceChildren(...blocks.map((block, index) => {
      if (block.kind === "setup") return setupBundle(block.entries, query);
      if (block.kind === "tools") return toolBundle(block.tools, { query, positions: block.positions, key: `tools:${index}` });
      const message = block.message, assistant = message.role === "assistant";
      return el("article", { class: `message ${message.role === "user" ? "user-message" : ""}`,
        id: `message-${block.index}`, tabindex: "-1" },
      el("header", {}, el("span", { class: "message-avatar", "aria-hidden": "true" }, message.role === "user" ? "You" : "AI"),
        el("strong", {}, message.role === "user" ? "You" : assistant ? sourceName(item.source) : message.role || "Message"),
        assistant && button("Copy answer", async () => {
          try { await navigator.clipboard.writeText(String(message.content)); notice("Answer copied"); }
          catch { notice("Couldn’t copy. Select the answer text and copy it manually.", true); }
        }, { variant: "quiet transcript-copy", symbol: "copy", "aria-label": `Copy answer ${block.index + 1}` })),
      expandableText(message.content, "", { query, key: `text:${block.index}` }));
    }));
    for (const key of openKeys) {
      const details = conversation.querySelector(`[data-view-key="${CSS.escape(key)}"]`);
      if (details) { details.open = true; details.restoreDisclosure?.(); }
    }
    const terms = sessionTerms(query);
    matches = terms.length ? passages.filter(passage => terms.some(term => passage.text.toLocaleLowerCase().includes(term))) : [];
    // Prefer the passage containing the most searched words, then follow transcript order.
    selected = matches.length ? matches.reduce((best, passage, index) => {
      const score = value => terms.filter(term => value.text.toLocaleLowerCase().includes(term)).length;
      return score(passage) > score(matches[best]) ? index : best;
    }, 0) : -1;
    clear.hidden = !find.value;
    updateStatus();
  };
  const applyFind = () => {
    query = find.value.trim();
    const url = new URL(location.href);
    url.searchParams.set("find", query);
    history.replaceState(history.state, "", url.pathname + url.search);
    draw();
    if (query) jump(selected);
  };
  const finder = el("form", { class: "transcript-finder", role: "search", "aria-label": "Search within captured conversation",
    onSubmit: event => { event.preventDefault(); applyFind(); } },
  el("label", { for: "transcript-find" }, "Find in this session"),
  el("div", { class: "transcript-find-line" },
    el("div", { class: "sessions-search-input" }, icon("search"), find, clear),
    el("button", { type: "submit", class: "button secondary" }, "Find"),
    el("div", { class: "transcript-find-actions" }, previous, next)),
  resultStatus);
  const lastAnswer = [...blocks].reverse().find(block => block.kind === "message" && block.message.role === "assistant");
  const detail = el("div", { class: "session-detail" },
    el("div", { class: "session-detail-nav" }, link(state.search ? "Back to search results" : "All sessions", sessionsURL(), "back-link"),
      item.project && link(`More in ${sessionProjectName(item.project)}`,
        sessionsURL({ ...sessionQueryState(""), project: item.project }), "back-link")),
    el("header", { class: "session-detail-heading" },
      el("div", { class: "session-detail-agent" }, sourceMark(item.source), sourceName(item.source),
        item.kind === "subagent" && tag("Sub-agent"), (item.kind === "fork" || item.forked_from) && tag("Fork")),
      el("h1", {}, item.title || "Untitled session"),
      el("p", { class: "session-detail-project", translate: "no" }, icon("folder"), item.project || "Project path not reported"),
      el("div", { class: "session-detail-facts" },
        el("time", { datetime: item.occurred_at }, sessionDateLabel(item.occurred_at, true)),
        el("span", {}, `${number(blocks.filter(block => block.kind === "message").length)} messages`),
        el("span", {}, `${number(item.tool_count)} tool calls`)),
      el("div", { class: "actions" },
        lastAnswer && el("a", { class: "button secondary", href: `#message-${lastAnswer.index}`,
          onClick: event => {
            if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
            event.preventDefault(); reveal({ id: `message-${lastAnswer.index}` }, true);
          },
        }, icon("sessions"), "Latest answer"),
        link("Review this session", `/reviews?session=${encodeURIComponent(item.id)}`, "button secondary"),
        el("a", { class: "button quiet", href: `/api/sessions/${encodeURIComponent(item.id)}/export`, download: "" },
          icon("download"), "Export JSON"))),
    Boolean(item.parent || item.forked_from || item.child_count) && el("section", { class: "session-related", "aria-label": "Related sessions" },
      el("h2", {}, "Related work"),
      (item.parent || item.forked_from) && el("div", { class: "session-relations" },
        item.parent && link(`Parent conversation: ${item.parent.title}`, sessionLink(item.parent.id)),
        item.forked_from && link(`Forked from: ${item.forked_from.title}`, sessionLink(item.forked_from.id))),
      sessionChildren(item)),
    item.partial ? el("div", { class: "banner warning" }, icon("alert"),
      "This source reported truncation or a partial export. ADR does not label it complete.") : null,
    finder, conversation,
    !blocks.length && empty("No messages in this capture", "This source supplied session details but no conversation text."),
    el("details", { class: "session-capture-details", "data-view-key": "capture-details" },
      el("summary", {}, "Capture details"),
      el("p", {}, item.model || "Model not reported"),
      el("p", {}, `${number(item.revisions)} captured ${item.revisions === 1 ? "revision" : "revisions"}. Export includes the full current snapshot.`),
      item.token_usage && el("div", { class: "token-stats" },
        ...Object.entries(item.token_usage).filter(([, value]) => typeof value === "number")
          .map(([key, value]) => el("div", {}, muted(key.replaceAll("_", " ")), el("strong", {}, number(value)))))));
  draw();
  detail.onReady = () => {
    if (!restoring && query && matches.length) jump(selected, true);
    else if (!restoring && /^#(?:message|tool)-\d+(?:-\d+)?$/.test(location.hash)) {
      const passage = passages.find(entry => entry.id === location.hash.slice(1));
      if (passage) reveal(passage, true);
    }
  };
  return [detail];
}
document.addEventListener("keydown", event => {
  if (!state.route.startsWith("/sessions") || event.key !== "/" || event.metaKey || event.ctrlKey ||
    event.altKey || event.isComposing || document.querySelector("dialog[open]") ||
    event.target.closest?.("input, textarea, select, [contenteditable='true']")) return;
  const input = document.querySelector("#session-search, #transcript-find");
  if (input) { event.preventDefault(); input.focus(); }
});
const inventoryApplications = new Set(["app", "cli_agent", "ai_browser", "model_runtime", "unverified_executable"]);
const inventoryKinds = {
  app: "Desktop app", cli_agent: "CLI agent", ai_browser: "AI browser", model_runtime: "Model runtime",
  extension: "Extension", mcp_server: "MCP server", mcp_bundle: "MCP bundle", skill: "Skill", plugin: "Plugin",
  command: "Command", agent_definition: "Agent definition", hook: "Hook", instructions: "Instructions",
  output_style: "Output style", model_weights: "Model weights", agent_platform: "Agent platform", ci_agent: "CI agent",
  unverified_executable: "Unverified executable",
};
function inventoryPath(asset) { return asset.install_path || asset.path || asset.install_root || ""; }
function inventoryBrand(asset) {
  const value = `${asset.catalog_id || ""} ${asset.name || ""} ${inventoryPath(asset)}`.toLowerCase();
  for (const [matches, mark, label, tone] of [
    [["codex", "chatgpt", "openai"], "Cx", "OpenAI", "openai"],
    [["claude", "anthropic"], "Cl", "Claude", "claude"],
    [["copilot"], "Co", "GitHub Copilot", "copilot"],
    [["cursor"], "Cu", "Cursor", "cursor"],
    [["gemini"], "Ge", "Gemini", "gemini"],
    [["opencode"], "Oc", "opencode", "opencode"],
    [["windsurf"], "Ws", "Windsurf", "windsurf"],
    [["ollama"], "Ol", "Ollama", "neutral"],
    [["visual studio", "vscode", ".vscode"], "VS", "Visual Studio Code", "gemini"],
    [["adr"], "AD", "ADR", "windsurf"],
  ]) if (matches.some(part => value.includes(part))) return { mark, label, tone };
  return { mark: null, label: inventoryKinds[asset.kind] || "AI item", tone: "neutral" };
}
function inventoryTitle(asset) {
  const name = String(asset.name || asset.identity || "Unnamed item");
  const legacy = /^(PreToolUse|PostToolUse|UserPromptSubmit|SessionStart|SessionEnd|Stop) hook \d+$/.exec(name);
  if (!legacy) return name;
  const event = {
    PreToolUse: "Before tool use", PostToolUse: "After tool use", UserPromptSubmit: "Before prompt submission",
    SessionStart: "Session start", SessionEnd: "Session end", Stop: "Agent finished",
  }[legacy[1]];
  return `${inventoryBrand(asset).label} · ${event}`;
}
function inventoryPages(items, renderItem, label = "items") {
  const container = el("div", {}), rows = el("div", {}), controls = el("div", { class: "inventory-pager" });
  let page = 0;
  const draw = () => {
    rows.replaceChildren(...items.slice(page * 20, (page + 1) * 20).map(renderItem));
    controls.replaceChildren(muted(`${number(page * 20 + 1)}–${number(Math.min((page + 1) * 20, items.length))} of ${number(items.length)} ${label}`),
      ...(items.length > 20 ? [
        button("Previous", () => { page--; draw(); }, { disabled: page === 0, "aria-label": `Previous ${label}` }),
        button("Next", () => { page++; draw(); }, { disabled: (page + 1) * 20 >= items.length, "aria-label": `Next ${label}` }),
      ] : []));
  };
  draw(); container.append(rows, controls); return container;
}
async function openAccessSettings() {
  const result = await api("/access/settings", { method: "POST", body: { target: "full_disk_access" } });
  notice(result.request_accepted ?
    "System Settings requested. Enable ADR, then fully reopen it and scan again." :
    "Open System Settings → Privacy & Security → Full Disk Access.", !result.request_accepted);
}
function deviceAccessCard(access, { compact = false } = {}) {
  if (!access) return null;
  const bundle = access.identity?.bundle_path;
  const isMac = access.setup?.settings_targets?.includes("full_disk_access");
  return el("section", { class: `card access-setup${compact ? " access-setup-compact" : ""}`, id: "device-access",
    "aria-labelledby": "device-access-title" },
    el("div", { class: "access-setup-heading" }, el("div", {},
      el("h2", { id: "device-access-title" }, "Set up device access"),
      el("p", { class: "small muted" }, "Let ADR read more agent locations. Capture and inventory still work with the access already available.")),
      access.setup?.settings_available && button("Open Full Disk Access", async () => {
        try { await openAccessSettings(); } catch (error) { notice(error.message, true); }
      }, { symbol: "settings", variant: "secondary" })),
    !compact && isMac && el("ol", { class: "access-steps" },
      el("li", {}, "In macOS System Settings, open Privacy & Security → Full Disk Access."),
      el("li", {}, "Enable this copy of ADR. If it is missing, use the + button to add the app."),
      el("li", {}, "Fully quit and reopen ADR, then run an inventory scan again.")),
    compact && isMac && el("p", { class: "small muted" },
      "Enable ADR in macOS Full Disk Access, fully quit and reopen it, then scan again. Other users’ file permissions and intentional scan exclusions are separate."),
    !isMac && el("p", { class: "small muted" }, access.setup?.manual_steps || "Review the reported locations and their file permissions."),
    !compact && bundle && el("div", { class: "access-app-location" },
      el("span", { class: "small muted" }, "This copy of ADR"),
      el("code", { class: "path", translate: "no" }, bundle),
      button("Copy app path", async () => {
        try { await navigator.clipboard.writeText(bundle); notice("App path copied"); }
        catch { notice("Select and copy the app path", true); }
      }, { variant: "quiet", symbol: "copy" })),
    !compact && el("details", { class: "access-explanation" },
      el("summary", {}, "Why can some locations still be unreadable?"),
      el("p", { class: "small muted" },
        "Full Disk Access can help with macOS privacy-protected locations. It does not change file ownership, other users’ permissions, or ADR’s intentional exclusions. A popup for one folder is not permission for every folder."),
      el("p", { class: "small muted" },
        "Grant access to the app you actually run. A separate development copy or terminal-launched command can have a different macOS permission identity. ADR will show the remaining scan results; it does not claim that opening Settings granted access.")));
}
function groupedInventoryCoverage(access, revision) {
  const report = access.coverage, blocked = report.access, skipped = report.skipped;
  const page = (section, root, offset) => api("/inventory/coverage?" + new URLSearchParams({
    section, offset, limit: 20, ...(root === undefined ? {} : { root }), ...(revision ? { revision } : {}),
  }));
  const detailRow = item => el("div", { class: "inventory-coverage-row" },
    el("code", { class: "path", translate: "no" }, item.path),
    el("p", { class: "small muted" }, ({
      filesystem_permissions: "File ownership or access permissions",
      os_privacy_or_policy: "Operating-system privacy or security policy",
      unclassified_access: "Access could not be determined",
      scanner_scope: "Outside the broad scan scope",
      personal_path: "Intentionally skipped personal location",
      missing: "Location no longer exists",
    })[item.category] || String(item.category || "Reported by the scanner").replaceAll("_", " ")),
    el("p", { class: "small muted" }, item.reason, item.errno_name ? ` (${item.errno_name})` : "",
      item.occurrences > 1 ? ` · observed ${number(item.occurrences)} times` : ""),
    item.detail && el("p", { class: "small muted" }, item.detail));
  const locationGroup = (group, section, tone) => {
    const rows = el("div", {}, ...group.details.map(detailRow));
    let offset = group.details.length;
    const more = button(`Show more paths (${number(group.omitted_details)} remaining)`, async () => {
      more.disabled = true;
      try {
        const result = await page(section, group.root, offset);
        rows.append(...result.items.map(detailRow));
        offset += result.items.length;
        more.hidden = result.next_offset === null;
        more.textContent = `Show more paths (${number(Math.max(0, result.total - offset))} remaining)`;
      } catch (error) { notice(error.message, true); }
      finally { more.disabled = false; }
    }, { variant: "quiet" });
    more.hidden = !group.omitted_details;
    return el("details", { class: "coverage-location" },
      el("summary", {}, el("code", { class: "path" }, group.root),
        tag(`${number(group.path_count)} ${group.path_count === 1 ? "path" : "paths"}`, tone)),
      el("div", { class: "coverage-location-body" }, rows, more));
  };
  const groups = (section, name, tone) => {
    const rows = el("div", {}, ...section.groups.map(group => locationGroup(group, name, tone)));
    let offset = section.groups.length;
    const more = button(`Show more locations (${number(section.omitted_groups)} remaining)`, async () => {
      more.disabled = true;
      try {
        const result = await page(name, undefined, offset);
        rows.append(...result.items.map(group => locationGroup(group, name, tone)));
        offset += result.items.length;
        more.hidden = result.next_offset === null;
        more.textContent = `Show more locations (${number(Math.max(0, result.total - offset))} remaining)`;
      } catch (error) { notice(error.message, true); }
      finally { more.disabled = false; }
    }, { variant: "quiet" });
    more.hidden = !section.omitted_groups;
    return el("div", {}, rows, more);
  };
  const partials = [
    ["Scan limits", report.limits, "The scan stopped at a configured time or entry limit.",
      item => [item.path, item.detail || String(item.boundary).replaceAll("_", " ")]],
    ["Optional sources unavailable", report.unavailable, "These optional sources were not available on this device.",
      item => [item.provider, item.reason]],
    ["Partial inputs", report.truncated, "Only part of these large inputs was read.",
      item => [item.path, `${number(item.kept)} of ${number(item.true_count)} bytes or entries read`]],
    ["Source errors", report.failed_probes, "These source checks did not complete.",
      item => [item.name, item.detail || item.status]],
  ].filter(([, section]) => section.count);
  const ioFailures = skipped.category_counts?.io_error?.path_count || 0;
  const hasIssues = blocked.path_count || partials.length || ioFailures;
  return el("details", { class: "inventory-coverage" },
    el("summary", {}, icon(hasIssues ? "alert" : "check"), el("div", {},
      el("strong", {}, blocked.group_count ?
        `${number(blocked.group_count)} ${blocked.group_count === 1 ? "location needs" : "locations need"} an access review` :
        hasIssues ? "Some source checks were incomplete" : "Scan details"),
      el("span", { class: "small muted" }, blocked.path_count ?
        `${number(blocked.path_count)} unreadable paths grouped by location. These are not separate permission requests.` :
        ioFailures ? `${number(ioFailures)} paths had read errors. These are separate from permission requests.` :
        hasIssues ? "Review scan limits and optional sources below." : "No access failures were reported by the scanned sources."))),
    el("div", { class: "inventory-coverage-body" },
      blocked.group_count > 0 && el("section", {},
        ...access.guidance.map(item => el("div", { class: "coverage-guidance" },
          el("h3", {}, item.title), el("p", { class: "small muted" }, item.explanation))),
        groups(blocked, "access", "amber")),
      ...partials.map(([title, section, explanation, values]) => el("details", { class: "inventory-coverage-group" },
        el("summary", {}, `${title} (${number(section.count)})`), el("p", { class: "small muted" }, explanation),
        inventoryPages(section.items, item => {
          const [name, reason] = values(item);
          return el("div", { class: "inventory-coverage-row" }, el("code", { class: "path" }, name),
            el("p", { class: "small muted" }, reason));
        }, title.toLowerCase()),
        section.omitted > 0 && el("p", { class: "small muted" },
          `${number(section.omitted)} more are retained in the local scan record.`))),
      skipped.group_count > 0 && el("details", { class: "inventory-coverage-group" },
        el("summary", {}, `${ioFailures ? "Skipped locations and read errors" : "Skipped or unavailable locations"} (${number(skipped.group_count)} groups)`),
        el("p", { class: "small muted" }, ioFailures ?
          "Some filesystem reads failed. Review their errors below; Full Disk Access is not a remedy for I/O errors. Intentional exclusions and missing paths are also listed separately here." :
          "Intentional exclusions, missing paths, and other non-permission outcomes. Granting broader access does not change these."),
        groups(skipped, "skipped", "neutral"))));
}
function inventoryCoverage(coverage, access, revision) {
  if (access?.coverage) return groupedInventoryCoverage(access, revision);
  if (!coverage) return null;
  const unique = (items, key) => [...new Map((items || []).map(item => [key(item), item])).values()];
  const denied = unique(coverage.denied, item => `${item.path}\0${item.reason}`);
  const boundaries = unique(coverage.boundaries_hit, item => `${item.path}\0${item.boundary}`);
  const restricted = denied.filter(item => item.reason !== "personal_path");
  const skipped = denied.filter(item => item.reason === "personal_path");
  const excluded = boundaries.filter(item => item.boundary === "scope_excluded");
  const limits = boundaries.filter(item => item.boundary !== "scope_excluded");
  const unavailable = unique(coverage.unavailable, item => `${item.provider}\0${item.reason}`);
  const truncated = unique(coverage.truncated, item => item.path);
  const failures = unique((coverage.probes || []).filter(item => ["failed", "degraded"].includes(item.status)),
    item => `${item.name}\0${item.detail}`);
  const groups = [
    ["Access restricted", restricted,
      "File permissions or your operating system prevented these reads. Review the paths below; allow access only to locations you want included, then scan again.",
      item => [item.path, item.reason]],
    ["Scan limit reached", limits,
      "This scan has a time and entry limit to keep your device responsive. The locations below were not fully checked. A scan does not promise every installed tool was found.",
      item => [item.path, item.detail || String(item.boundary).replaceAll("_", " ")]],
    ["Optional sources unavailable", unavailable,
      "Some operating-system sources are not available on this device. For example, macOS does not expose its DNS cache. Other inventory sources still work.",
      item => [item.provider.replaceAll("_", " "), item.reason]],
    ["Partial files or directories", truncated,
      "These inputs exceeded a read limit. Their contents may be only partly represented in this inventory.",
      item => [item.path, `${number(item.kept)} of ${number(item.true_count)} bytes or entries read`]],
    ["Sources needing attention", failures,
      "These sources could not be fully processed. Review the reported reason below.",
      item => [item.name, item.detail || item.status]],
    ["Private locations skipped", skipped,
      "Discovery deliberately skips personal locations such as SSH keys and personal documents. This is not a scan error or a file-protection rule.",
      item => [item.path, "Excluded by the inventory privacy policy"]],
    ["Dependency and cache folders skipped", excluded,
      "The broad folder scan skips dependency trees and caches. Dedicated application and package checks run separately.",
      item => [item.path, item.detail]],
  ].filter(([, items]) => items.length);
  const summary = [
    restricted.length && `${number(restricted.length)} access restrictions`,
    limits.length && "scan limit reached",
    unavailable.length && `${number(unavailable.length)} optional sources unavailable`,
    truncated.length && "some inputs partial",
    failures.length && "some sources need attention",
  ].filter(Boolean).join(" · ");
  const sections = groups.map(([title, items, explanation, values]) =>
    el("details", { class: "inventory-coverage-group" },
      el("summary", {}, `${title} (${number(items.length)})`),
      el("p", { class: "small muted" }, explanation),
      inventoryPages(items, item => {
        const [name, reason] = values(item);
        return el("div", { class: "inventory-coverage-row" },
          el("code", { class: "path" }, name), el("p", { class: "small muted" }, reason));
      }, title.toLowerCase())));
  return el("details", { class: "inventory-coverage" },
    el("summary", {}, icon(summary ? "alert" : "check"), el("div", {},
      el("strong", {}, summary ? "What this scan could check" : "Scan coverage"),
      el("span", { class: "small muted" }, summary || (groups.length ? "Some locations were intentionally skipped" : "No limits reported by the scanned sources")))),
    el("div", { class: "inventory-coverage-body" },
      el("p", { class: "small muted" }, "A configured item is not necessarily enabled or running. Inventory never executes discovered agents or enables protection."),
      ...sections));
}
async function inventoryPage() {
  const data = await api("/inventory");
  const detected = data.snapshot?.assets || [];
  const candidates = (data.snapshot?.review_queue || []).filter(item =>
    item.suspected_name && ["binary", "process", "exec_event"].includes(item.candidate_kind));
  const assets = [...detected, ...candidates.map(item => ({
    name: item.suspected_name, path: item.path, kind: "unverified_executable", liveness: "unverified",
  }))];
  const params = new URLSearchParams(location.search);
  let query = params.get("q") || "", kind = params.get("kind") || "", currentPage = Math.max(0, Math.floor(Number(params.get("page")) || 0));
  let assetId = params.get("asset") || "";
  const rows = el("tbody", { role: "rowgroup" }), results = el("div", {}), pager = el("div", { class: "inventory-pager" });
  const selectedItem = el("div", { class: "threat-inventory-selection" });
  const count = el("span", { class: "small muted", role: "status", "aria-live": "polite" });
  const search = el("input", { type: "search", name: "inventory_search", "aria-label": "Search inventory",
    placeholder: "Search names or paths…", value: query, autocomplete: "off", spellcheck: "false" });
  const choices = [
    ["", "All items"], ["applications", "Applications & CLIs"],
    ...[...new Set(assets.map(asset => asset.kind))].filter(item => item && !inventoryApplications.has(item))
      .sort().map(item => [item, inventoryKinds[item] || item.replaceAll("_", " ")]),
  ];
  if (!choices.some(([value]) => value === kind)) kind = "";
  const filter = el("select", { name: "inventory_kind", "aria-label": "Inventory type" },
    ...choices.map(([value, label]) => el("option", { value, selected: kind === value }, label)));
  const syncUrl = () => {
    const url = new URL(location.href);
    for (const [key, value] of [["q", query], ["kind", kind], ["asset", assetId], ["page", currentPage ? String(currentPage) : ""]])
      if (value) url.searchParams.set(key, value); else url.searchParams.delete(key);
    history.replaceState(history.state, "", url);
  };
  const draw = (updateUrl = true) => {
    const term = query.trim().toLocaleLowerCase();
    const filtered = assets.filter(asset => (!assetId || asset.asset_id === assetId) &&
      (!kind || (kind === "applications" ? inventoryApplications.has(asset.kind) : asset.kind === kind)) &&
      (!term || `${inventoryTitle(asset)} ${inventoryPath(asset)} ${inventoryKinds[asset.kind] || asset.kind} ${asset.vendor || ""}`
        .toLocaleLowerCase().includes(term)));
    currentPage = Math.min(currentPage, Math.max(0, Math.ceil(filtered.length / 25) - 1));
    if (updateUrl && location.pathname === "/inventory") syncUrl();
    rows.replaceChildren(...filtered.slice(currentPage * 25, (currentPage + 1) * 25).map(asset => {
      const brand = inventoryBrand(asset);
      const status = ({ installed: "Installed", running: "Running", declared_only: "Configured", unverified: "Unverified" })[asset.liveness] || "Reported";
      return el("tr", { role: "row" },
        el("td", { role: "cell" }, el("div", { class: "inventory-item" },
          el("span", { class: `inventory-mark inventory-mark-${brand.tone}`, "aria-hidden": "true", title: brand.label },
            brand.mark || icon(asset.kind === "hook" ? "activity" : asset.kind === "skill" ? "file" : "inventory")),
          el("div", {}, el("strong", {}, inventoryTitle(asset)),
            el("div", { class: "muted small path" }, inventoryPath(asset))))),
        el("td", { role: "cell", "data-label": "Type" }, tag(inventoryKinds[asset.kind] || String(asset.kind || "Unknown").replaceAll("_", " "))),
        el("td", { role: "cell", "data-label": "Status", title: status === "Configured" ? "Declared in local configuration; not proof that it is enabled or running." :
          status === "Unverified" ? "Filename matches a known tool; ADR could not confirm its publisher or package identity." : "" },
          tag(status, status === "Running" ? "green" : status === "Unverified" ? "amber" : "neutral")),
        el("td", { role: "cell", "data-label": "Version", class: "small muted" }, asset.version || "Not reported"));
    }));
    count.textContent = `${number(filtered.length)} ${filtered.length === 1 ? "item" : "items"}${query || kind || assetId ? ` of ${number(assets.length)}` : ""}`;
    selectedItem.replaceChildren(...(assetId ? [
      el("span", { class: "small muted" }, "Showing the inventory item linked to this threat finding."),
      button("Show all items", () => { assetId = ""; query = ""; kind = ""; currentPage = 0; search.value = ""; filter.value = ""; draw(); },
        { variant: "quiet" }),
    ] : []));
    results.replaceChildren(filtered.length ? el("div", { class: "table-wrap inventory-table" }, el("table", { role: "table" },
      el("caption", { class: "inventory-caption" }, "Discovered applications and their local configuration"),
      el("thead", { role: "rowgroup" }, el("tr", { role: "row" },
        ...["Item", "Type", "Status", "Version"].map(text => el("th", { scope: "col", role: "columnheader" }, text)))), rows)) :
      empty("No matching items", "Try another name or clear the filters.",
        button("Clear filters", () => { assetId = ""; query = ""; kind = ""; currentPage = 0; search.value = ""; filter.value = ""; draw(); })));
    pager.replaceChildren(
      muted(filtered.length ? `${number(currentPage * 25 + 1)}–${number(Math.min((currentPage + 1) * 25, filtered.length))} of ${number(filtered.length)}` : "0 items"),
      ...(filtered.length > 25 ? [
        button("Previous", () => { currentPage--; draw(); }, { disabled: currentPage === 0, "aria-label": "Previous inventory page" }),
        button("Next", () => { currentPage++; draw(); }, { disabled: (currentPage + 1) * 25 >= filtered.length, "aria-label": "Next inventory page" }),
      ] : []));
  };
  search.addEventListener("input", () => { assetId = ""; query = search.value; currentPage = 0; draw(); });
  filter.addEventListener("change", () => { assetId = ""; kind = filter.value; currentPage = 0; draw(); });
  if (assets.length) draw(false);
  return [
    pageHeading("INSIGHTS", "AI inventory", "The AI apps on your device, and the skills, hooks, and MCP servers configured for them.",
      button(data.phase === "scanning" ? "Scanning…" : "Scan this device", async () => {
        await perform(() => api("/inventory/scan", { method: "POST" }), "Local inventory scan started"); render();
      }, { variant: "primary", symbol: "refresh", disabled: data.phase === "scanning" })),
    data.phase === "error" && el("div", { class: "banner warning", role: "alert" }, icon("alert"),
      "The latest inventory scan failed. Your previous results are still here. Try scanning again."),
    data.updated_at && el("div", { class: "session-facts" }, tag(`${number(assets.length)} items`),
      candidates.length > 0 && tag(`${number(candidates.length)} unverified`, "amber"),
      muted(`Last scan ${time(data.updated_at)}`),
      el("span", { class: "small muted" }, "Inventory scans run separately from session capture.")),
    data.access?.coverage?.access?.group_count > 0 && deviceAccessCard(data.access, { compact: true }),
    inventoryCoverage(data.snapshot?.coverage, data.access, data.updated_at),
    card("On this device", "Applications includes desktop apps, CLI agents, AI browsers, and local model runtimes.",
      assets.length ? [
        candidates.length > 0 && el("p", { class: "small muted inventory-candidate-note" },
          "Unverified executables match a known tool’s filename. ADR has not confirmed who published them; they are not verified installations."),
        selectedItem,
        el("div", { class: "inventory-controls" }, el("div", { class: "inventory-search" }, icon("search"), search),
          selectControl(filter), count),
        results, pager,
      ] : empty(data.phase === "scanning" ? "Looking for AI tools…" : data.snapshot ? "No tools identified in this scan" : "See your AI tools in one place",
        data.snapshot ? "Review scan coverage above to see which locations were checked." : "Run a local scan to find applications and their configured extensions. Scanning does not turn on protection.")),
    data.snapshot?.findings?.length ? card("Inventory notes", "Configuration observations from ADR Discovery, not threat verdicts.",
      inventoryPages(data.snapshot.findings, finding => el("div", { class: "activity-row" },
        icon("alert"), el("div", {}, el("strong", {}, finding.summary || finding.rule || "Finding"),
          el("p", { class: "muted" }, finding.detail || finding.description || ""))), "notes")) : null,
  ];
}
let nextDialogId = 0;
function dialog(title, subtitle, build, submitText = "Save", submit) {
  const identifier = `adr-dialog-${++nextDialogId}`;
  const modal = el("dialog", { class: "dialog", "aria-labelledby": `${identifier}-title`,
    "aria-describedby": subtitle ? `${identifier}-description` : undefined });
  const form = el("form", { method: "dialog", class: "dialog-form" });
  const close = () => { modal.close(); modal.remove(); };
  const fields = el("div", { class: "form-fields" });
  build(fields, close);
  let submitting = false;
  const cancel = button(submit ? "Cancel" : submitText, close);
  const dismiss = button("", close, { variant: "icon-button", symbol: "close", "aria-label": "Close dialog" });
  const errorText = el("p", { class: "dialog-error", hidden: "", role: "alert", tabindex: "-1" });
  const save = el("button", { type: "submit", class: "button primary" }, submitText);
  form.append(el("div", { class: "dialog-heading" }, el("div", {},
    el("h2", { id: `${identifier}-title` }, title),
    subtitle && el("p", { id: `${identifier}-description` }, subtitle)), dismiss),
  fields, errorText, el("div", { class: "dialog-actions" }, cancel, submit && save));
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submitting) return;
    if (!submit) { close(); return; }
    submitting = true; form.setAttribute("aria-busy", "true"); errorText.hidden = true;
    save.disabled = true; cancel.disabled = true; dismiss.disabled = true;
    save.replaceChildren(icon("refresh", "progress-spinner"), "Working…");
    try { await submit(new FormData(form)); close(); await loadStatus(); await render(); }
    catch (error) {
      if (modal.isConnected) {
        errorText.textContent = error.message; errorText.hidden = false; errorText.focus();
      } else notice(error.message, true);
    }
    finally {
      submitting = false; form.setAttribute("aria-busy", "false");
      save.disabled = false; cancel.disabled = false; dismiss.disabled = false; save.textContent = submitText;
    }
  });
  modal.append(form); document.body.append(modal);
  modal.addEventListener("cancel", event => { event.preventDefault(); if (!submitting) close(); });
  modal.showModal(); return modal;
}
let nextFieldId = 0;
function field(label, input, help) {
  const identifier = `adr-field-${++nextFieldId}`;
  const caption = el("span", { id: `${identifier}-label` }, label);
  const control = input.matches?.("input, select, textarea") ? input : input.querySelector?.("input, select, textarea");
  if (control) {
    if (!control.id) control.id = identifier;
    if (!control.hasAttribute("aria-label") && !control.hasAttribute("aria-labelledby"))
      control.setAttribute("aria-labelledby", caption.id);
    if (help && !control.hasAttribute("aria-describedby"))
      control.setAttribute("aria-describedby", `${identifier}-help`);
  }
  return el("label", { class: "field", for: control?.id }, caption,
    input.tagName === "SELECT" ? selectControl(input) : input,
    help && el("small", { id: `${identifier}-help` }, help));
}
function selectControl(input) {
  // Keep native keyboard, touch-picker, form and screen-reader behavior.
  return el("span", { class: "select-control" }, input, icon("chevron", "select-chevron"));
}
async function pickPath(input, kind) {
  try {
    const result = await api("/native/choose-path", { method: "POST", timeout: 125000 });
    if (result.path) { input.value = result.path; if (kind) kind.value = result.kind; }
  } catch (error) { notice(error.message, true); }
}
function ruleDialog() {
  dialog("Protect a file or folder", "Choose what agents should ask about—or never access.", (fields) => {
    const path = el("input", { name: "path", required: "", placeholder: "~/Documents/private", autocomplete: "off" });
    const kind = el("select", { name: "kind" },
      el("option", { value: "directory" }, "Folder and everything inside"),
      el("option", { value: "file" }, "One file"));
    fields.append(
      field("File or folder", el("div", { class: "input-with-button" }, path,
        button("Browse", () => pickPath(path, kind), { symbol: "folder", disabled: !state.status.vault_available }))),
      field("Scope", kind),
      field("Name", el("input", { name: "label", placeholder: "Personal documents", maxlength: "100" })),
      field("When an agent tries to access it", el("select", { name: "action" },
        el("option", { value: "ask" }, "Ask me first"), el("option", { value: "block" }, "Block access"))),
      el("div", { class: "form-note" }, icon("shield"), "Rules take effect through connected agent hooks, not an OS sandbox."));
  }, "Add protection", async data => {
    await api("/protection/rules", { method: "POST", body: Object.fromEntries(data) });
    notice("File protection rule added");
  });
}
function confirmDialog(title, text, action, label = "Confirm") {
  return dialog(title, text, fields => {}, label, action);
}
function starterProtectionCard(starter) {
  if (!starter.supported || starter.applied) return null;
  const connected = state.status.hooks.some(hook => hook.installed);
  const status = starter.available ? `${starter.available} paths ready to add` :
    starter.covered === starter.items.length ? "All starter paths have rules" : "Your existing choices are kept";
  return card("Start with the essentials",
    "One click adds Block rules for common credential stores: keys, cloud access, and package tokens.",
    el("div", { class: "starter-controls" },
      el("div", {}, el("strong", {}, status),
        el("p", { class: "small muted" }, "Your custom rules stay unchanged. You can remove any rule afterward.")),
      button("Add starter protections", async event => {
        const control = event.currentTarget;
        control.disabled = true;
        try {
          const result = await api("/protection/starter", { method: "POST", body: {} });
          notice(result.added ? `Added ${result.added} starter protections` : "Your existing protections were kept");
          await loadStatus(); await render();
        } catch (error) { notice(error.message, true); }
        finally { control.disabled = !starter.available; }
      }, { variant: "primary", symbol: "shield", disabled: !starter.available || !connected })),
    el("details", { class: "starter-preview" },
      el("summary", {}, `Review ${starter.items.length} standard paths`),
      el("p", { class: "small muted" }, "These are standard locations, not a scan of your secrets. Rules also apply if a listed path is created later."),
      ...starter.items.map(item => el("div", { class: "starter-path" },
        el("div", {}, el("strong", {}, item.label), el("code", { class: "path" }, item.path),
          el("p", { class: "small muted" }, item.description),
          ["custom", "unavailable"].includes(item.state) && el("p", { class: "small muted" }, item.note)),
        tag(item.state === "available" ? "Block" : item.state === "covered" ?
          (item.existing_action === "block" ? "Block rule kept" : "Ask first kept") :
          item.state === "custom" ? "Custom rule kept" : "Review manually",
          item.state === "available" ? "red" : item.state === "covered" && item.existing_action === "block" ? "green" : "amber")))),
    starter.review_required > 0 && el("p", { class: "starter-note small" }, icon("alert"),
      "An existing rule has a path that cannot be checked. Review your rules before adding the starter set."),
    (!starter.enabled || !connected) && el("p", { class: "starter-note small" }, icon("alert"),
      !starter.enabled ? "File rules are paused. Adding this set does not resume them." :
        "Connect an agent above first. Then you can enable the starter set."),
    el("p", { class: "starter-limit small muted" },
      "Project .env files and custom credential locations need their own rules. File hooks do not lock operating-system credential APIs."));
}
function protectedRuleRow(rule) {
  return el("div", { class: "rule-row" },
    el("span", { class: "rule-icon" }, icon(rule.kind === "file" ? "file" : "folder")),
    el("div", { class: "rule-main" }, el("strong", {}, rule.label), el("code", { class: "path" }, rule.path)),
    tag(rule.action === "block" ? "Block" : "Ask first", rule.action === "block" ? "red" : "amber"),
    button("", () => confirmDialog("Remove this protection?", rule.path, async () => {
      await api(`/protection/rules/${rule.id}`, { method: "DELETE" }); notice("Rule removed");
    }, "Remove rule"), { variant: "icon-button", symbol: "trash", "aria-label": `Remove ${rule.label}` }));
}
function connectADR() {
  const detected = state.status.hooks.filter(hook => hook.available || hook.installed);
  dialog("Connect installed agents", "One ADR plugin. No project folders, key selections, or MCP configuration to copy.", fields => {
    fields.append(
      el("p", {}, detected.length ? `Found on this device: ${detected.map(hook => hook.name).join(", ")}.` :
        "ADR will look for Claude Code, Codex, opencode, and GitHub Copilot CLI."),
      el("p", { class: "small" }, "Connected agents can search captured conversations across this device and use all saved credentials in local commands, including credentials you add later. Your file-protection rules still apply."),
      el("p", { class: "small" }, "Local programs receive the real values. The model receives variable names and filtered command output. ADR does not grant permission to change its own settings."),
      el("p", { class: "small muted" }, "ADR preserves other plugins and settings. Restart your agents afterward and complete their native trust prompts. Prompt blocking is currently supported for Claude Code and Codex."));
  }, "Connect installed agents", async () => {
    const result = await api("/integrations/connect-all", {
      method: "POST", body: { allow_agents: true }, timeout: 600000,
    });
    const configured = result.items.filter(item => item.status === "configured");
    const failed = result.items.filter(item => item.status === "needs_repair");
    if (!configured.length && !failed.length) throw new Error("No supported agent CLI was found. Install an agent, then try again.");
    if (failed.length) {
      setTimeout(() => dialog("ADR connection results", "Some agents need attention. Completed connections are kept.", fields => {
        result.items.forEach(item => fields.append(el("p", { class: "small" },
          `${sourceName(item.harness)}: ${item.status === "configured" ? "Configured — restart the agent" :
            item.status === "not_installed" ? "CLI not found" : "Setup failed — check the agent’s plugin settings and try again"}`)));
      }, "Done"), 0);
    }
    notice(`${configured.length} agent${configured.length === 1 ? "" : "s"} configured. Restart them to load ADR.`, failed.length > 0);
  });
}
function agentIntegrationCard() {
  const agents = state.status.hooks;
  const ready = agents.filter(hook => hook.vault_connected && !hook.needs_update);
  return card("One ADR plugin", "Conversation search, saved credentials, and file-protection hooks in each supported agent.",
    el("div", { class: "integration-heading" },
      el("p", { class: "small muted" }, ready.length ?
        `${ready.map(hook => hook.name).join(", ")} configured. New credentials are available without reconnecting.` :
        "Connect once for all installed agents. No separate vault setup."),
      button(ready.length ? "Update installed agents" : "Connect installed agents", connectADR,
        { variant: ready.length ? "secondary" : "primary", symbol: "shield" })),
    el("ul", { class: "integration-list", "aria-label": "ADR agent integrations" }, ...agents.map(hook =>
      el("li", {}, el("div", {}, el("strong", {}, hook.name),
        el("p", { class: "small muted" }, hook.vault_connected ? "History, credentials, and protection" :
          hook.installed ? "Update to include the credential vault" :
            hook.available ? "Ready to connect" : "CLI not found on this device")),
      tag(hook.vault_connected && !hook.needs_update ? "Configured" : hook.installed ? "Update needed" :
        hook.available ? "Not connected" : "Not installed", hook.vault_connected && !hook.needs_update ? "green" : "neutral"),
      hook.installed && button("", () => confirmDialog(`Disconnect ADR from ${hook.name}?`,
        "This removes its ADR integration and revokes history and credential use. Your saved values, file rules, and other plugins stay in place.", async () => {
          await api(`/integrations/${hook.harness}/disconnect`, { method: "POST", timeout: 180000 });
          notice("ADR disconnected");
        }, "Disconnect"), { variant: "icon-button", symbol: "close", "aria-label": `Disconnect ${hook.name}` })))),
    el("p", { class: "small muted" }, "Restart agents after setup and review their native trust prompts. A configured plugin is not proof that every hook is loaded."));
}
async function protectionPage() {
  const [policy, events, starter] = await Promise.all([
    api("/protection"), api("/protection/events?interventions_only=true&limit=20"), api("/protection/starter"),
  ]);
  const interventions = events.items.filter(item => item.decision === "deny" || item.decision === "ask" ||
    item.approval_requested === true || item.decision === "pass" && item.reason === "Allowed once in ADR");
  const customRules = policy.rules.filter(rule => rule.preset !== starter.id);
  const starterRules = policy.rules.filter(rule => rule.preset === starter.id);
  const connected = state.status.hooks.filter(hook => hook.installed);
  const seen = connected.some(hook => hook.last_event);
  const statusText = !connected.length ? "Not connected" : !policy.enabled ? "Protection paused" :
    seen ? "Hooks reporting" : "Setup saved · restart your agent";
  const currentReview = policy.strict_execution ? policy.opaque_tools : "off";
  const executionReview = el("select", {
    "aria-label": "Command and unknown-tool review",
    onChange: async event => {
      const select = event.target, mode = select.value;
      select.disabled = true;
      try {
        await perform(() => api("/protection", { method: "PATCH", body: {
          strict_execution: mode !== "off",
          ...(mode === "off" ? {} : { opaque_tools: mode }),
        } }), "Command approval preference updated");
        render();
      } catch { select.value = currentReview; }
      finally { select.disabled = false; }
    },
  }, el("option", { value: "off" }, "Off (default)"),
  el("option", { value: "ask" }, "Ask each time"),
  el("option", { value: "block" }, "Block"));
  executionReview.value = currentReview;
  return [
    pageHeading("PROTECTION", "File protection", "Connect your agent, then choose which files it must leave alone.",
      button("Protect a path", ruleDialog, { variant: "primary", symbol: "plus" })),
    el("div", { class: `banner ${connected.length && policy.enabled && seen ? "secure" : "warning"}` },
      icon("shield"), el("div", {}, el("strong", {}, statusText), el("p", {},
        !connected.length ? `${policy.rules.length ? "Your saved rules are not active yet. " : ""}Connect an agent below. Rules do not protect agents without an ADR hook.` :
          !policy.enabled ? "Your rules are saved, but file protection is paused." :
            "Restart an agent after connecting or updating its hook. Its first tool request confirms the connection."))),
    agentIntegrationCard(),
    starterProtectionCard(starter),
    card("Your file rules", connected.length ? "Block takes priority when rules overlap." : "Saved only. Connect an agent to enforce these rules.",
      el("div", { class: "card-controls" }, tag(!connected.length ? "Not active · no connection" :
        policy.enabled ? "Rules ready" : "File rules paused", connected.length && policy.enabled ? "green" : "amber"),
        button(policy.enabled ? "Pause file rules" : "Enable file rules", async () => {
          await perform(() => api("/protection", { method: "PATCH", body: { enabled: !policy.enabled } })); render();
        }, { variant: "quiet" })),
      policy.rules.length ? el("div", {}, ...customRules.map(protectedRuleRow),
        starterRules.length > 0 && el("details", { class: "starter-rules" },
          el("summary", {}, `Starter rules (${starterRules.length})`), ...starterRules.map(protectedRuleRow))) :
        empty("Start with your crown jewels", "Protect a private folder, an environment file, or another sensitive path.",
          button("Choose a path", ruleDialog, { symbol: "plus" })),
      starter.applied && starter.available > 0 && button("Restore missing starter rules", async () => {
        await perform(() => api("/protection/starter", { method: "POST", body: {} }), "Missing starter rules restored"); render();
      }, { variant: "quiet", disabled: !connected.length }),
      el("details", { class: "starter-rules" },
        el("summary", {}, "Advanced: command approvals"),
        el("p", { class: "small muted" },
          "File rules check supported file tools. Command review is separate: turn it on to ask about, or block, shell commands and unrecognized tools. Off keeps the agent’s own permissions and supported credential-output checks."),
        selectControl(executionReview))),
    card("Blocks and approvals", "Recent blocked operations and approval requests.",
      interventions.length ? el("div", {}, ...interventions.map(item => el("div", { class: "activity-row protection-event" },
        icon(item.decision === "deny" ? "shield" : "activity"),
        el("div", {}, el("strong", {}, `${item.tool || "Operation"} · ${sourceName(item.harness)}`),
          item.paths?.length > 0 && el("code", { class: "path protection-event-path" }, item.paths.join(", ")),
          el("p", {}, item.credential_kinds?.length ? `${item.credential_kinds.join(", ")} detected · secret value not logged` : item.reason),
          item.credential_kinds?.length > 0 && link("Set up safe use in Credential vault", "/credentials")),
        tag(item.decision === "deny" ? "Blocked" : item.decision === "ask" ? "Approval requested" : "Allowed after approval",
          item.decision === "deny" ? "red" : item.decision === "ask" ? "amber" : "green"),
        muted(ago(item.timestamp))))) : el("div", { class: "small-empty" },
          connected.length > 0 ? "No blocks or approval requests yet." :
            "Connect an agent to see blocks and approval requests here.")),
  ];
}
const threatKindLabels = {
  file_sha256: "File hash", skill_sha256: "Skill hash", npm: "npm package",
  pypi: "PyPI package", mcp_endpoint: "MCP endpoint",
};
function threatCounts(counts = {}, label = "Active threat indicators") {
  return el("dl", { class: "threat-counts", "aria-label": label },
    ...Object.entries(threatKindLabels).map(([key, label]) => el("div", {},
      el("dt", {}, label), el("dd", {}, number(counts[key])))));
}
function threatPages(items, renderItem, label) {
  const key = `${label}_page`;
  const current = Number(new URLSearchParams(location.search).get(key));
  let page = Number.isFinite(current) ? Math.max(0, Math.floor(current)) : 0;
  page = Math.min(page, Math.max(0, Math.ceil(items.length / 20) - 1));
  const container = el("div", {}), rows = el("div", {}), controls = el("div", { class: "inventory-pager" });
  const draw = (updateUrl = false) => {
    if (updateUrl && state.route === "/threats") {
      const url = new URL(location.href);
      if (page) url.searchParams.set(key, String(page)); else url.searchParams.delete(key);
      history.replaceState(history.state, "", url);
    }
    rows.replaceChildren(...items.slice(page * 20, (page + 1) * 20).map(renderItem));
    controls.replaceChildren(
      muted(`${number(page * 20 + 1)}–${number(Math.min((page + 1) * 20, items.length))} of ${number(items.length)} ${label}`),
      ...(items.length > 20 ? [
        button("Previous", () => { page--; draw(true); }, { disabled: page === 0, "aria-label": `Previous ${label}` }),
        button("Next", () => { page++; draw(true); }, { disabled: (page + 1) * 20 >= items.length, "aria-label": `Next ${label}` }),
      ] : []));
  };
  draw(); container.append(rows, controls); return container;
}
function threatReference(value, index) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
    return el("a", { href: url.href, target: "_blank", rel: "noopener noreferrer",
      referrerpolicy: "no-referrer", class: "threat-reference" },
    `Source ${index + 1}: ${url.hostname}`, icon("arrow"));
  } catch { return null; }
}
function threatMatchDetails(item) {
  return el("details", { class: "threat-details", "data-view-key": `threat-match-${item.id}` },
    el("summary", {}, "Match details"),
    el("dl", { class: "threat-facts" },
      el("dt", {}, "Matched identity"), el("dd", {}, el("code", { translate: "no" }, item.target_display || "Not reported")),
      el("dt", {}, "Indicator"), el("dd", {}, el("code", { translate: "no" }, item.indicator_id || "Not reported")),
      el("dt", {}, "Feed"), el("dd", {}, el("code", { translate: "no" }, item.source_id || "Not reported")),
      item.generation && [el("dt", {}, "Generation"), el("dd", {}, el("code", { translate: "no" }, item.generation))]),
    Array.isArray(item.references) && el("div", { class: "threat-references" },
      ...item.references.map(threatReference)));
}
function threatFinding(item) {
  return el("article", { class: "threat-finding" },
    el("div", { class: "threat-item-heading" },
      el("h3", {}, item.label || item.target_display || "Matching item"), tag("Match found", "red")),
    el("p", { class: "small muted" }, threatKindLabels[item.kind] || (item.kind === "package" ? "Package" : "Artifact")),
    item.location && el("code", { class: "path threat-location", translate: "no" }, item.location),
    item.summary && el("p", { class: "small threat-summary" }, item.summary),
    threatMatchDetails(item),
    item.inventory_asset_id &&
      link("View item in AI inventory", `/inventory?asset=${encodeURIComponent(item.inventory_asset_id)}`, "threat-inventory-link"));
}
function threatBlock(item) {
  return el("article", { class: "threat-block" },
    el("div", { class: "threat-item-heading" },
      el("h3", {}, `${item.tool || "Operation"} · ${sourceName(item.harness)}`), tag("Blocked", "red")),
    el("p", { class: "small muted" }, time(item.timestamp)),
    el("code", { class: "path threat-location", translate: "no" }, item.target_display || "Known-malicious artifact"),
    el("p", { class: "small muted" },
      `${threatKindLabels[item.kind] || (item.kind === "package" ? "Package" : "Artifact")} matched before this supported operation.`),
    threatMatchDetails(item));
}
function threatImportDialog(document, preview) {
  return dialog("Import this threat list?", "Review the local list before changing the active feed.",
    fields => fields.append(...[
      el("dl", { class: "threat-facts" },
        el("dt", {}, "Feed"), el("dd", {}, el("code", {}, preview.feed_id)),
        el("dt", {}, "Revision"), el("dd", {}, el("code", {}, preview.revision)),
        el("dt", {}, "Active indicators"), el("dd", {}, number(preview.active_indicators)),
        el("dt", {}, "Revoked indicators"), el("dd", {}, number(preview.revoked_indicators))),
      el("p", { class: "small muted" }, "Active feed coverage after import"),
      threatCounts(preview.counts, "Active indicators after import"),
      preview.all_versions_count > 0 && el("div", { class: "banner warning threat-import-warning" },
        icon("alert"), el("p", {},
          `${number(preview.all_versions_count)} package ${preview.all_versions_count === 1 ? "indicator matches" : "indicators match"} all versions, not just specific releases.`)),
      el("p", { class: "small" }, preview.replaces_custom ?
        "This replaces your previous custom list. The bundled feed is kept." :
        "This adds a custom list alongside the bundled feed. The bundled feed is kept."),
      el("p", { class: "small muted" },
        "The list stays on this device. Importing does not upload findings, delete files, or change whether blocking is enabled.")
    ].filter(Boolean)),
    "Import list", async () => {
      await api("/threats/import", { method: "POST", body: {
        document, expected_revision: preview.expected_revision, confirm: true,
      } });
      notice("Threat list imported");
    });
}
async function threatsPage() {
  const data = await api("/threats");
  const feed = data.feed || {}, scan = data.scan || {};
  const findings = scan.findings || [], blocks = data.blocks || [];
  const hooks = (state.status.hooks || []).filter(hook => hook.installed);
  const reported = hooks.filter(hook => hook.last_event);
  const errors = el("p", { class: "error-text threat-action-error", role: "alert", hidden: "", tabindex: "-1" });
  const busy = el("span", { class: "small muted", role: "status", "aria-live": "polite" });
  let pending = false;
  const controls = [];
  const run = async (action, message) => {
    if (pending) return;
    pending = true;
    state.threatsPending = true;
    controls.forEach(control => { control.disabled = true; });
    errors.hidden = true;
    busy.textContent = message;
    try { await action(); }
    catch (error) {
      if (errors.isConnected) {
        errors.textContent = error.message; errors.hidden = false; errors.focus();
      } else notice(error.message, true);
    } finally {
      pending = false;
      state.threatsPending = false;
      controls.forEach(control => { control.disabled = false; });
      busy.textContent = "";
    }
  };
  const refresh = async () => { await loadStatus(); if (state.route === "/threats") await render(); };
  const toggle = button(data.enabled ? "On" : "Off", () => run(async () => {
    await api("/threats", { method: "PATCH", body: {
      enabled: !data.enabled, expected_revision: data.revision,
    } });
    notice(data.enabled ? "Artifact blocking turned off" : "Artifact blocking turned on");
    await refresh();
  }, "Saving blocking preference…"), {
    variant: "quiet", class: "button threat-switch", role: "switch",
    "aria-label": "Block known-malicious artifacts", "aria-checked": String(Boolean(data.enabled)),
    "aria-describedby": "threat-toggle-help",
  });
  const check = button("Check installed items", () => run(async () => {
    await api("/threats/check", { method: "POST", body: {} });
    notice("Installed-item check finished");
    await refresh();
  }, "Checking local items…"), { symbol: "refresh" });
  const fileInput = el("input", { type: "file", name: "threat-list", autocomplete: "off", accept: ".json,application/json",
    "aria-label": "Choose a local threat list", hidden: "" });
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    fileInput.value = "";
    if (!file) return;
    run(async () => {
      if (file.size > 512 * 1024) throw new Error("Choose a JSON threat list no larger than 512 KiB.");
      const document = await file.text();
      const preview = await api("/threats/import/preview", { method: "POST", body: {
        document, expected_revision: data.revision,
      } });
      if (state.route === "/threats") threatImportDialog(document, preview);
    }, "Reviewing the local list…");
  });
  const importButton = button("Import local list", () => fileInput.click(), { symbol: "file" });
  controls.push(toggle, check, importButton);
  const stateLabel = feed.state === "ready" ? "Feed loaded" :
    feed.state === "empty" ? "No active indicators" : "Feed needs attention";
  const checked = scan.state && scan.state !== "not_run";
  const scanSummary = checked ? el("div", { class: "threat-scan-summary" },
    tag(`${number(scan.checked_items)} items checked`),
    tag(`${number(findings.length)} matches`, findings.length ? "red" : "neutral"),
    tag(`${number(scan.skipped_items)} skipped`, scan.skipped_items ? "amber" : "neutral"),
    muted(`Last check ${time(scan.checked_at)}`)) : null;
  const feedDetails = el("details", { class: "threat-details threat-feed-details", "data-view-key": "threat-feed" },
    el("summary", {}, "Feed sources and revisions"),
    ...(feed.feeds || []).map(item => el("div", { class: "threat-feed-source" },
      el("strong", {}, item.feed_id),
      el("dl", { class: "threat-facts" },
        el("dt", {}, "Revision"), el("dd", {}, el("code", {}, item.revision)),
        el("dt", {}, "Published"), el("dd", {}, time(item.published_at)),
        el("dt", {}, "Indicators"), el("dd", {},
          `${number(item.active_indicators)} active, ${number(item.revoked_indicators)} revoked`)))),
    el("p", { class: "small muted" }, feed.imported_at ?
      `Custom list imported ${time(feed.imported_at)}.` : "No custom list imported."),
    feed.generation && el("p", { class: "small muted" }, "Active generation: ",
      el("code", { class: "path" }, feed.generation)));
  const feedCard = card("Your local threat feed", "Exact identities from the bundled feed and your optional custom list.",
    el("div", { class: "threat-feed-heading" },
      tag(stateLabel, feed.state === "ready" ? "neutral" : "amber"),
      el("span", { class: "small muted" },
        `${number(feed.counts?.total)} active indicators · ${number(feed.counts?.package_versions)} specific package releases`)),
    threatCounts(feed.counts),
    feed.error && el("p", { class: "error-text", role: "alert" }, feed.error),
    feed.state === "empty" && el("p", { class: "small muted" },
      "This feed has no active identities to match. An enabled switch alone cannot produce threat matches."),
    el("p", { class: "small muted threat-feed-note" },
      "A zero count means this feed has no indicators of that type. Items not on the list can still be harmful."),
    feedDetails,
    el("div", { class: "threat-import-actions" }, importButton, fileInput,
      el("span", { class: "small muted" }, "JSON · up to 512 KiB · reviewed before import")));
  const scanCard = card("Matches on this device", "Items that match your list. Attempts stopped by ADR appear in Blocked activity below.",
    el("div", { class: "threat-check-actions" }, check,
      el("span", { class: "small muted" }, "A bounded local check. No installs, uploads, or file changes.")),
    scanSummary,
    scan.stale && el("div", { class: "banner warning threat-scan-warning" }, icon("clock"),
      el("div", {}, el("strong", {}, "These results need a new check"),
        el("p", {}, "The active feed has changed. Check installed items again to refresh these findings."))),
    scan.state === "partial" && el("p", { class: "small muted threat-scan-note" },
      "Only part of the inventory could be checked. Skipped and unreadable items have no verdict."),
    scan.state === "error" && el("div", { class: "banner warning threat-scan-warning", role: "alert" },
      icon("alert"), el("p", {}, "The installed-item check did not finish. Try again; any shown findings are retained results.")),
    scan.issues?.length > 0 && el("details", { class: "threat-details threat-scan-issues", "data-view-key": "threat-issues" },
      el("summary", {}, "Skipped items and check limits"),
      el("ul", {}, ...scan.issues.map(issue => el("li", {},
        `${String(issue.reason || "Not checked").replaceAll("_", " ")}: ${number(issue.count)}`)))),
    findings.length ? threatPages(findings, threatFinding, "matches") :
      el("div", { class: "small-empty threat-empty" },
        !checked ? "Run a check to compare configured skills, packages, and MCP endpoints with this feed." :
          scan.state === "error" ? "There is no completed result for this check." :
            "No matches in the items checked against this feed."),
    link("Review inventory and scan coverage", "/inventory", "threat-inventory-link"));
  const blocksCard = card("Blocked activity", "Agent operations stopped because they matched a known-malicious artifact.",
    blocks.length ? threatPages(blocks, threatBlock, "blocks") :
      el("div", { class: "small-empty" }, "No artifact blocks recorded. This does not mean every operation was checked."));
  return [
    pageHeading("PROTECTION", "Malicious artifacts", "Block known-malicious skills, MCP servers, packages, and files in supported agent operations."),
    el("section", { class: "card threat-control", "aria-label": "Artifact blocking preference" },
      el("div", { class: "threat-control-row" },
        el("div", {}, el("h2", {}, "Block known-malicious artifacts"),
          el("p", { id: "threat-toggle-help", class: "small muted" }, data.enabled ?
            "On for supported operations. File protection and credential checks keep their own settings." :
            "Artifact blocking is off. File protection and credential checks keep their own settings.")),
        toggle),
      el("div", { class: "threat-connection-note" }, icon(hooks.length ? "activity" : "alert"),
        el("p", { class: "small muted" }, !hooks.length ?
          ["No agent hook is connected. ", link("Connect an agent", "/protection"), " to check supported operations."] :
          reported.length ? `${number(reported.length)} of ${number(hooks.length)} configured agent hooks have reported. A report is not proof that every operation is covered.` :
            "Hook configuration is saved. Restart your agent; no hook has reported yet.")),
      el("details", { class: "threat-details threat-coverage", "data-view-key": "threat-coverage" },
        el("summary", {}, "What these checks cover"),
        el("p", { class: "small muted" },
          "Checks cover supported tool requests, literal package commands, direct file reads, and resolvable MCP calls. They are not an operating-system sandbox."),
        el("p", { class: "small muted" },
          "Automatic skill loading, MCP server startup, arbitrary scripts, and transitive dependencies are not fully covered. Blocking a call cannot undo a server’s startup activity."))),
    el("div", { class: "threat-action-status" }, busy, errors),
    feedCard, scanCard, blocksCard,
    el("p", { class: "threat-privacy small muted" }, icon("lock"),
      "Matching stays on this device. ADR does not upload files, hashes, inventory, or reports. This feed has no automatic network updater."),
  ];
}
async function reviewSettingsDialog(data) {
  const filters = await api("/sessions/filters");
  const saved = data.settings;
  dialog("Security review settings", "Run local agent processes using your existing CLI sign-in.", fields => {
    const provider = el("select", { name: "provider" },
      ...[["claude", "Claude Code · claude -p"], ["codex", "Codex · app-server"]].map(([value, label]) =>
        el("option", { value, selected: value === saved.provider ? "" : undefined }, label)));
    const mode = el("select", { name: "mode" },
      el("option", { value: "budget", selected: saved.mode === "budget" ? "" : undefined }, "Use my review budget"),
      el("option", { value: "spare", selected: saved.mode === "spare" ? "" : undefined }, "Use spare subscription capacity"));
    const numeric = (name, value, min, max, step = 1) => el("input", {
      type: "number", name, value, min, max, step, required: "", inputmode: step === 1 ? "numeric" : "decimal",
    });
    const advancedBody = el("div", { class: "review-advanced-body" },
      field("Model (optional)", el("input", {
        name: "model", value: saved.model, maxlength: 100, autocomplete: "off", placeholder: "Use the agent’s default…",
      })),
      el("div", { class: "review-form-pair" },
        field("Reviews per 24 hours", numeric("daily_jobs", saved.daily_jobs, 1, 100)),
        field("Seconds per review", numeric("max_seconds", saved.max_seconds, 30, 600))));
    const advanced = el("details", { class: "review-advanced" },
      el("summary", {}, "More limits and model"), advancedBody);
    fields.append(
      field("Agent", provider, "Uses its current CLI account. ADR does not copy sign-in tokens."),
      el("div", { class: "review-form-pair" },
        field("Tokens per review", numeric("max_tokens", saved.max_tokens, 1000, 100000)),
        field("Review tokens per 24 hours", numeric("daily_tokens", saved.daily_tokens, 1000, 1000000))),
      el("p", { class: "small muted" },
        "Token budgets include input, cached input and output as reported by the agent. An in-flight response can exceed a limit. Interrupted runs keep their reservation."),
      field("When capacity is available", mode,
        "Spare-capacity mode requires fresh quota windows. Budgeted mode can run with unknown quota and stops when the agent reports a limit."),
    );
    const spare = el("div", { class: "review-spare-fields" },
      el("div", { class: "review-form-pair" },
        field("Keep this quota percentage for me", numeric("reserve_percent", saved.reserve_percent, 10, 90)),
        field("Start within hours of the next reset", numeric("reset_within_hours", saved.reset_within_hours, 1, 24))));
    const showMode = () => { spare.hidden = mode.value !== "spare"; };
    mode.addEventListener("change", showMode); showMode();
    const background = el("input", { type: "checkbox", name: "background", checked: saved.background });
    const idleOptions = el("div", { class: "review-idle-options" },
      field("Idle minutes before starting", numeric("idle_minutes", saved.idle_minutes, 5, 120)),
      el("fieldset", { class: "review-projects" }, el("legend", {}, "Projects for idle reviews"),
        ...(filters.projects || []).slice(0, 30).map(item => field(shortPath(item.project),
          el("input", { type: "checkbox", name: "projects", value: item.project,
            checked: saved.projects.includes(item.project) }), item.project)),
        !(filters.projects || []).length && el("p", { class: "small muted" }, "Capture sessions to choose their projects.")));
    const showIdle = () => { idleOptions.hidden = !background.checked; };
    background.addEventListener("change", showIdle); showIdle();
    fields.append(spare,
      field("Review while idle", background, "Wait for device inactivity and pause when you return."),
      idleOptions,
      field("Allow configured API or managed access", el("input", {
        type: "checkbox", name: "allow_paid", checked: saved.allow_paid,
      }), "This permits API/managed sign-ins. Your CLI’s billing and extra-usage settings still apply, including on subscriptions. ADR never buys credits or switches authentication."),
    );
    const dollars = el("div", { class: "review-form-pair" },
      field("Claude cost limit per review (USD)", numeric("max_cost_usd", saved.max_cost_usd, .01, 100, .01)),
      field("Claude cost budget per 24 hours (USD)", numeric("daily_cost_usd", saved.daily_cost_usd, .01, 100, .01)));
    advancedBody.append(dollars, el("p", { class: "small muted" },
      "Claude receives --max-budget-usd. Its reported model cost may differ from a subscription bill, and an in-flight response can overshoot. Codex uses token and time limits; no dollar cap is claimed."));
    fields.append(advanced,
      field("I approve sending selected session evidence through this agent", el("input", {
        type: "checkbox", name: "confirm_data_share", required: "",
      }), "The configured model provider receives the evidence, including history captured from other agents. Reviews cannot change repositories or use the ADR vault."),
    );
  }, "Save review settings", async form => {
    const numbers = ["max_tokens", "daily_tokens", "daily_jobs", "max_seconds", "max_cost_usd",
      "daily_cost_usd", "reserve_percent", "idle_minutes", "reset_within_hours"];
    await api("/reviews/settings", { method: "PATCH", body: {
      expected_revision: saved.revision, provider: form.get("provider"), model: form.get("model").trim(),
      mode: form.get("mode"), background: form.has("background"), allow_paid: form.has("allow_paid"),
      projects: form.getAll("projects"), confirm_data_share: form.has("confirm_data_share"),
      ...Object.fromEntries(numbers.map(key => [key, Number(form.get(key))])),
    } });
    notice("Security review settings saved");
  });
}
function reviewStartDialog(data, sessions, selectedId = "") {
  const requestId = crypto.randomUUID();
  dialog("Review a captured session", "Your local agent will receive the selected evidence for a read-only security review.", fields => {
    fields.append(field("Session", el("select", { name: "session_id", required: "" },
      ...sessions.map(item => el("option", { value: item.id, selected: item.id === selectedId ? "" : undefined },
        `${sourceName(item.source)} · ${item.title}`)))),
      el("p", { class: "small muted" },
        `${data.settings.provider === "claude" ? "Claude Code" : "Codex"} · Up to ${number(data.settings.max_tokens)} review tokens reserved · ${number(data.settings.max_seconds)} seconds maximum`),
      el("p", { class: "small muted" },
        "Checks may omit messages that exceed the input budget. Every report shows what was reviewed. No code edits, credential use or automatic fixes."),
    );
  }, "Start review", async form => {
    await api("/reviews/start", { method: "POST", body: {
      session_id: form.get("session_id"), request_id: requestId,
    }, timeout: 15000 });
    notice("Security review queued");
  });
}
function reviewWindowLabel(item) {
  const minutes = item.window_minutes;
  const unit = minutes % 1440 === 0 ? "day" : minutes % 60 === 0 ? "hour" : "minute";
  const amount = minutes / (unit === "day" ? 1440 : unit === "hour" ? 60 : 1);
  const bucket = item.name.includes(" / ") ? `${item.name.split(" / ")[0]} · ` : "";
  return `${bucket}${number(amount)}-${unit} window`;
}
async function reviewsPage() {
  const data = await api("/reviews"), settings = data.settings;
  const agent = settings.provider === "claude" ? "Claude Code" : "Codex";
  const settingsButton = button("Review settings", () => reviewSettingsDialog(data).catch(error => notice(error.message, true)),
    { symbol: "settings" });
  const review = button("Review now", async () => {
    try {
      // A just-saved dialog can close before the background page refresh
      // finishes. Read current consent/limits instead of a stale closure.
      const current = await api("/reviews");
      if (current.active) { notice("A security review is already running."); await render(); return; }
      if (!current.settings.consented) { await reviewSettingsDialog(current); return; }
      const sessions = (await api("/sessions?limit=100&grouped=true")).items || [];
      const selected = new URLSearchParams(location.search).get("session") || "";
      if (selected && !sessions.some(item => item.id === selected)) {
        sessions.unshift(await api(`/sessions/${encodeURIComponent(selected)}`));
      }
      if (!sessions.length) { notice("Capture a session before starting a review", true); return; }
      reviewStartDialog(current, sessions, selected);
    } catch (error) { notice(error.message, true); }
  }, { variant: "primary", symbol: "play", disabled: Boolean(data.active) });
  const quota = data.quota;
  const windows = quota?.windows || [];
  const quotaButton = button("Refresh agent usage", async () => {
    state.reviewPending = true; quotaButton.disabled = true;
    try {
      await api("/reviews/quota", { method: "POST", body: {}, timeout: 20000 });
      await render();
    } catch (error) { notice(error.message, true); }
    finally { state.reviewPending = false; quotaButton.disabled = false; }
  }, { symbol: "refresh" });
  const claudeUsageButton = button(data.claude_usage_connected ? "Disconnect Claude usage" : "Connect Claude usage", () => {
    const connect = !data.claude_usage_connected;
    dialog(connect ? "Connect Claude usage reporting?" : "Disconnect Claude usage reporting?",
      connect ? "ADR will wrap your Claude status-line command and preserve its displayed output." :
        "ADR will restore your previous status-line command if its bridge is still installed.",
      fields => fields.append(el("p", { class: "small muted" },
        "Only usage percentages and reset times are sent to the local ADR app. No model request is made. Restart Claude after changing this setting.")),
      connect ? "Connect usage" : "Disconnect usage", async () => {
        await api("/reviews/claude-usage", { method: "POST", body: { allow: connect } });
        notice(connect ? "Claude usage reporting connected" : "Claude usage reporting disconnected");
      });
  }, { symbol: "activity" });
  const jobs = data.jobs || [];
  const cards = jobs.map(job => {
    const findings = job.report?.findings || [];
    const label = job.state === "completed" ? job.coverage.partial ? "Partially reviewed" : "Reviewed" :
      ({ queued: "Queued", running: "Reviewing", failed: "Not completed", cancelled: "Stopped", interrupted: "Interrupted", skipped: "Not sent" }[job.state] || "Unknown");
    return el("article", { class: "card review-job", "data-review-id": job.id },
      el("div", { class: "review-job-heading" },
        el("div", {}, el("h2", {}, job.session_title || "Captured session"),
          el("p", { class: "small muted" }, `${sourceName(job.session_source)} session · Reviewed with ${job.provider === "claude" ? "Claude Code" : "Codex"} · ${time(job.created_at)}`)),
        tag(label, job.state === "failed" || job.coverage.partial ? "amber" : "neutral")),
      job.error && el("p", { class: "review-job-error small", role: "status" }, job.error),
      job.coverage.capture_partial && el("p", { class: "small muted" }, "The source capture was already partial."),
      job.coverage.evidence_deleted && el("p", { class: "small muted" }, "Session evidence and report deleted. Budget receipt retained."),
      job.stale && el("p", { class: "small muted" }, "This session changed after the reviewed snapshot."),
      job.report && el("p", { class: "review-summary" }, job.report.summary),
      job.state === "completed" && !findings.length && el("p", { class: "small muted" },
        "No supported finding in the supplied evidence. This is not a guarantee that the session is safe."),
      ...findings.map((finding, index) => el("details", { class: "review-finding", "data-view-key": `review-${job.id}-${index}` },
        el("summary", {}, tag(finding.severity, ["high", "critical"].includes(finding.severity) ? "red" : "amber"),
          el("strong", {}, finding.title)),
        el("p", {}, finding.explanation),
        el("blockquote", { class: "review-evidence" }, finding.evidence),
        el("p", { class: "small muted" }, `Message ${number(finding.message_index + 1)} · ${finding.confidence} confidence`),
        el("p", { class: "review-suggestion" }, finding.suggestion),
        link("View in session", `/sessions/${encodeURIComponent(job.session_id)}?find=${encodeURIComponent(finding.evidence.slice(0, 180))}`))),
      el("div", { class: "review-job-footer" },
        !job.coverage.evidence_deleted && link("Open session", `/sessions/${encodeURIComponent(job.session_id)}`),
        muted(`${number(job.coverage.included_messages)} of ${number(job.coverage.total_messages)} messages included`),
        muted(job.tokens === null ? `${number(job.token_charge)} tokens reserved` : `${number(job.tokens)} tokens reported`),
        job.id === data.active && button("Stop review", async event => {
          event.currentTarget.disabled = true;
          try { await api(`/reviews/${job.id}/cancel`, { method: "POST", body: {} }); notice("Stopping review"); }
          catch (error) { event.currentTarget.disabled = false; notice(error.message, true); }
        }, { symbol: "pause" })));
  });
  return [
    pageHeading("INSIGHTS", "Security reviews", "Let your agents check earlier work for security issues.", settingsButton, review),
    el("section", { class: "card review-control", "aria-label": "Review activity and budget" },
      el("div", { class: "review-control-main" }, icon(settings.background ? "moon" : "activity"),
        el("div", {}, el("h2", {}, data.active ? "A review is running" :
          settings.background ? data.scheduler : "Ready when you are"),
        el("p", { class: "small muted" },
          `${agent} · ${settings.background ? "Idle reviews enabled" : "Idle reviews off"} · ${settings.mode === "spare" ? "Spare capacity only" : "Within your review budget"}`))),
      el("div", { class: "review-budget-row" },
        el("div", {}, el("strong", {}, `${number(data.budget.tokens)} / ${number(settings.daily_tokens)}`),
          el("span", {}, "Review tokens · rolling 24 hours")),
        el("div", {}, el("strong", {}, `${number(data.budget.jobs)} / ${number(settings.daily_jobs)}`),
          el("span", {}, "Reviews · rolling 24 hours")),
        settings.provider === "claude" && settings.allow_paid && el("div", {},
          el("strong", {}, `${new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(data.budget.cost_usd)} / ${new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(settings.daily_cost_usd)}`),
          el("span", {}, "Claude reported cost + reservations · not an invoice"))),
      !data.available[settings.provider] && el("p", { class: "small error-text" }, `Install ${agent} and sign in through its CLI to run reviews.`),
      el("details", { class: "review-usage", "data-view-key": "review-usage" },
        el("summary", {}, "Agent usage and capacity"),
        el("p", { class: "small muted" }, data.admission.reason),
        quota && el("p", { class: "small muted" }, `Last reported ${time(new Date(quota.observed_at * 1000).toISOString())}`),
        ...windows.map(item => el("div", { class: "review-quota-window" },
          el("span", {}, reviewWindowLabel(item)),
          el("strong", {}, `${Math.round(item.used_percent)}% used`),
          el("span", { class: "muted" }, `Resets ${time(new Date(item.resets_at * 1000).toISOString())}`))),
        !windows.length && el("p", { class: "small muted" },
          settings.provider === "claude" ?
            "Claude reports limits during supported runs. Connect usage reporting for both subscription windows. Refresh checks sign-in; it does not spend tokens to probe quota." :
            "Refresh to request current windows from Codex’s app-server. Unknown usage is never shown as spare capacity."),
        settings.provider === "claude" && windows.length > 0 && el("p", { class: "small muted" },
          "Claude capacity is an estimate from CLI observations, usable for up to 30 minutes. Repeated status-line values do not refresh its age; older observations pause spare-capacity reviews."),
        data.admission.forecast && el("p", { class: "small muted" },
          data.admission.forecast.some(item => item.predicted_use_percent === null) ?
            "Learning usage patterns. Scheduling currently uses your reserve plus a safety margin." :
            "The headroom estimate also reserves projected consumption at your recent observed rate. Other-device activity can change it."),
        el("div", { class: "actions" }, quotaButton, settings.provider === "claude" && claudeUsageButton))),
    ...(cards.length ? cards : [empty("Your first security review", "Choose a captured session. Your agent will return findings with links to the original evidence.")]),
    el("p", { class: "small muted review-privacy" },
      "Reports stay on this device. Approved evidence goes through the selected agent’s configured model provider. In-flight requests can exceed a stop limit. ADR does not buy credits, change authentication, or publish fixes."),
  ];
}
function credentialDialog() {
  dialog("Add a credential", "Give it a name. Paste the value in the secure ADR window next.", fields => {
    const name = el("input", { name: "name", required: "", maxlength: "80", autocomplete: "off",
      placeholder: "e.g. Database password…" });
    const variable = el("input", { name: "env_name", required: "", maxlength: "64", autocomplete: "off",
      spellcheck: "false", pattern: "[A-Za-z_][A-Za-z0-9_]{0,63}", placeholder: "MY_PASSWORD" });
    let customized = false;
    const preview = el("code", { class: "path" }, "$MY_PASSWORD");
    variable.addEventListener("input", () => {
      customized = true; preview.textContent = "$" + (variable.value || "MY_PASSWORD");
    });
    name.addEventListener("input", () => {
      if (customized) return;
      variable.value = name.value.trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
      if (/^[0-9]/.test(variable.value)) variable.value = "MY_" + variable.value;
      preview.textContent = "$" + (variable.value || "MY_PASSWORD");
    });
    fields.append(
      field("Name", name, "A label you recognize. Don’t put the secret in the name."),
      field("Environment variable", variable, "No leading $. Use the name your code or CLI expects, such as GH_TOKEN or AWS_SECRET_ACCESS_KEY."),
      el("div", { class: "form-note" }, icon("terminal"), el("div", {},
        "Your agent refers to ", preview, ". Code launched through ADR can read it from its environment.")),
      el("div", { class: "form-note secure-note" }, icon("lock"),
        "Next: enter the value in ADR’s native window. It is encrypted in your local vault; no Keychain unlock is needed. Passwords, tokens, and multiline text are supported."),
      el("p", { class: "small muted" }, "Every agent connected through the ADR plugin can use this variable automatically. You do not need to reconnect after saving."));
  }, "Continue to secure window", async data => {
    await api("/environment-credentials", { method: "POST", timeout: 125000,
      body: { name: data.get("name"), env_name: data.get("env_name") } });
    notice("Credential saved. Connected agents can now use its variable name.");
  });
}
function serviceCredentialDialog() {
  dialog("Add an API credential", "Bind a credential to a service for API-only reads.", fields => {
    const name = el("input", {
      name: "name", required: "", placeholder: "e.g. My GitHub…", maxlength: "80", autocomplete: "off",
    });
    const origin = el("input", {
      name: "origin", type: "url", required: "", placeholder: "https://api.example.com",
      autocomplete: "off", spellcheck: "false",
    });
    const paths = el("textarea", { name: "paths", rows: "3", spellcheck: "false", autocomplete: "off" }, "/");
    const header = el("input", {
      name: "header_name", value: "X-API-Key", maxlength: "64", autocomplete: "off", spellcheck: "false",
    });
    const username = el("input", { name: "username", autocomplete: "off", maxlength: "200", spellcheck: "false" });
    const auth = el("select", { name: "auth_type" },
      el("option", { value: "bearer" }, "Bearer token"),
      el("option", { value: "api_key" }, "API key in a header"),
      el("option", { value: "basic" }, "Username and password (Basic auth)"));
    const headerField = field("API key header", header, "Use the header your service accepts, such as X-API-Key.");
    const usernameField = field("Username", username);
    const typeHelp = el("p", { class: "small muted", role: "status" });
    const scopeHelp = el("p", { class: "small muted vault-scope-summary" });
    const updateType = () => {
      headerField.hidden = header.disabled = auth.value !== "api_key";
      usernameField.hidden = username.disabled = auth.value !== "basic";
      username.required = auth.value === "basic";
      header.required = auth.value === "api_key";
      typeHelp.textContent = auth.value === "basic" ?
        "For APIs that accept a username and password. Paste only the password in the next window." :
        auth.value === "api_key" ? "Paste the API key in the next window. ADR adds it to this header locally." :
          "Paste the token in the next window. ADR adds the Bearer header locally.";
    };
    const updateScope = () => {
      const selected = paths.value.split("\n").map(value => value.trim()).filter(Boolean);
      scopeHelp.textContent = !selected.length || selected.includes("/") ?
        "Read requests can use any path on this service. You can narrow this below." :
        `Read requests are limited to: ${selected.join(", ")}.`;
    };
    auth.addEventListener("change", updateType);
    paths.addEventListener("input", updateScope);
    fields.append(
      el("div", { class: "vault-preset" }, el("span", { class: "small muted" }, "Setting up GitHub?"),
        button("Use GitHub settings", () => {
          if (!name.value.trim()) name.value = "My GitHub";
          origin.value = "https://api.github.com"; paths.value = "/user\n/repos"; auth.value = "bearer";
          updateType(); updateScope(); name.focus();
        }, { variant: "quiet" })),
      field("Name", name, "The name you and your agent will use. Don’t put the secret here."),
      field("Credential type", auth), typeHelp,
      field("Service URL", origin, "The API address, without a path. ADR sends the credential only to this HTTPS service."),
      headerField, usernameField, scopeHelp,
      el("details", { class: "vault-details" }, el("summary", {}, "Limit which API paths agents can use"),
        field("Allowed paths", paths, "One prefix per line. / means all paths; /repos includes its subpaths. Only GET requests are supported.")),
      el("div", { class: "form-note secure-note" }, icon("lock"),
        "Next: paste the value in the native ADR window. It goes into the encrypted local vault, not this page."));
    updateType(); updateScope();
  }, "Continue to secure window", async data => {
    const paths = String(data.get("paths") || "/").split("\n").map(value => value.trim()).filter(Boolean);
    const body = {
      name: data.get("name"), origin: String(data.get("origin")).trim(), auth_type: data.get("auth_type"),
      header_name: data.get("header_name") || "Authorization", username: data.get("username") || "",
      allowed_paths: paths.length ? paths : ["/"],
    };
    await api("/credentials", { method: "POST", body, timeout: 125000 });
    notice("Credential saved. Choose which agent can use it.");
  });
}
function environmentExample(item) {
  dialog("Use $" + item.env_name, "The value is available inside ADR-run Bash commands and their child programs.", fields => {
    const example = `Run my program through adr_run_command using $${item.env_name} from ADR Vault. Read it from the environment; do not request or print the value.`;
    fields.append(
      el("dl", { class: "vault-facts" },
        el("dt", {}, "Bash"), el("dd", {}, el("code", {}, "$" + item.env_name)),
        el("dt", {}, "Python"), el("dd", {}, el("code", {}, `os.environ["${item.env_name}"]`)),
        el("dt", {}, "JavaScript"), el("dd", {}, el("code", {}, `process.env.${item.env_name}`))),
      el("div", { class: "vault-example" }, el("strong", {}, "Ask your agent"),
        el("p", { class: "small" }, example),
        button("Copy request", async () => {
          try { await navigator.clipboard.writeText(example); notice("Request copied"); }
          catch { notice("Select and copy the request manually", true); }
        }, { symbol: "copy" })),
      el("p", { class: "small muted" },
        "The ADR plugin already includes these tools. No separate vault connection is needed. Your agent runs credential-dependent commands through ADR; values are not added to every shell or to the model’s environment."));
  }, "Done");
}
async function vaultAccessDialog(preselected = []) {
  const credentials = (await api("/credentials")).items.filter(item => item.state === "active");
  dialog("Allow an agent to use the vault", "Choose its credentials and whether it needs to ask you before using them.", fields => {
    const automatic = el("input", { name: "confirm_automatic", type: "checkbox", required: "" });
    const consent = el("label", { class: "consent" }, automatic,
      el("span", {}, "Allow requests to these saved services and paths without asking me each time."));
    const mode = el("select", { name: "approval_mode", "aria-label": "Credential permission", onChange: event => {
      automatic.required = event.target.value === "automatic";
      automatic.disabled = event.target.value !== "automatic";
      consent.hidden = event.target.value !== "automatic";
    } }, el("option", { value: "automatic" }, "Use allowed GET requests automatically"),
    el("option", { value: "ask" }, "Ask me before each request"));
    fields.append(
      field("Agent name", el("input", {
        name: "name", required: "", placeholder: "e.g. My Codex…", maxlength: "80", autocomplete: "off",
      })),
      el("fieldset", { class: "vault-choices" }, el("legend", {}, "Credentials this agent can use"),
        credentials.length ? el("div", { class: "checkbox-list" }, ...credentials.map(item =>
          el("label", {}, el("input", { type: "checkbox", name: "credentials", value: item.id, checked: preselected.includes(item.id) }),
            el("span", {}, item.name, el("small", {}, `${item.origin} · GET ${item.allowed_paths.join(", ")}`))))) :
          el("p", { class: "small muted" }, "Add a credential first.")),
      field("Permission", mode, "Automatic use avoids approval popups for requests within these limits."), consent,
      el("div", { class: "form-note" }, icon("key"),
        "Next you’ll get the ADR Vault connection to add to your agent. No file hook is required, and conversation history is not included."));
  }, "Allow selected access", async data => {
    if (!data.getAll("credentials").length) throw new Error("Select at least one credential for this agent.");
    const saved = await api("/agents", { method: "POST", body: {
      name: data.get("name"), kind: "vault", credentials: data.getAll("credentials"),
      approval_mode: data.get("approval_mode"), confirm_automatic: data.get("confirm_automatic") === "on",
    } });
    setTimeout(() => configDialog(saved.configuration), 0);
  });
}
function configDialog(configuration) {
  const servers = configuration.mcpServers;
  const isVault = Object.hasOwn(servers, "adr_vault");
  const isEnvironment = Object.hasOwn(servers, "adr_vault_env");
  function formatted(kind) {
    if (kind === "codex") return Object.entries(servers).map(([name, server]) =>
      `[mcp_servers.${name}]\ncommand = ${JSON.stringify(server.command)}\nargs = ${JSON.stringify(server.args)}${name === "adr_vault_env" ? "\ntool_timeout_sec = 180" : ""}`).join("\n\n");
    if (kind === "opencode") return JSON.stringify({ mcp: Object.fromEntries(Object.entries(servers).map(([name, server]) =>
      [name, { type: "local", command: [server.command, ...server.args], enabled: true }])) }, null, 2);
    return JSON.stringify(configuration, null, 2);
  }
  dialog(isEnvironment ? "Connect your vault environment" : isVault ? "Connect ADR Vault to your agent" : "Your MCP setup",
    "Add this server alongside your agent’s existing MCP servers. No secret values are included.", fields => {
    const code = el("pre", { class: "config-block" }, formatted("json"));
    fields.append(field("Agent configuration format", el("select", { onChange: event => { code.textContent = formatted(event.target.value); } },
      el("option", { value: "json" }, "Claude Code / standard MCP JSON"),
      el("option", { value: "codex" }, "Codex · config.toml"),
      el("option", { value: "opencode" }, "opencode · opencode.json"))), code,
      button("Copy configuration", async () => {
        try { await navigator.clipboard.writeText(code.textContent); notice("Configuration copied"); }
        catch { notice("Select and copy the configuration manually", true); }
      }, { symbol: "copy" }),
      el("p", { class: "small muted" }, "Restart the agent after adding its configuration. You can revoke this connection at any time."),
      isVault && el("div", { class: "form-note" }, icon("key"),
        "Then ask your agent to list its ADR Vault credentials. It can use adr_list_credentials and adr_request_service without receiving the secret."),
      isEnvironment && el("div", { class: "form-note" }, icon("terminal"),
        "Then ask the agent to list its vault variables with adr_list_environment. Use adr_run_command for Bash commands or code that needs them."));
  }, "Done");
}
function credentialDetailsDialog(item) {
  const examplePath = item.allowed_paths[0] || "/";
  const prompt = `Use ADR Vault to make a GET request to ${examplePath} on ${item.origin} using the credential named ${JSON.stringify(item.name)}. Find its reference with adr_list_credentials, submit it with adr_request_service, then check adr_service_result. Do not request or print the secret value.`;
  dialog(item.name, "Your agent uses this saved credential through ADR Vault.", fields => {
    fields.append(
      el("dl", { class: "vault-facts" },
        el("dt", {}, "Service"), el("dd", { class: "path" }, item.origin),
        el("dt", {}, "Allowed reads"), el("dd", { class: "path" }, item.allowed_paths.join(", ")),
        el("dt", {}, "Credential type"), el("dd", {}, credentialTypeName(item.auth_type)),
        el("dt", {}, "Agent reference"), el("dd", { class: "path mono" }, item.id)),
      el("p", { class: "small muted" },
        "Connect ADR Vault to your agent first. This reference is not a password; it works only for an agent you have allowed."),
      el("div", { class: "vault-example" }, el("strong", {}, "Try a request"),
        el("p", { class: "small" }, prompt),
        button("Copy example request", async () => {
          try { await navigator.clipboard.writeText(prompt); notice("Example request copied"); }
          catch { notice("Select and copy the example request manually", true); }
        }, { symbol: "copy" })),
      el("p", { class: "small muted" },
        "This example uses your first saved path. Replace it with the endpoint you need inside the allowed paths."));
  }, "Done");
}
function credentialTypeName(type) {
  return { bearer: "Bearer token", api_key: "API key", basic: "Username and password" }[type] || "Credential";
}
function connectionRow(item) {
  const scope = item.kind === "history" ? "Read-only · all captured history on this device" :
    item.kind === "execution" ? `${item.credentials.includes("*") ? "All current and future variables" : `${item.credentials.length} ${item.credentials.length === 1 ? "variable" : "variables"}`} · ${shortPath(item.project)} · ${item.approval_mode === "automatic" ? "automatic commands" : "ask each time"}` :
    item.kind === "vault" ? `${item.credentials.length} ${item.credentials.length === 1 ? "account" : "accounts"} · ${item.approval_mode === "automatic" ? "automatic use" : "ask each time"}` :
      `Existing project connection · ${item.project}`;
  return el("div", { class: "rule-row" }, icon(["vault", "execution"].includes(item.kind) ? "key" : "search"),
    el("div", { class: "rule-main" }, el("strong", {}, item.name), el("p", { class: "small muted path" }, scope)),
    tag(item.revoked ? "Revoked" : "Access granted", item.revoked ? "neutral" : "green"),
    !item.revoked && button("Setup", async () => {
      try { configDialog(await api(`/agents/${item.id}/configuration`)); } catch (error) { notice(error.message, true); }
    }, { variant: "quiet" }),
    !item.revoked && button("Revoke", () => confirmDialog("Revoke this access?", "The connection will stop working immediately.", async () => {
      await api(`/agents/${item.id}`, { method: "DELETE" }); notice("Access revoked");
    }, "Revoke access"), { variant: "quiet" }));
}
function credentialRequests(items) {
  const pending = items.filter(item => item.state === "pending");
  if (!pending.length) return null;
  return card("Requests needing your approval", "Only connections set to “Ask me before each request” appear here.",
    ...pending.map(item => el("article", { class: "approval" },
      el("div", { class: "approval-top" }, icon("key"), el("div", {},
        el("h3", {}, item.credential_name), muted(item.agent))),
      el("div", { class: "request-url" }, tag("GET"), el("code", {}, item.origin + item.path)),
      el("div", { class: "approval-bottom" }, muted(`Requested ${ago(item.created_at)}`),
        el("div", { class: "actions" }, button("Deny", async () => {
          await perform(() => api(`/approvals/${item.id}`, { method: "POST", body: { allow: false } }), "Request denied"); render();
        }), button("Approve once", async () => {
          await perform(() => api(`/approvals/${item.id}`, { method: "POST", body: { allow: true } }), "Approved once"); render();
        }, { variant: "primary" }))))));
}
async function credentialsPage() {
  const [credentials, agents, requests, protectionEvents, environment, storage] = await Promise.all([
    api("/credentials"), api("/agents"), api("/approvals"), api("/protection/events?interventions_only=true"),
    api("/environment-credentials"), api("/vault/storage"),
  ]);
  const access = agents.items.filter(item => item.kind === "vault" || item.kind === "legacy" && item.credentials.length);
  const findings = protectionEvents.items.filter(item => item.credential_kinds?.length);
  const connected = state.status.hooks.some(hook => hook.installed);
  const usedBy = id => access.filter(item => !item.revoked && item.credentials.includes(id));
  const recent = requests.items.filter(item => item.state !== "pending").slice(0, 8);
  const executionAccess = agents.items.filter(item => item.kind === "execution");
  const vaultAgents = state.status.hooks.filter(hook => hook.vault_connected);
  const promptAgents = state.status.hooks.filter(hook => hook.prompt_check).map(hook => hook.name);
  const storageById = new Map((storage.entries || []).map(item => [item.id, item]));
  const missing = [...environment.items, ...credentials.items].filter(item =>
    item.state === "active" && storageById.get(item.id)?.state === "missing");
  const interrupted = item => ["preparing", "unconfirmed", "error"].includes(item.state);
  const storageReady = item => item.state === "active" && storageById.get(item.id)?.state === "available";
  const storageExplanation = item => {
    const stored = storageById.get(item.id);
    if (interrupted(item) && (!stored || ["available", "missing"].includes(stored.state))) return stored?.state === "available" ?
      "A valid local copy was found. Recover this entry without deleting or replacing it." :
      "The save was not confirmed. Finish any open save window, then refresh storage. Existing copies are kept.";
    if (stored?.state === "available") return !item.env_name ?
      "Encrypted local copy ready. Existing service permissions still apply." :
      vaultAgents.length ? "Available to connected agents" : "Connect the ADR plugin below to use this variable";
    if (stored?.state === "missing") return "No local copy yet. Move an older Keychain entry or save the value again.";
    return ({
      local_vault_key_missing: "The local vault key is missing. Restore the complete vault backup; do not create a replacement key.",
      local_vault_key_invalid: "The local vault key is invalid. Restore the complete backup or re-enter credentials after reviewing recovery.",
      local_vault_corrupt: "This local copy could not be verified. Keep it for recovery; ADR has not replaced it.",
      local_vault_permissions: "The vault files need private owner-only permissions. Review the ADR profile; broader disk access will not fix this.",
      local_vault_unsafe_path: "A vault path is not safe to use. Check for moved files or symbolic links in the ADR profile.",
      local_vault_busy: "Another vault operation is finishing. Refresh storage in a moment.",
      local_vault_too_large: "The local record is larger than supported. Keep it for recovery and review the saved entry.",
    })[stored?.reason_code] || "Storage could not be checked. Open the ADR app and refresh; no credential was removed.";
  };
  const recoverEntry = item => confirmDialog("Recover this saved credential?",
    "ADR will verify its existing local copy and make the same entry available again. Its ID and agent permissions stay unchanged.",
    async () => {
      const response = await api("/vault/recover", { method: "POST", body: { ids: [item.id], confirm: true } });
      if (!response.items?.[0]?.recovered) throw new Error("No verified copy was available. Nothing was replaced.");
      notice("Saved credential recovered");
    }, "Recover saved entry");
  const finishEntry = item => confirmDialog("Finish this credential save?",
    "Enter the value again in ADR’s native window. This reuses the original entry and will not overwrite a local copy.",
    async () => {
      const response = await api("/vault/finish-save", {
        method: "POST", body: { ids: [item.id], confirm: true }, timeout: 125000,
      });
      if (!response.items?.[0]?.recovered) throw new Error("Refresh storage to check this save. Nothing was replaced.");
      notice("Credential saved");
    }, "Continue to secure window");
  const savedBadge = item => {
    const stored = storageById.get(item.id);
    if (interrupted(item)) return tag("Save needs confirmation", "amber");
    if (item.state !== "active") return tag(item.state, "amber");
    if (stored?.state === "available") return tag("Ready", "green");
    if (stored?.state === "missing") return tag("Move or re-enter", "amber");
    return tag("Check storage", "amber");
  };
  const moveCredentials = () => dialog("Move credentials to the local vault",
    "A one-time copy. Your existing Keychain entries stay intact.", fields => {
    fields.append(
      el("p", {}, `${number(missing.length)} saved ${missing.length === 1 ? "entry needs" : "entries need"} a local copy.`),
      el("ul", { class: "vault-migration-list" }, ...missing.map(item => el("li", {}, item.name))),
      el("p", { class: "small muted" }, "macOS may ask to allow this one-time Keychain read. Once copied, ADR uses its local vault for prompts and commands, without repeated Keychain dialogs."));
  }, "Move to local vault", async () => {
    const result = await api("/vault/migrate", { method: "POST",
      body: { ids: missing.map(item => item.id), confirm: true }, timeout: 125000 });
    const failed = (result.results || []).filter(item => item.status === "failed");
    const moved = (result.results || []).length - failed.length;
    notice(`${number(moved)} ${moved === 1 ? "credential is" : "credentials are"} ready in the local vault.`, failed.length > 0);
    if (failed.length) setTimeout(() => dialog("Some entries still need attention",
      "Completed copies are kept. All Keychain originals remain unchanged.", fields => {
      failed.forEach(item => fields.append(el("p", { class: "small" },
        `${missing.find(entry => entry.id === item.id)?.name || "Saved credential"}: ${
          item.reason_code === "legacy_keychain_missing" ? "No Keychain copy was found. Save the value again." :
          item.reason_code === "legacy_keychain_cancelled" ? "The Keychain request was cancelled." :
          item.reason_code === "legacy_keychain_locked" ? "Keychain is locked. Unlock it before moving this entry." :
          "The copy could not be completed. Refresh storage before trying again."}`)));
    }, "Done"), 0);
  });
  return [
    pageHeading("PROTECTION", "Credential vault", "Save the value here. Give your agent a variable name.",
      button("Add credential", credentialDialog, { variant: "primary", symbol: "plus", disabled: !credentials.available })),
    !credentials.available && el("div", { class: "banner warning" }, icon("lock"), el("div", {},
      el("strong", {}, "Open the ADR menu-bar app to use your vault"),
      el("p", {}, "The native app handles secret entry and local credential use. Your saved credentials stay in place."))),
    el("section", { class: "vault-explainer", "aria-label": "How the credential vault works" },
      el("div", {}, icon("lock"), el("strong", {}, "You save the value"),
        el("p", {}, "Paste it once in ADR’s secure window. It is encrypted on this device, with no recurring unlock prompt.")),
      el("div", {}, icon("key"), el("strong", {}, "Your agent uses $VARIABLE"),
        el("p", {}, "Every connected agent can use your saved variables. The model gets names, not values.")),
      el("div", {}, icon("terminal"), el("strong", {}, "ADR supplies the environment"),
        el("p", {}, "Bash and child programs receive the values. ADR filters their output before returning it."))),
    missing.length > 0 && el("section", { class: "banner info vault-migration", "aria-label": "Move saved credentials" },
      icon("key"), el("div", {}, el("strong", {}, "Saved entries need a local copy"),
        el("p", {}, "Move any previous Keychain values, or use Re-enter value on an entry. Existing copies are not overwritten."),
        button("Move to local vault", moveCredentials, { variant: "primary", disabled: !storage.available }))),
    credentials.available && !storage.available && el("div", { class: "banner warning", role: "status" },
      icon("alert"), el("div", {}, el("strong", {}, "Vault storage could not be checked"),
        el("p", {}, "Your entries are still listed below. Refresh after any pending vault operation finishes."))),
    card("Saved environment variables", "For passwords, tokens, keys, and code that reads credentials from its environment.",
      button("Refresh storage", () => render(), { variant: "quiet", symbol: "refresh" }),
      environment.items.length ? el("div", {}, ...environment.items.map(item =>
        el("div", { class: "credential-row environment-row" }, el("span", { class: "credential-icon" }, icon("key")),
          el("div", { class: "rule-main" }, el("strong", {}, item.name),
            el("code", { class: "path" }, "$" + item.env_name),
            el("span", { class: "small muted" }, storageExplanation(item))),
          savedBadge(item),
          el("div", { class: "actions" },
            interrupted(item) && storageById.get(item.id)?.state === "available" &&
              button("Recover saved entry", () => recoverEntry(item), { variant: "primary" }),
            item.state !== "revoked" && storageById.get(item.id)?.state === "missing" &&
              button(interrupted(item) ? "Finish saving" : "Re-enter value", () => finishEntry(item), { variant: "secondary" }),
            button("Use in code", () => environmentExample(item), { variant: "quiet", disabled: !storageReady(item) })),
          button("", () => confirmDialog("Remove this credential?", "This removes ADR’s local copy and stops new uses. Any old Keychain original is left intact. A command already running cannot be undone.", async () => {
            await api(`/environment-credentials/${item.id}`, { method: "DELETE" }); notice("Credential removed");
          }, "Remove credential"), { variant: "icon-button", symbol: "trash", "aria-label": `Remove ${item.name}` })))) :
        empty("Keep the value out of the conversation", "Save a credential once. Agents connected through ADR can use its variable name.",
          button("Add your first credential", credentialDialog, { symbol: "plus", disabled: !environment.available }))),
    agentIntegrationCard(),
    environment.recent_runs?.length > 0 && card("Recent credential use",
      "Open a session to see the conversation behind a credential use. Links appear once the session is captured.",
      ...environment.recent_runs.map(item => el("div", { class: "activity-row credential-use-row" }, icon("terminal"),
        el("div", {}, el("strong", {}, item.agent),
          el("p", { class: "small muted" }, item.state === "finished" && item.exit_code !== 0 ?
            `Command exited with status ${item.exit_code ?? "unknown"}` : ({
              checking: "Checking the request", running: "Command in progress", finished: "Command completed",
              failed: "Request not completed", interrupted: "Interrupted by an app restart",
            })[item.state] || "Recorded request"),
          item.session ? el("a", {
            class: "credential-session-link", href: sessionLink(item.session.id), onClick: routeClick,
            "aria-label": `Open session ${item.session_id}: ${item.session.title}`, title: item.session.title,
          }, icon("sessions"), el("span", {}, "Session ", el("code", { translate: "no" }, item.session_id))) :
            el("p", { class: "credential-session-pending" },
              item.session_id && el("span", {}, "Reported session ", el("code", { translate: "no" }, item.session_id), " · "),
              item.session_status === "ambiguous" ? "Session could not be uniquely identified" :
                item.session_status === "not_captured" ? "Session log not captured yet" : "Session not recorded")),
        muted(ago(item.created_at))))),
    executionAccess.length > 0 && el("details", { class: "card" },
      el("summary", {}, "Older manual connections"),
      el("p", { class: "small muted" }, "These keep their original permissions. The ADR plugin does not need them."),
      ...executionAccess.map(connectionRow)),
    el("div", { class: "banner info" }, icon("shield"), el("div", {},
      el("strong", {}, promptAgents.length ? `Prompt checks configured for ${promptAgents.join(", ")}` : "Connect prompt protection"),
      el("p", {}, "Updated Claude Code and Codex integrations can stop recognized credentials before submission. Save the value here, replace it with $VARIABLE, then submit again."),
      el("p", { class: "small muted" }, "Other connected agents can use vault commands, but their prompt-submission paths are not protected by ADR yet."))),
    environment.prompt_blocks.length > 0 && card("Prompts stopped", "Submitted text and credential values are not stored in this activity list.",
      ...environment.prompt_blocks.slice(0, 5).map(item => el("div", { class: "activity-row" }, icon("shield"),
        el("div", {}, el("strong", {}, `${item.harness === "vault" ? "Vault command" : sourceName(item.harness)} · ${JSON.parse(item.kinds).join(", ")}`),
          el("p", {}, JSON.parse(item.aliases).length ? `Use ${JSON.parse(item.aliases).map(name => "$" + name).join(", ")} instead.` : "Save the value in ADR and use its variable name.")),
        muted(ago(item.created_at))))),
    credentialRequests(requests.items),
    credentials.items.length > 0 && card("Existing API-only credentials", "These keep their original permissions. Use a saved environment variable for new credentials.",
      button("Add API credential", serviceCredentialDialog, { variant: "quiet", symbol: "plus", disabled: !credentials.available }),
      credentials.items.length ? el("div", {}, ...credentials.items.map(item => el("div", { class: "credential-row" },
        el("span", { class: "credential-icon" }, icon("key")),
        el("div", { class: "rule-main" }, el("strong", {}, item.name), el("span", { class: "muted" }, item.origin),
          el("p", { class: "small muted" }, storageExplanation(item)),
          el("div", { class: "small muted" }, `${credentialTypeName(item.auth_type)} · ${usedBy(item.id).length ?
            `${usedBy(item.id).length} agent connection${usedBy(item.id).length === 1 ? "" : "s"} allowed` : "No agent access yet"}`)),
        savedBadge(item),
        el("div", { class: "actions" },
          interrupted(item) && storageById.get(item.id)?.state === "available" &&
            button("Recover saved entry", () => recoverEntry(item), { variant: "primary" }),
          item.state !== "revoked" && storageById.get(item.id)?.state === "missing" &&
            button(interrupted(item) ? "Finish saving" : "Re-enter value", () => finishEntry(item), { variant: "secondary" }),
          button("Use with an agent", () => credentialDetailsDialog(item), { variant: "quiet", disabled: !storageReady(item) }),
          button("Allow agent use", () => vaultAccessDialog([item.id]), { disabled: item.state !== "active" })),
        button("", () => confirmDialog("Remove this credential?", "This removes ADR’s local copy and access. Any old Keychain original stays intact. It does not revoke the token at the service provider.", async () => {
          await api(`/credentials/${item.id}`, { method: "DELETE" }); notice("Credential removed");
        }, "Revoke and remove"), { variant: "icon-button", symbol: "trash", "aria-label": `Remove ${item.name}` })))) :
        el("p", { class: "small muted" }, "Optional: use the native HTTPS broker when you only need API reads, not command execution.")),
    access.length > 0 && card("Allowed vault access", "These connections can use selected credentials. New vault connections cannot read your conversations.",
      ...access.map(connectionRow)),
    el("details", { class: "card vault-support" },
      el("summary", {}, "What can I use here?"),
      el("div", { class: "vault-support-body" },
        el("p", {}, el("strong", {}, "How is it stored? "),
          "ADR encrypts values in a private folder on this device. Its local key unlocks them automatically, so there is no recurring Keychain or vault password prompt. This protects stored files from casual disclosure, not from someone who can read your entire ADR profile or run code as your OS account."),
        el("p", {}, el("strong", {}, "Works now: "),
          "Saved text values become environment variables in adr_run_command and its child programs. Use the names your tools expect. API-only credentials remain GET-only."),
        el("p", {}, el("strong", {}, "What about JSON and SSH keys? "),
          "Multiline values work as environment text. Code can read and parse them. ADR does not yet create credential files or provide an SSH signing agent; a tool that needs a file or socket still needs an adapter."),
        el("p", {}, el("strong", {}, "Do I need hooks? "),
          "The same ADR plugin includes vault commands and hooks. Command output is filtered inside ADR. Blocking pasted prompts requires the plugin’s trusted Claude Code or Codex hook. Other agents can use vault commands without prompt blocking.",
          !connected && " ", !connected && link("Set up file protection", "/protection")),
        el("p", {}, el("strong", {}, "What if I paste a secret into a chat? "),
          "Supported prompt hooks check saved values, common key formats, and explicit password assignments. On a match, submission stops and asks you to save the value here. ADR does not automatically import it or resubmit the prompt. Unlabeled, unfamiliar passwords cannot always be recognized."),
        el("p", {}, el("strong", {}, "Can a program read the actual value? "),
          "Yes. Environment credentials are a compatibility feature. Output filtering reduces accidental exposure; it is not a sandbox against a program deliberately writing or transmitting a secret."),
        el("p", {}, el("strong", {}, "Do tool-output checks erase local logs? "),
          "No. An agent may record the original tool output locally even when its model receives a blocked-result message. ADR capture keeps those records unchanged."))),
    findings.length > 0 && card("Credential reads stopped by protection", "These are detections, not imported vault entries. Only types and locations are recorded.",
      ...findings.slice(0, 5).map(item => el("div", { class: "activity-row" }, icon("shield"), el("div", {},
        el("strong", {}, item.credential_kinds.join(", ")), el("p", { class: "small path" }, item.paths.join(", ") || `${item.harness} tool output`)),
      muted(ago(item.timestamp))))),
    recent.length > 0 && card("Recent vault requests", "See when an agent used a credential or a request was declined.",
      ...recent.map(item => el("div", { class: "activity-row" }, icon("key"), el("div", {},
        el("strong", {}, `${item.agent} · ${item.credential_name}`),
        el("p", { class: "path" }, `GET ${item.origin}${item.path}`)),
      tag(({ succeeded: "Completed", running: "In progress", denied: "Declined", failed: "Failed", expired: "Expired", revoked: "Revoked" })[item.state] || item.state,
        item.state === "succeeded" ? "green" : item.state === "failed" ? "red" : "neutral"), muted(ago(item.created_at))))),
  ];
}
async function approvalsPage() {
  const data = await api("/approvals"), pending = data.items.filter(item => item.state === "pending");
  return [
    pageHeading("GUARDRAILS", "Your approval, first", "Review the service, project, and exact request before a credential is used."),
    card("Waiting for you", `${pending.length} pending ${pending.length === 1 ? "request" : "requests"}`,
      pending.length ? el("div", { class: "approval-list" }, ...pending.map(item => el("article", { class: "approval" },
        el("div", { class: "approval-top" }, el("span", { class: "credential-icon" }, icon("key")),
          el("div", {}, el("h3", {}, item.credential_name), muted(`${item.agent} · ${shortPath(item.project)}`)), tag("READ ONLY", "green")),
        el("div", { class: "request-url" }, tag("GET"), el("code", {}, item.origin + item.path)),
        el("div", { class: "approval-bottom" }, muted(`Requested ${ago(item.created_at)} · expires after 5 minutes`),
          el("div", { class: "actions" }, button("Deny", async () => {
            await perform(() => api(`/approvals/${item.id}`, { method: "POST", body: { allow: false } }), "Request denied"); render();
          }), button("Approve once", async () => {
            await perform(() => api(`/approvals/${item.id}`, { method: "POST", body: { allow: true } }), "Approved once"); render();
          }, { variant: "primary", symbol: "check" })))))) :
        empty("Nothing waiting on you", "Requests from connected agents will appear here. Approval applies to one exact GET request.")),
    card("Recent requests", null, data.items.filter(item => item.state !== "pending").length ?
      el("div", {}, ...data.items.filter(item => item.state !== "pending").slice(0, 20).map(item =>
        el("div", { class: "activity-row" }, icon("key"), el("div", {},
          el("strong", {}, `${item.agent} → ${item.credential_name}`),
          el("p", { class: "mono path" }, item.path)),
        tag(item.state, item.state === "succeeded" ? "green" : item.state === "failed" ? "red" : "neutral"),
        muted(ago(item.created_at))))) : el("div", { class: "small-empty" }, "No credential requests yet.")),
  ];
}
async function settingsPage() {
  const [audit, access] = await Promise.all([api("/audit"), api("/access")]);
  const settings = state.status.settings;
  const interval = el("select", { "aria-label": "Capture interval", onChange: async event => {
    const select = event.currentTarget;
    select.disabled = true;
    try {
      await perform(() => api("/settings", { method: "PATCH", body: { interval_seconds: Number(select.value) } }), "Capture interval updated");
    } catch { select.value = state.status.settings.interval_seconds; }
    finally { select.disabled = false; }
  } }, ...state.status.capture_intervals_seconds.map(value =>
    el("option", { value }, `Every ${value / 60} minutes`)));
  interval.value = settings.interval_seconds;
  const days = el("select", { "aria-label": "Capture history window", onChange: async event => {
    await perform(() => api("/settings", { method: "PATCH", body: { history_days: Number(event.target.value) } }), "History window updated");
  } }, ...[1, 7, 14, 30].map(value => el("option", { value }, `Last ${value} ${value === 1 ? "day" : "days"}`)));
  days.value = settings.history_days;
  let login = { available: false };
  try { login = await api("/native/login"); } catch {}
  return [
    pageHeading("PREFERENCES", "Your device. Your settings.", "Nothing here requires a cloud account."),
    deviceAccessCard(access),
    card("Local capture", "ADR reuses the existing Sensor collectors. Captured content is not additionally redacted.",
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Capture interval"), el("p", { class: "small muted" }, "Runs the Sensor over local agent logs, then waits this long before the next pass. Start capture runs the first pass immediately.")), selectControl(interval)),
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "History to look for"), el("p", { class: "small muted" }, "Changing this does not delete history already captured.")), selectControl(days)),
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Last completed capture"), el("p", { class: "small muted" }, time(state.status.collector.last_success))), tag(state.status.collector.phase))),
    card("Menu-bar app", null,
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Start at login"),
        el("p", { class: "small muted" }, login.requires_approval ? "macOS needs approval in Login Items." : "Keep ADR available when you sign in.")),
      button(login.enabled ? "Disable" : "Enable", async () => {
        await perform(() => api("/native/login", { method: "POST", body: { allow: !login.enabled } })); render();
      }, { disabled: !state.status.vault_available })),
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Version"), muted(`ADR Desktop ${state.status.version} · local preview`)), tag("Local storage", "green"))),
    card("Your data", "Session content can contain sensitive prompts and tool results. ADR sends no telemetry to a backend.",
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Storage location"), el("code", { class: "path" }, state.status.state_dir)),
        tag(`${(state.status.storage_bytes / 1024 / 1024).toFixed(1)} MiB`)),
      el("div", { class: "setting-row" }, el("div", {}, el("strong", {}, "Delete collected history"),
        el("p", { class: "small muted" }, "Pauses collection and removes ADR’s session copies. Original agent logs, rules, and Keychain items are not deleted.")),
      button("Delete history", () => confirmDialog("Delete collected session history?", "This removes ADR’s local session history, not your agents’ original files. Collection will remain paused.", async () => {
        await api("/history/delete", { method: "POST" }); notice("Collected history deleted");
      }, "Delete local history"), { variant: "danger", symbol: "trash" }))),
    card("App activity", "Local administrative actions. No credential values are recorded.",
      audit.items.length ? el("div", {}, ...audit.items.slice(0, 20).map(item => el("div", { class: "activity-row" },
        icon("activity"), el("div", {}, el("strong", {}, item.summary), muted(item.kind.replaceAll("_", " "))),
        muted(ago(item.timestamp))))) : el("div", { class: "small-empty" }, "No administrative actions yet.")),
  ];
}
let renderSequence = 0;
function focusedControl(page) {
  const node = document.activeElement;
  if (!node || !page.contains(node)) return null;
  const attribute = ["name", "aria-label", "id"].find(name => node.getAttribute(name));
  if (!attribute) return null;
  return { selector: `${node.tagName.toLowerCase()}[${attribute}="${CSS.escape(node.getAttribute(attribute))}"]`,
    start: node.selectionStart, end: node.selectionEnd };
}
async function restoreDisclosures(page, sequence, keys = null) {
  // Parent disclosures are remembered before their children. Restoring in that
  // order lets a lazy child list exist before a nested disclosure is opened.
  for (const key of keys || pendingView?.disclosures || []) {
    if (sequence !== renderSequence) return;
    const details = page.querySelector(`details[data-view-key="${CSS.escape(key)}"]`);
    if (!details) continue;
    details.open = true;
    if (details.restoreDisclosure) await details.restoreDisclosure();
  }
}
function finishView(page, route, scroll, focus) {
  const destination = pendingView?.route === route ? pendingView : null;
  if (destination) {
    // Run after the winning asynchronous render, not when a link is clicked.
    // Background refreshes must not move a reader back to the beginning.
    const target = page.querySelector(".session-search-error") ||
      (destination.focus && page.querySelector(destination.focus)) || page.querySelector("h1") || page;
    if (!target.matches("input, select, button, a")) target.setAttribute("tabindex", "-1");
    target.focus({ preventScroll: true });
    pendingView = null;
  } else if (focus) {
    const control = page.querySelector(focus.selector);
    control?.focus({ preventScroll: true });
    if (typeof focus.start === "number" && control?.setSelectionRange)
      control.setSelectionRange(focus.start, focus.end);
  }
  const position = destination || scroll;
  window.scrollTo({ left: position.x, top: position.y, behavior: "instant" });
  rememberView();
}
async function render() {
  const sequence = ++renderSequence;
  const route = state.route;
  updateChrome();
  const page = document.querySelector("#page");
  if (!page) return;
  page.setAttribute("aria-busy", "true");
  const status = document.querySelector("#view-status");
  const progress = setTimeout(() => {
    if (sequence === renderSequence && status) status.textContent = pendingView ? "Opening view…" : "Refreshing…";
  }, 250);
  try {
    let content;
    if (route === "/") content = await overview();
    else if (route === "/sessions") content = await sessionsPage();
    else if (route === "/history") {
      history.replaceState({}, "", "/sessions"); state.route = "/sessions";
      if (pendingView) pendingView.route = "/sessions";
      content = await sessionsPage();
    }
    else if (route.startsWith("/sessions/")) content = await sessionPage(route.split("/")[2]);
    else if (route === "/inventory") content = await inventoryPage();
    else if (route === "/protection") content = await protectionPage();
    else if (route === "/threats") content = await threatsPage();
    else if (route === "/reviews") content = await reviewsPage();
    else if (route === "/credentials") content = await credentialsPage();
    else if (route === "/approvals") content = await credentialsPage();
    else content = await settingsPage();
    if (sequence !== renderSequence) return;
    const scroll = { x: window.scrollX, y: window.scrollY }, focus = focusedControl(page);
    const disclosures = !pendingView && (route.startsWith("/sessions") || ["/threats", "/reviews"].includes(route)) ?
      [...page.querySelectorAll("details[data-view-key][open]")].map(node => node.dataset.viewKey) : null;
    page.replaceChildren(...content.filter(Boolean)); document.title = `${page.querySelector("h1")?.textContent || "Insights"} · ADR`;
    await restoreDisclosures(page, sequence, disclosures);
    if (sequence !== renderSequence) return;
    finishView(page, state.route, scroll, focus);
    page.querySelector(".session-detail")?.onReady?.();
  } catch (error) {
    if (sequence === renderSequence) {
      const scroll = { x: window.scrollX, y: window.scrollY };
      page.replaceChildren(empty("This view couldn’t load", error.message,
        button("Try again", () => render(), { symbol: "refresh" })));
      finishView(page, state.route, scroll, null);
    }
  } finally {
    clearTimeout(progress);
    if (sequence === renderSequence) {
      page.setAttribute("aria-busy", "false");
      if (status) status.textContent = "";
    }
  }
}
function disconnected(message) {
  root.replaceChildren(el("main", { class: "reconnect" },
    el("img", { src: "/assets/icon.svg", width: 60, height: 60, alt: "ADR" }),
    el("h1", {}, "Open your local workspace"),
    el("p", {}, "Choose “Open ADR Insights” from the ADR icon in your menu bar."),
    el("p", { class: "muted small" }, message || "A private, one-time link connects this browser to the app."),
    el("div", { class: "local-note" }, icon("lock"), "No account or password required.")));
}
async function boot() {
  try {
    const match = location.hash.match(/^#ticket=(.+)$/);
    if (match) {
      history.replaceState({}, "", location.pathname + location.search);
      const result = await api("/auth/bootstrap", { method: "POST", body: { ticket: decodeURIComponent(match[1]) } });
      state.csrf = result.csrf;
    } else state.csrf = (await api("/auth/session")).csrf;
    await loadStatus(); shell(); await render();
    setInterval(async () => {
      try {
        const old = state.status;
        await loadStatus();
        if (["/", "/approvals", "/credentials", "/protection", "/inventory", "/threats", "/reviews"].includes(state.route) &&
          !document.querySelector("dialog[open]") && !state.threatsPending && !state.reviewPending && (
          old.pending !== state.status.pending ||
          old.prompt_blocks !== state.status.prompt_blocks ||
          old.collector.phase !== state.status.collector.phase ||
          old.collector.inventory_phase !== state.status.collector.inventory_phase ||
          hookConnectionState(old.hooks) !== hookConnectionState(state.status.hooks) ||
          old.protection.latest_intervention_id !== state.status.protection.latest_intervention_id ||
          JSON.stringify(old.threats) !== JSON.stringify(state.status.threats)
          || (state.route === "/reviews" && JSON.stringify(old.reviews) !== JSON.stringify(state.status.reviews))
        )) await render();
      } catch { document.querySelector("#collection-label").textContent = "App connection lost"; }
    }, 4000);
  } catch (error) { disconnected(error.message); }
}
boot();
