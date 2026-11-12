// Guardian SOC dashboard.
// SAFETY NOTE: alert and event data can contain attacker-style text such as "<script>".
// So we NEVER use innerHTML with data. Everything is added with textContent via the h() helper.

const $ = (id) => document.getElementById(id);

// h("div", {class: "x"}, "text", childNode, ...) -> builds a DOM element safely.
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function setChildren(el, ...kids) { el.replaceChildren(...kids.flat().filter(Boolean)); }

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(path + " -> " + res.status);
  return res.json();
}

const state = { tab: "alerts", selected: null, filter: "" };
const STATUS_LABEL = {
  open: "Open", investigating: "Investigating",
  closed_true_positive: "Closed - real attack", closed_false_positive: "Closed - false alarm",
};
const when = (ts) => (ts || "").replace("T", " ").slice(0, 19);

// ---------------------------------------------------------------- tabs
$("tabs").addEventListener("click", (e) => {
  const tab = e.target.dataset.tab;
  if (!tab) return;
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((s) => s.classList.toggle("active", s.id === "tab-" + tab));
  refresh();
});
$("filter").addEventListener("change", (e) => { state.filter = e.target.value; loadAlerts(); });

// ---------------------------------------------------------------- alerts
async function loadAlerts() {
  const alerts = await api("/api/alerts?limit=200" + (state.filter ? "&status=" + state.filter : ""));
  if (!alerts.length) {
    setChildren($("alert-list"), h("p", { class: "muted" }, "No alerts yet. Start Nemesis on the Ubuntu laptop and wait for the first attack."));
    return;
  }
  setChildren($("alert-list"), alerts.map((a) =>
    h("div", { class: `item sev-${a.severity}` + (a.id === state.selected ? " sel" : ""), onclick: () => select(a.id) },
      h("div", { class: "t" }, h("span", { class: `badge ${a.severity}` }, a.severity), " ", a.title),
      h("div", { class: "m" }, `${a.alert_code} | ${a.host} / ${a.user} | ${when(a.first_event_ts)}`,
        h("span", { class: "tag" }, STATUS_LABEL[a.status] || a.status)),
      h("div", { class: "m" }, a.summary))));
}

async function select(id) {
  state.selected = id;
  const a = await api("/api/alerts/" + id);
  const an = a.analysis;
  const list = (items) => h("ul", {}, items.map((x) => h("li", {}, x)));
  const statusBtn = (s, label) => h("button", { class: "btn", onclick: async () => {
    await api(`/api/alerts/${id}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: s }) });
    await loadAlerts(); select(id);
  } }, label);

  setChildren($("detail"),
    h("div", { class: "panel-head" },
      h("h2", {}, h("span", { class: `badge ${a.severity}` }, a.severity), " ", a.title),
      h("span", { class: "muted" }, `${a.alert_code} | risk ${a.risk_score}/100 | ${STATUS_LABEL[a.status] || a.status}`)),
    h("div", { class: "kv" },
      h("div", {}, "What happened"), h("div", {}, an.what_happened),
      h("div", {}, "Affected"), h("div", {}, an.affected),
      h("div", {}, "MITRE ATT&CK"), h("div", {}, an.mitre),
      h("div", {}, "Category"), h("div", {}, a.category)),
    h("h3", {}, "Why is it suspicious?"), h("p", {}, an.why_suspicious),
    a.ai_briefing ? [h("h3", {}, "AI analyst briefing"), h("div", { class: "brief" }, a.ai_briefing)] : null,
    h("h3", {}, "What should you investigate?"), list(an.investigate),
    h("h3", {}, "Recommended response"), list(an.remediate),
    h("h3", {}, `Evidence (${a.events.length} events)`),
    h("div", { class: "table-wrap" }, eventTable(a.events)),
    h("div", { class: "actions" },
      statusBtn("investigating", "Start investigating"),
      statusBtn("closed_true_positive", "Close: real attack"),
      statusBtn("closed_false_positive", "Close: false alarm"),
      statusBtn("open", "Re-open")));
  loadAlerts();
}

function eventTable(events) {
  return h("table", {},
    h("thead", {}, h("tr", {}, ["Time (UTC)", "Source", "Host", "User", "Action", "Details"].map((c) => h("th", {}, c)))),
    h("tbody", {}, events.map((e) => h("tr", {},
      h("td", { class: "mono" }, when(e.ts)), h("td", {}, e.source), h("td", {}, e.host), h("td", {}, e.user),
      h("td", {}, e.action), h("td", { class: "mono" }, JSON.stringify(e.details))))));
}

// ---------------------------------------------------------------- overview
function barRows(obj) {
  const entries = Object.entries(obj);
  if (!entries.length) return h("p", { class: "muted" }, "Nothing yet.");
  const max = Math.max(...entries.map(([, v]) => v));
  return entries.map(([k, v]) => h("div", { class: "row" }, h("span", {}, k),
    h("div", { class: "bar", style: `width:${(v / max) * 100}%` }), h("span", {}, v)));
}

async function loadOverview() {
  const o = await api("/api/overview");
  const card = (n, l) => h("div", { class: "card" }, h("div", { class: "n" }, n), h("div", { class: "l" }, l));
  setChildren($("cards"), card(o.total_alerts, "Total alerts"), card(o.open_alerts, "Open / investigating"),
    card(o.by_severity.CRITICAL, "Critical"), card(o.by_severity.HIGH, "High"),
    card(o.by_severity.MEDIUM, "Medium"), card(o.by_severity.LOW, "Low"), card(o.total_events, "Events received"));
  setChildren($("chart-cat"), barRows(o.by_category));
  setChildren($("chart-tech"), barRows(o.by_technique));
  const t = Object.entries(o.timeline);
  const max = Math.max(1, ...t.map(([, v]) => v));
  setChildren($("chart-time"), t.length ? t.map(([k, v]) =>
    h("div", { class: "col", title: `${v} alerts`, style: `height:${(v / max) * 100}%` }, h("span", {}, k.slice(11) + "h")))
    : h("p", { class: "muted" }, "No alerts yet."));
}

// ---------------------------------------------------------------- activity
async function loadActivity() {
  setChildren($("activity"), eventTable(await api("/api/activity?limit=60")));
}

// ---------------------------------------------------------------- performance
async function loadPerformance() {
  const p = await api("/api/performance");
  const stat = (n, l, cls = "") => h("div", { class: "card" }, h("div", { class: "n " + cls }, n), h("div", { class: "l" }, l));
  setChildren($("perf"), h("div", { class: "cards" },
    stat(p.detection_rate === null ? "-" : p.detection_rate + "%", "Attacks detected"),
    stat(p.attacks_total, "Attacks launched"), stat(p.attacks_detected, "Detected", "yes"),
    stat(p.attacks_missed, "Missed", "no"), stat(p.alerts_true_positive, "Alerts: real"),
    stat(p.alerts_false_positive, "Alerts: false alarms")),
    h("h3", {}, "By category"),
    Object.keys(p.by_category).length ? barRows(Object.fromEntries(
      Object.entries(p.by_category).map(([k, v]) => [`${k} (${v.detected}/${v.total} caught)`, v.detected])))
      : h("p", { class: "muted" }, "No data yet."));
  if (!$("attack-log").classList.contains("hidden")) loadAttackLog();
}

async function loadAttackLog() {
  const log = await api("/api/attack-log");
  setChildren($("attack-log"), h("table", {},
    h("thead", {}, h("tr", {}, ["Started (UTC)", "Real attack?", "Scenario", "Category", "MITRE", "Diff.", "Planner", "Caught?", "Alerts", "Why Nemesis chose it"].map((c) => h("th", {}, c)))),
    h("tbody", {}, log.map((t) => h("tr", {},
      h("td", { class: "mono" }, when(t.started_at)), h("td", {}, t.is_attack ? "yes" : "decoy"), h("td", {}, t.name),
      h("td", {}, t.category), h("td", {}, t.technique_id || "-"), h("td", {}, t.difficulty), h("td", {}, t.planner || "-"),
      h("td", { class: t.detected ? "yes" : "no" }, t.detected ? "yes" : "NO"), h("td", {}, (t.alerts || []).join(", ")),
      h("td", {}, t.reasoning || ""))))));
}
$("reveal-btn").addEventListener("click", () => { $("attack-log").classList.remove("hidden"); loadAttackLog(); });

// ---------------------------------------------------------------- refresh loop
async function refresh() {
  try {
    if (state.tab === "alerts") await loadAlerts();
    if (state.tab === "overview") await loadOverview();
    if (state.tab === "activity") await loadActivity();
    if (state.tab === "performance") await loadPerformance();
    $("status").textContent = "live - updated " + new Date().toLocaleTimeString();
    document.querySelector(".dot").classList.remove("off");
  } catch (err) {
    $("status").textContent = "cannot reach Guardian";
    document.querySelector(".dot").classList.add("off");
  }
}
refresh();
setInterval(refresh, 4000);
