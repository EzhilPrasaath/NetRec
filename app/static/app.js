"use strict";
const root = document.getElementById("app");
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
let poll = null, user = null;

// All DOM is built with textContent-safe helpers. Never innerHTML: scanned hosts control banner text.
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
};
const svg = (tag, props = {}, ...kids) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(props)) n.setAttribute(k, v);
  kids.forEach(c => n.append(c));
  return n;
};
async function api(path, method = "GET", body) {
  const r = await fetch("/api" + path, {
    method, credentials: "same-origin", headers: { "Content-Type": "application/json" },
    body: method === "GET" ? undefined : JSON.stringify(body || {}),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(d.error || "Request failed"), { status: r.status });
  return d;
}
const when = s => (s ? new Date(s).toLocaleString() : "-");
const chip = s => el("span", { class: "chip " + String(s).toLowerCase() }, s);

/* ---------- auth ---------- */
function showAuth(register = false) {
  stopPoll();
  const err = el("div", { class: "err", role: "alert" });
  const u = el("input", { placeholder: "Username", autocomplete: "username", maxlength: 32, "aria-label": "Username" });
  const p = el("input", { type: "password", placeholder: register ? "Password (8+ characters)" : "Password",
    autocomplete: register ? "new-password" : "current-password", "aria-label": "Password" });
  const go = async () => {
    err.textContent = "";
    try { user = (await api(register ? "/register" : "/login", "POST", { username: u.value, password: p.value })).username; showApp(); }
    catch (e) { err.textContent = e.message; }
  };
  p.addEventListener("keydown", e => e.key === "Enter" && go());
  root.replaceChildren(el("div", { class: "card auth" },
    el("h1", {}, "Net", el("span", {}, "Rec")),
    el("p", { class: "muted" }, register ? "Create an account to run scans." : "Sign in to run scans."),
    u, p, err,
    el("button", { class: "btn", onclick: go }, register ? "Create account" : "Sign in"),
    el("a", { href: "#", onclick: e => { e.preventDefault(); showAuth(!register); } },
      register ? "Already registered? Sign in" : "New here? Create an account")));
}

/* ---------- app shell ---------- */
function showApp() {
  const out = el("div"), prog = el("div"), hist = el("div");
  root.replaceChildren(
    el("header", {}, el("div", { class: "brand" }, "Net", el("span", {}, "Rec")),
      el("div", { class: "row" }, el("span", {}, user),
        el("button", { onclick: async () => { await api("/logout", "POST"); showAuth(); } }, "Sign out"))),
    el("main", {}, scanForm(prog, out, hist), prog, out, hist));
  loadHistory(hist, prog, out);
}

function scanForm(prog, out, hist) {
  const MIN = { fast: 5, moderate: 15, deep: 45 };
  const target = el("input", { placeholder: "192.168.1.0/24, 10.0.0.5 or scanme.nmap.org", maxlength: 100, "aria-label": "Target" });
  const profile = el("select", {}, el("option", { value: "fast" }, "Fast: top 100 ports, light fingerprinting"),
    el("option", { value: "moderate", selected: true }, "Moderate: top 1000 ports, OS + versions"),
    el("option", { value: "deep" }, "Deep: all 65535 ports, full version probing"));
  const mins = el("input", { type: "number", min: 1, max: 60, value: MIN.moderate });
  const ports = el("input", { placeholder: "Profile default. Or 22,80,443 / 1-1024 / all" });
  const up = el("input", { type: "checkbox" }), auth = el("input", { type: "checkbox" });
  const err = el("div", { class: "err", role: "alert" });
  const btn = el("button", { class: "btn" }, "Start scan");
  profile.addEventListener("change", () => { mins.value = MIN[profile.value]; });
  btn.addEventListener("click", async () => {
    err.textContent = ""; btn.disabled = true;
    try {
      const s = await api("/scans", "POST", { target: target.value, profile: profile.value, ports: ports.value,
        timeout_min: Number(mins.value), assume_up: up.checked, authorized: auth.checked });
      out.replaceChildren(); track(s.id, prog, out, hist);
    } catch (e) { err.textContent = e.message; if (e.status === 401) showAuth(); }
    btn.disabled = false;
  });
  return el("div", { class: "card" }, el("h2", {}, "New scan"),
    el("div", { class: "form-grid" },
      el("label", { class: "span2" }, "Target", target),
      el("label", {}, "Profile", profile),
      el("label", {}, "Time limit (minutes)", mins),
      el("label", { class: "span2" }, "Ports", ports)),
    el("label", { class: "check" }, up, "Treat hosts as online (skip ping). Use for internet targets that block ICMP."),
    el("label", { class: "check" }, auth, "I own this target or have written permission to scan it."),
    el("div", { class: "row" }, err, btn));
}

/* ---------- progress ---------- */
function stopPoll() { if (poll) clearInterval(poll); poll = null; }
function track(id, prog, out, hist) {
  stopPoll();
  const fill = el("div"), phase = el("b", {}, "Queued"), pct = el("span", {}, "0%");
  const cancel = el("button", { class: "btn ghost", onclick: () => api(`/scans/${id}/cancel`, "POST").catch(() => {}) }, "Cancel");
  prog.replaceChildren(el("div", { class: "card" },
    el("div", { class: "row" }, el("div", {}, "Scanning: ", phase), pct),
    el("div", { class: "bar", role: "progressbar", "aria-label": "Scan progress" }, fill), cancel));
  const tick = async () => {
    let s;
    try { s = await api(`/scans/${id}`); } catch { return; }
    fill.style.width = s.progress + "%"; pct.textContent = s.progress + "%"; phase.textContent = s.phase;
    if (["completed", "failed", "cancelled"].includes(s.status)) {
      stopPoll(); prog.replaceChildren();
      if (s.status === "completed") renderResults(s, out);
      else out.replaceChildren(el("div", { class: "card" }, el("h2", {}, s.status === "failed" ? "Scan failed" : "Scan cancelled"), el("p", { class: "err" }, s.error || "")));
      loadHistory(hist, prog, out);
    }
  };
  tick(); poll = setInterval(tick, 1500);
}

async function loadHistory(hist, prog, out) {
  let rows = [];
  try { rows = await api("/scans"); } catch { return; }
  hist.replaceChildren(el("div", { class: "card" }, el("h2", {}, "Scan history"),
    rows.length ? el("table", {}, el("tr", {}, ["Target", "Profile", "Status", "Started"].map(h => el("th", {}, h))),
      rows.map(s => el("tr", { class: "click", tabindex: 0, onclick: async () => {
        stopPoll(); prog.replaceChildren(); out.replaceChildren();
        if (["queued", "running"].includes(s.status)) return track(s.id, prog, out, hist);
        const full = await api(`/scans/${s.id}`);
        full.status === "completed" ? renderResults(full, out)
          : out.replaceChildren(el("div", { class: "card" }, el("h2", {}, "Scan " + full.status), el("p", { class: "err" }, full.error || "")));
      } }, el("td", {}, s.target), el("td", {}, s.profile), el("td", {}, s.status), el("td", {}, when(s.started_at || s.created_at)))))
      : el("p", { class: "muted" }, "No scans yet. Start one above.")));
}

/* ---------- results + infographics ---------- */
const pdfIcon = () => svg("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" },
  svg("path", { d: "M6 2h9l5 5v15H6z" }), svg("path", { d: "M14 2v6h6M12 11v6M9 14l3 3 3-3" }));

function donut(sev) {
  const total = SEV.reduce((a, k) => a + (sev[k] || 0), 0), s = svg("svg", { viewBox: "0 0 42 42", class: "donut", role: "img", "aria-label": "Findings by severity" });
  s.append(svg("circle", { cx: 21, cy: 21, r: 15.9155, fill: "none", stroke: "#e3e8ed", "stroke-width": 6 }));
  let acc = 0;
  for (const k of SEV) {
    const v = sev[k] || 0; if (!v) continue;
    const p = v / total * 100;
    s.append(svg("circle", { cx: 21, cy: 21, r: 15.9155, fill: "none", class: "seg-" + k.toLowerCase(), "stroke-width": 6,
      "stroke-dasharray": `${p} ${100 - p}`, "stroke-dashoffset": 25 - acc }));
    acc += p;
  }
  const t = svg("text", { x: 21, y: 23, "text-anchor": "middle", class: "donut-n" }); t.textContent = total; s.append(t);
  return el("div", { class: "donut-wrap" }, s, el("div", { class: "legend" },
    SEV.map(k => el("div", {}, el("span", { class: "dot " + k.toLowerCase() }), `${k[0]}${k.slice(1).toLowerCase()}: ${sev[k] || 0}`))));
}
function bars(title, items) {
  const max = Math.max(1, ...items.map(i => i.count));
  const body = items.length ? items.map(i => {
    const f = el("div", { class: "fill" }); f.style.width = (i.count / max * 100) + "%";
    return el("div", { class: "hbar" }, el("span", { class: "lab", title: i.label }, i.label), el("div", { class: "track" }, f), el("span", {}, i.count));
  }) : [el("p", { class: "muted" }, "No data")];
  return el("div", { class: "chart" }, el("h3", {}, title), body);
}

function renderResults(scan, out) {
  const r = scan.result, sm = r.summary, id = scan.id;
  const notes = [];
  if (r.stats.timed_out) notes.push("Time limit reached. Results may be incomplete.");
  if (sm.cve_partial) notes.push("CVE lookup budget reached. Some services were not checked. Add an NVD API key to speed this up.");
  if (sm.possible_cves) notes.push(`${sm.possible_cves} low-confidence keyword matches are listed as "possible" and excluded from the counts.`);
  if (r.hosts.some(h => !h.ports.length)) notes.unshift("Some hosts returned no open ports. If you expect services there, the scanner may not be able to reach them (separate Docker networks are isolated) or a firewall is dropping probes. Zero findings here does not mean the host is clean.");
  notes.push("CVEs are inferred from version banners. Treat them as potential exposure, not confirmed vulnerabilities.");
  out.replaceChildren(
    el("div", { class: "card" },
      el("div", { class: "row" },
        el("div", {}, el("h2", {}, "Results: " + scan.target), el("span", { class: "muted" }, `${scan.profile} scan, finished ${when(scan.finished_at)}`)),
        el("a", { class: "icon-btn", href: `/api/scans/${id}/report.pdf`, title: "Download PDF report", "aria-label": "Download PDF report" }, pdfIcon(), "PDF report")),
      el("div", { class: "tiles gap-top" },
        [["Hosts up", sm.hosts_up], ["Open ports", sm.open_ports], ["CVE findings", sm.cve_findings],
         ["Critical + High", sm.severity.CRITICAL + sm.severity.HIGH, true], ["Known exploited", sm.kev, true]]
          .map(([l, v, bad]) => el("div", { class: "tile" + (bad && v ? " bad" : "") }, el("b", {}, v), el("span", {}, l))))),
    el("div", { class: "card charts" }, el("div", { class: "chart" }, el("h3", {}, "Findings by severity"), donut(sm.severity)),
      bars("Most common open ports", sm.top_ports), bars("Operating systems", sm.os)),
    el("div", { class: "card" }, notes.map(n => el("p", { class: "notice" }, n)), el("h2", {}, "Hosts"), r.hosts.map(hostCard)));
}

function hostCard(h) {
  const cves = h.ports.flatMap(p => p.cves.map(c => ({ ...c, port: `${p.port}/${p.proto}`, low: p.cve_confidence === "low" })))
    .sort((a, b) => (b.score || 0) - (a.score || 0));
  const top = SEV.find(k => cves.some(c => !c.low && c.severity === k));
  return el("details", { class: "host" },
    el("summary", {}, el("b", {}, h.ip), h.hostname && el("span", {}, h.hostname), el("span", { class: "muted" }, h.os || "OS unknown"),
      el("span", {}, `${h.ports.length} open`), chip(top ? top : "none"),
      !h.ports.length && el("span", { class: "warn" }, h.reason === "user-set" ? "assumed up, nothing answered" : "up, but no open ports found")),
    el("div", { class: "host-body" },
      el("p", { class: "muted" }, `MAC: ${h.mac || "-"} ${h.vendor || ""} | closed/filtered: ${h.not_open}`),
      h.ports.length ? el("table", {}, el("tr", {}, ["Port", "Service", "Product / version", "CVEs"].map(x => el("th", {}, x))),
        h.ports.map(p => el("tr", {}, el("td", {}, `${p.port}/${p.proto}`), el("td", {}, p.service || "-"),
          el("td", {}, [p.product, p.version, p.extra].filter(Boolean).join(" ") || "-"), el("td", {}, p.cves.length ? p.cve_total : 0)))) : el("p", {}, "No open ports found."),
      cves.length ? el("table", {}, el("tr", {}, ["CVE", "CVSS", "Severity", "Port", "Summary"].map(x => el("th", {}, x))),
        cves.slice(0, 60).map(c => el("tr", {},
          el("td", {}, /^CVE-\d{4}-\d+$/.test(c.id) ? el("a", { href: "https://nvd.nist.gov/vuln/detail/" + c.id, target: "_blank", rel: "noopener noreferrer" }, c.id) : c.id,
            c.low ? " (possible)" : "", c.kev ? " [KEV]" : ""),
          el("td", {}, c.score ?? "-"), el("td", {}, chip(c.severity)), el("td", {}, c.port), el("td", {}, c.summary.slice(0, 180))))) : null));
}

(async () => { try { user = (await api("/me")).username; showApp(); } catch { showAuth(); } })();
