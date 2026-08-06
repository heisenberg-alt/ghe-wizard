/* ============================================================================
   ghe-wizard dashboard — application logic
   ========================================================================== */
(() => {
  "use strict";

  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };

  const ICON = { pass: "✓", fail: "✕", warn: "!", manual: "✎", error: "⚡", skipped: "–" };
  const STATUS_ORDER = ["fail", "warn", "manual", "error", "pass", "skipped"];

  const state = {
    scorecard: null,
    filter: "all",
    query: "",
    remediableFailing: [],
  };

  /* ------------------------------ helpers -------------------------------- */
  function body(extra) {
    return Object.assign({
      enterprise: $("#enterprise").value.trim(),
      token: $("#token").value.trim(),
    }, extra || {});
  }

  async function api(path, payload) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    let data;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok || (data && data.error)) {
      throw new Error((data && data.error) || `Request failed (${res.status})`);
    }
    return data;
  }

  function setConn(kind, text) {
    const dot = $("#connDot");
    dot.className = "dot" + (kind ? " " + kind : "");
    $("#connText").textContent = text;
  }

  function busy(on) {
    $("#assessBtn").disabled = on;
    $("#previewBtn").disabled = on;
    $("#applyBtn").disabled = on;
  }

  function grade(score) {
    if (score >= 90) return { g: "A", c: "var(--pass)", bg: "var(--pass-soft)" };
    if (score >= 75) return { g: "B", c: "var(--pass)", bg: "var(--pass-soft)" };
    if (score >= 60) return { g: "C", c: "var(--warn)", bg: "var(--warn-soft)" };
    if (score >= 40) return { g: "D", c: "var(--error)", bg: "var(--error-soft)" };
    return { g: "F", c: "var(--fail)", bg: "var(--fail-soft)" };
  }

  const DOT = {
    pass: "var(--pass)", fail: "var(--fail)", warn: "var(--warn)",
    manual: "var(--manual)", error: "var(--error)", skipped: "var(--fg-subtle)",
  };

  /* -------------------------------- toast -------------------------------- */
  function toast(kind, title, msg, ms = 4200) {
    const t = el("div", "toast " + kind);
    const check = kind === "ok" ? "M20 6 9 17l-5-5" : kind === "err" ? "M18 6 6 18M6 6l12 12" : "M12 16v-4M12 8h.01";
    t.innerHTML =
      `<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" opacity="${kind==='ok'?0:.001}"/><path d="${check}"/></svg>
       <div><div class="tt">${title}</div>${msg ? `<div class="tm">${msg}</div>` : ""}</div>`;
    $("#toasts").appendChild(t);
    setTimeout(() => { t.style.transition = "opacity .3s, transform .3s"; t.style.opacity = "0"; t.style.transform = "translateY(6px)"; setTimeout(() => t.remove(), 300); }, ms);
  }

  /* ------------------------------- assess -------------------------------- */
  async function runAssess() {
    if (!$("#enterprise").value.trim()) { toast("err", "Enterprise required", "Enter your enterprise slug first."); $("#enterprise").focus(); return; }
    busy(true); setConn("busy", "Assessing…");
    $("#emptyCard").style.display = "none";
    $("#resultRoot").style.display = "none";
    $("#loadingCard").style.display = "";
    try {
      const sc = await api("/api/assess", body());
      state.scorecard = sc;
      render(sc);
      loadTrends();
      $("#loadingCard").style.display = "none";
      $("#resultRoot").style.display = "";
      setConn("ok", `Assessed · score ${sc.summary.score}/100`);
      toast("ok", "Assessment complete", `Score ${sc.summary.score}/100 across ${sc.summary.total} checks.`);
    } catch (e) {
      $("#loadingCard").style.display = "none";
      $("#emptyCard").style.display = "";
      setConn("err", "Failed");
      toast("err", "Assessment failed", e.message, 7000);
    } finally {
      busy(false);
    }
  }

  /* ------------------------------- trends -------------------------------- */
  async function loadTrends() {
    try {
      const runs = await api2GET("/api/history?enterprise=" + encodeURIComponent($("#enterprise").value.trim()));
      if (!Array.isArray(runs) || runs.length < 2) { $("#trendsCard").style.display = "none"; return; }
      renderTrends(runs);
      $("#trendsCard").style.display = "";
    } catch { $("#trendsCard").style.display = "none"; }
  }

  async function api2GET(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error("history " + r.status);
    return r.json();
  }

  function renderTrends(runs) {
    // runs are newest-first; reverse for chronological plotting.
    const series = runs.slice().reverse();
    const scores = series.map(r => r.score);
    const w = 640, h = 90, pad = 8;
    const max = 100, min = 0;
    const n = scores.length;
    const x = i => pad + (w - 2 * pad) * (n === 1 ? 0 : i / (n - 1));
    const y = v => pad + (h - 2 * pad) * (1 - (v - min) / (max - min));
    const pts = scores.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `${pad},${h - pad} ` + pts + ` ${x(n - 1)},${h - pad}`;
    const last = scores[n - 1], prev = scores[n - 2];
    const delta = last - prev;
    const col = last >= 75 ? "var(--pass)" : last >= 40 ? "var(--warn)" : "var(--fail)";

    $("#trendChart").innerHTML =
      `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none">
         <polygon points="${area}" fill="${col}" fill-opacity="0.10"/>
         <polyline points="${pts}" fill="none" stroke="${col}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
         ${scores.map((v, i) => `<circle cx="${x(i).toFixed(1)}" cy="${y(v).toFixed(1)}" r="${i === n - 1 ? 3.5 : 2}" fill="${col}"/>`).join("")}
       </svg>`;

    const sign = delta > 0 ? "▲ +" : delta < 0 ? "▼ " : "▬ ";
    const dcol = delta > 0 ? "var(--pass)" : delta < 0 ? "var(--fail)" : "var(--fg-muted)";
    $("#trendDelta").innerHTML = `<span style="color:${dcol};font-weight:600">${sign}${Math.abs(delta)}</span> since last scan`;
    $("#trendMeta").textContent = `${n} recorded scans · latest ${last}/100 · range ${Math.min(...scores)}–${Math.max(...scores)}`;
  }

  /* ------------------------------- render -------------------------------- */
  function render(sc) {
    // meta
    const dt = new Date(sc.generated_at);
    $("#scMeta").textContent = `${sc.enterprise} · ${dt.toLocaleString()}`;

    // gauge
    const C = 2 * Math.PI * 66;
    const prog = $("#gaugeProg");
    prog.style.strokeDasharray = C.toFixed(1);
    requestAnimationFrame(() => { prog.style.strokeDashoffset = (C * (1 - sc.summary.score / 100)).toFixed(1); });
    const gr = grade(sc.summary.score);
    prog.style.stroke = gr.c;
    animateNum($("#scoreNum"), sc.summary.score);
    const gb = $("#gradeBadge");
    gb.textContent = "Grade " + gr.g; gb.style.color = gr.c; gb.style.background = gr.bg;

    // stat cards
    const counts = sc.summary.counts || {};
    const stats = $("#stats"); stats.innerHTML = "";
    [["fail","Failing"],["warn","Warnings"],["manual","Manual"],["error","Errors"],["pass","Passing"]].forEach(([k, label]) => {
      const c = el("div", "stat" + (state.filter === k ? " active" : ""));
      c.dataset.f = k;
      c.innerHTML = `<div class="n" style="color:${DOT[k]}">${counts[k] || 0}</div>
        <div class="k"><span class="dotk" style="background:${DOT[k]}"></span>${label}</div>`;
      c.onclick = () => setFilter(state.filter === k ? "all" : k);
      stats.appendChild(c);
    });

    // domains
    const byDom = {};
    sc.results.forEach(r => { (byDom[r.meta.domain] = byDom[r.meta.domain] || []).push(r); });
    const doms = $("#domains"); doms.innerHTML = "";
    Object.keys(byDom).sort().forEach(dom => {
      const rs = byDom[dom];
      const p = rs.filter(r => r.status === "pass").length;
      const w = rs.filter(r => r.status === "warn").length;
      const f = rs.filter(r => r.status === "fail").length;
      const scored = p + w + f;
      const pct = scored ? Math.round((p + 0.5 * w) / scored * 100) : null;
      const row = el("div", "dom-row");
      row.innerHTML = `<div class="name">${dom}</div>
        <div class="bar">
          <i class="p" style="width:${scored?p/scored*100:0}%"></i>
          <i class="w" style="width:${scored?w/scored*100:0}%"></i>
          <i class="f" style="width:${scored?f/scored*100:0}%"></i>
        </div>
        <div class="pct">${pct == null ? "—" : pct + "%"}</div>`;
      doms.appendChild(row);
    });

    // remediable failing set for apply/preview
    state.remediableFailing = sc.results.filter(r => r.meta.remediable && (r.status === "fail" || r.status === "warn")).map(r => r.meta.id);

    renderRows();
  }

  function animateNum(node, to) {
    const from = 0, dur = 800, t0 = performance.now();
    function step(t) {
      const k = Math.min(1, (t - t0) / dur);
      node.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3)));
      if (k < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function setFilter(f) {
    state.filter = f;
    $$("#statusSeg button").forEach(b => b.classList.toggle("on", b.dataset.f === f));
    $$("#stats .stat").forEach(s => s.classList.toggle("active", s.dataset.f === f && f !== "all"));
    renderRows();
  }

  function renderRows() {
    const sc = state.scorecard; if (!sc) return;
    const q = state.query.toLowerCase();
    let items = sc.results.filter(r => {
      if (state.filter !== "all" && r.status !== state.filter) return false;
      if (!q) return true;
      return (r.meta.id + " " + r.meta.title + " " + (r.detail || "") + " " + r.meta.domain).toLowerCase().includes(q);
    });

    const root = $("#rows"); root.innerHTML = "";
    if (!items.length) {
      root.appendChild(el("div", "", `<div style="padding:34px;text-align:center;color:var(--fg-muted)">No findings match your filters.</div>`));
      return;
    }

    // group by domain, ordered
    const byDom = {};
    items.forEach(r => { (byDom[r.meta.domain] = byDom[r.meta.domain] || []).push(r); });
    Object.keys(byDom).sort().forEach(dom => {
      const list = byDom[dom].sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.meta.id.localeCompare(b.meta.id));
      const head = el("div", "rgroup-head");
      head.innerHTML = `${dom} <span class="count">· ${list.length}</span>`;
      root.appendChild(head);
      list.forEach(r => root.appendChild(rowNode(r)));
    });
  }

  function rowNode(r) {
    const row = el("div", "row");
    const remBadge = r.meta.remediable ? `<span class="rem-badge">auto-fix</span>` : "";
    const fix = r.remediation ? `<div class="fix"><b>Fix</b><span>${escapeHtml(r.remediation)}</span></div>` : "";
    const ev = r.evidence ? `<div class="evidence">${escapeHtml(typeof r.evidence === "string" ? r.evidence : JSON.stringify(r.evidence, null, 2))}</div>` : "";
    const canFix = r.meta.remediable && (r.status === "fail" || r.status === "warn");
    const actions = `<div class="expand-actions">
        <a class="mini-btn" href="${r.meta.docs_url}" target="_blank" rel="noopener">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14 21 3"/></svg>
          Docs
        </a>
        ${canFix ? `<button class="mini-btn primary" data-fix="${r.meta.id}">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 0 0 5.4-5.4l-2.1 2.1-2.1-.6-.6-2.1z"/></svg>
          Remediate this
        </button>` : ""}
      </div>`;
    row.innerHTML = `
      <div class="rid">${r.meta.id}<span class="sev ${r.meta.severity}">${r.meta.severity}</span></div>
      <div>
        <div class="title">${escapeHtml(r.meta.title)} ${remBadge}</div>
        <div class="detail">${escapeHtml(r.detail || r.meta.rationale || "")}</div>
        <div class="expand">
          <div class="meta-line">${escapeHtml(r.meta.rationale || "")}</div>
          ${fix}${ev}${actions}
        </div>
      </div>
      <div class="rstatus"><span class="chip ${r.status}"><span class="cd"></span>${r.status}</span></div>`;
    row.addEventListener("click", (e) => {
      if (e.target.closest("a,button")) return;
      row.classList.toggle("open");
    });
    const fb = row.querySelector("[data-fix]");
    if (fb) fb.addEventListener("click", (e) => { e.stopPropagation(); openRemediation([fb.dataset.fix], r.meta.title); });
    return row;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  /* --------------------------- remediation flow -------------------------- */
  function openRemediation(ruleIds, label) {
    if (!ruleIds || !ruleIds.length) {
      toast("info", "Nothing to remediate", "No failing auto-fixable checks found.");
      return;
    }
    $("#modalTitle").textContent = label ? `Remediate: ${label}` : `Remediate ${ruleIds.length} finding${ruleIds.length > 1 ? "s" : ""}`;
    $("#modalBody").innerHTML = `
      <div class="plan-note">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
        Preview the exact changes with a dry-run first. Applying will modify your enterprise configuration.
      </div>
      <div id="planOut"><div class="skeleton" style="height:44px;margin-bottom:8px"></div><div class="skeleton" style="height:44px"></div></div>`;
    $("#modalFoot").innerHTML = "";
    const foot = $("#modalFoot");
    const cancel = el("button", "btn btn-ghost", "Close"); cancel.onclick = closeModal;
    const applyBtn = el("button", "btn btn-danger", "Apply changes"); applyBtn.disabled = true;
    foot.append(cancel, applyBtn);
    showModal();

    // auto dry-run
    api("/api/apply", body({ dry_run: true, rules: ruleIds }))
      .then(res => {
        renderPlan(res);
        const hasChanges = res.some(x => (x.changes || []).length);
        applyBtn.disabled = !hasChanges;
        applyBtn.onclick = () => doApply(ruleIds, applyBtn);
      })
      .catch(e => { $("#planOut").innerHTML = `<div class="change err"><span class="badge">error</span>${escapeHtml(e.message)}</div>`; });
  }

  function renderPlan(res) {
    const out = $("#planOut"); out.innerHTML = "";
    let any = false;
    res.forEach(x => {
      const head = el("div", "", `<div style="font-family:var(--mono);font-size:12px;color:var(--fg-muted);margin:10px 0 6px">${x.rule_id} ${x.dry_run ? "· dry-run" : "· applied"}</div>`);
      out.appendChild(head);
      (x.changes || []).forEach(c => { any = true; out.appendChild(el("div", "change", `<span class="badge">change</span><span>${escapeHtml(c)}</span>`)); });
      (x.errors || []).forEach(er => out.appendChild(el("div", "change err", `<span class="badge">error</span><span>${escapeHtml(er)}</span>`)));
      if (!(x.changes || []).length && !(x.errors || []).length) out.appendChild(el("div", "change", `<span class="badge">ok</span><span>no changes needed</span>`));
    });
    if (!any) out.appendChild(el("div", "plan-note", "No changes are required for the selected checks."));
  }

  async function doApply(ruleIds, btn) {
    btn.disabled = true; btn.innerHTML = `<svg class="spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.6"/></svg> Applying…`;
    try {
      const res = await api("/api/apply", body({ dry_run: false, rules: ruleIds }));
      renderPlan(res);
      const errs = res.reduce((n, x) => n + (x.errors || []).length, 0);
      const changed = res.reduce((n, x) => n + (x.changes || []).length, 0);
      if (errs) toast("err", "Applied with errors", `${changed} change(s), ${errs} error(s).`, 6000);
      else toast("ok", "Remediation applied", `${changed} change(s) applied. Re-assessing…`);
      closeModal();
      runAssess();
    } catch (e) {
      toast("err", "Apply failed", e.message, 7000);
      btn.disabled = false; btn.textContent = "Apply changes";
    }
  }

  function showModal() { $("#modal").classList.add("show"); }
  function closeModal() { $("#modal").classList.remove("show"); }

  /* ------------------------------- export -------------------------------- */
  function exportJson() {
    if (!state.scorecard) return;
    const blob = new Blob([JSON.stringify(state.scorecard, null, 2)], { type: "application/json" });
    const a = el("a"); a.href = URL.createObjectURL(blob);
    a.download = `ghe-scorecard-${state.scorecard.enterprise}-${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(a.href);
    toast("ok", "Exported", "Scorecard downloaded as JSON.");
  }

  /* -------------------------------- theme -------------------------------- */
  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("ghe.theme", next);
    paintThemeIcon(next);
  }
  function paintThemeIcon(theme) {
    $("#themeIcon").innerHTML = theme === "dark"
      ? `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>`
      : `<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>`;
  }

  /* ------------------------------- wiring -------------------------------- */
  function init() {
    // theme
    const savedTheme = localStorage.getItem("ghe.theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    paintThemeIcon(savedTheme);
    $("#themeBtn").onclick = toggleTheme;

    // remembered slug
    const savedEnt = localStorage.getItem("ghe.enterprise");
    if (savedEnt) { $("#enterprise").value = savedEnt; $("#remember").checked = true; }

    // health / prefill
    fetch("/api/health").then(r => r.json()).then(h => {
      const v = String(h.version || "");
      $("#verPill").textContent = v.startsWith("v") ? v : "v" + v;
      $("#ruleCountTxt").textContent = h.rules;
      if (!$("#enterprise").value && h.default_enterprise) $("#enterprise").value = h.default_enterprise;
      if (h.has_server_token) $("#token").placeholder = "Using server token (override optional)";
      if (h.demo) {
        if (!$("#enterprise").value) $("#enterprise").value = "acme-corp";
        $("#token").placeholder = "Demo mode — no token required";
        setConn("ok", "Demo mode");
      } else {
        setConn("ok", "Ready");
      }
    }).catch(() => setConn("err", "Server unreachable"));

    // buttons
    $("#assessBtn").onclick = runAssess;
    $("#previewBtn").onclick = () => openRemediation(state.remediableFailing, null);
    $("#applyBtn").onclick = () => openRemediation(state.remediableFailing, null);
    $("#exportBtn").onclick = exportJson;
    $("#modalClose").onclick = closeModal;
    $("#modal").addEventListener("click", e => { if (e.target.id === "modal") closeModal(); });
    document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

    // reveal token
    $("#revealBtn").onclick = () => {
      const t = $("#token"); t.type = t.type === "password" ? "text" : "password";
    };

    // remember
    $("#remember").onchange = e => {
      if (e.target.checked) localStorage.setItem("ghe.enterprise", $("#enterprise").value.trim());
      else localStorage.removeItem("ghe.enterprise");
    };
    $("#enterprise").addEventListener("input", () => { if ($("#remember").checked) localStorage.setItem("ghe.enterprise", $("#enterprise").value.trim()); });
    $("#enterprise").addEventListener("keydown", e => { if (e.key === "Enter") runAssess(); });
    $("#token").addEventListener("keydown", e => { if (e.key === "Enter") runAssess(); });

    // filters
    $$("#statusSeg button").forEach(b => b.onclick = () => setFilter(b.dataset.f));
    let deb;
    $("#searchInput").addEventListener("input", e => {
      clearTimeout(deb);
      deb = setTimeout(() => { state.query = e.target.value; renderRows(); }, 140);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
