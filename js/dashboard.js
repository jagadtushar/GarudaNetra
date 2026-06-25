/* ===========================================================
   dashboard.js — render stats, donut, activity bars, recent list
   =========================================================== */
const Dashboard = (() => {
  const C = 2 * Math.PI * 15.915; // donut circumference (r=15.915 → 100)

  function render() {
    const list = Store.load();
    const counts = { safe: 0, suspicious: 0, dangerous: 0 };
    list.forEach((r) => { counts[r.verdict] = (counts[r.verdict] || 0) + 1; });
    const total = list.length;

    num('statTotal', total);
    num('statSafe', counts.safe);
    num('statSus', counts.suspicious);
    num('statDanger', counts.dangerous);
    set('legSafe', counts.safe);
    set('legSus', counts.suspicious);
    set('legDanger', counts.dangerous);

    renderDonut(counts, total);
  }

  function set(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
  function num(id, v) {
    const el = document.getElementById(id);
    if (!el) return;
    if (window.Effects && Effects.countUp) Effects.countUp(el, v);
    else el.textContent = v;
  }

  function renderDonut(counts, total) {
    const safePct = total ? (counts.safe / total) * 100 : 0;
    const susPct = total ? (counts.suspicious / total) * 100 : 0;
    const dangPct = total ? (counts.dangerous / total) * 100 : 0;

    const seg = (id, pct, offset) => {
      const el = document.getElementById(id);
      const len = (pct / 100) * C;
      el.setAttribute('stroke-dasharray', `${len} ${C - len}`);
      el.setAttribute('stroke-dashoffset', String((-offset / 100) * C));
    };
    seg('segSafe', safePct, 0);
    seg('segSus', susPct, safePct);
    seg('segDanger', dangPct, safePct + susPct);

    set('donutPct', Math.round(safePct) + '%');
  }

  function timeAgo(ts) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  return { render, timeAgo, esc };
})();
