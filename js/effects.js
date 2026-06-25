/* ===========================================================
   effects.js — cyber background particle network + scroll reveal
   Purely decorative; degrades gracefully and respects reduced-motion.
   =========================================================== */
const Effects = (() => {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- Particle network on #cyberCanvas ---------- */
  function initParticles() {
    const canvas = document.getElementById('cyberCanvas');
    if (!canvas || reduce) return;
    const ctx = canvas.getContext('2d');
    let w, h, dpr, particles;

    const COUNT = () => Math.min(70, Math.floor(window.innerWidth / 22));
    const LINK = 140;

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.width = window.innerWidth * dpr;
      h = canvas.height = window.innerHeight * dpr;
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
    }

    function seed() {
      particles = Array.from({ length: COUNT() }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25 * dpr,
        vy: (Math.random() - 0.5) * 0.25 * dpr,
        r: (Math.random() * 1.6 + 0.6) * dpr,
      }));
    }

    function accent() {
      // read brand colour from CSS so it tracks theme
      const c = getComputedStyle(document.documentElement).getPropertyValue('--brand').trim() || '#5b8cff';
      return c;
    }

    let color = accent();
    function tick() {
      ctx.clearRect(0, 0, w, h);
      const link = LINK * dpr;
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;

        // node
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = hexA(color, 0.55);
        ctx.fill();

        // links
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j];
          const dx = p.x - q.x, dy = p.y - q.y;
          const dist = Math.hypot(dx, dy);
          if (dist < link) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = hexA(color, 0.12 * (1 - dist / link));
            ctx.lineWidth = dpr * 0.6;
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(tick);
    }

    function hexA(hex, a) {
      const m = hex.replace('#', '');
      const n = m.length === 3 ? m.split('').map((c) => c + c).join('') : m;
      const r = parseInt(n.slice(0, 2), 16), g = parseInt(n.slice(2, 4), 16), b = parseInt(n.slice(4, 6), 16);
      return `rgba(${r},${g},${b},${a})`;
    }

    resize(); seed();
    window.addEventListener('resize', () => { resize(); seed(); });
    // refresh accent if the theme toggles
    new MutationObserver(() => { color = accent(); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    requestAnimationFrame(tick);
  }

  /* ---------- Scroll reveal ---------- */
  function initReveal() {
    const targets = document.querySelectorAll(
      '.feature-card, .stat-card, .flow-node, .step, .home-donut, .about-panel, .hero, .scan-grid > .panel'
    );
    if (reduce || !('IntersectionObserver' in window)) return;
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e, i) => {
        if (e.isIntersecting) {
          e.target.style.transitionDelay = Math.min(i * 40, 240) + 'ms';
          e.target.classList.add('in');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12 });
    targets.forEach((t) => { t.classList.add('reveal'); io.observe(t); });
  }

  /* ---------- Count-up animation for numbers ---------- */
  function countUp(el, to) {
    to = Number(to) || 0;
    if (reduce) { el.textContent = to; return; }
    const from = Number(el.textContent) || 0;
    if (from === to) return;
    const dur = 600, start = performance.now();
    function step(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function init() {
    initParticles();
    // reveal runs after first paint so initial view animates in
    requestAnimationFrame(initReveal);
  }

  return { init, countUp };
})();

document.addEventListener('DOMContentLoaded', Effects.init);
