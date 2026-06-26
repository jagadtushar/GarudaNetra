/* ===========================================================
   report.js — premium cybersecurity threat-intelligence PDF
   Vector charts (risk gauge, classification scale, coverage bar),
   KPI stat cards, color-coded threat indicator cards, security
   recommendations, custom icons and robust pagination — built on jsPDF.
   =========================================================== */
const Report = (() => {
  const C = {
    safe:       [22, 199, 132],
    suspicious: [232, 151, 18],
    dangerous:  [229, 57, 70],
    brand:      [59, 130, 246],
    brand2:     [37, 99, 235],
    navy:       [12, 18, 35],     // dark header band
    navy2:      [22, 30, 52],
    ink:        [17, 24, 39],     // headings
    body:       [55, 65, 81],     // paragraph text
    dim:        [107, 114, 128],
    faint:      [150, 158, 172],
    line:       [226, 232, 240],
    track:      [232, 236, 243],
    panel:      [247, 249, 252],
    white:      [255, 255, 255],
    headSub:    [150, 176, 232],
  };
  const TINT = {
    safe:       [236, 252, 245],
    suspicious: [255, 248, 235],
    dangerous:  [254, 240, 241],
  };

  // Logo as an inlined base64 data URL (js/logo-data.js). jsPDF's addImage is
  // rock-solid with a data URL but unreliable with a raw <img>, and inlining
  // avoids canvas tainting under file://. Falls back to null if not loaded.
  const logoData = (typeof window !== 'undefined' && window.GN_LOGO) || null;

  function fmtDate(ts) {
    const d = new Date(ts || Date.now());
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  }

  /** Stable, human-readable report id: GN-YYYYMMDD-XXXXXX (derived from url + ts). */
  function reportIdFor(result, ts) {
    const d = new Date(ts || Date.now());
    const ymd = '' + d.getFullYear() +
      String(d.getMonth() + 1).padStart(2, '0') +
      String(d.getDate()).padStart(2, '0');
    const str = (result.url || '') + '|' + (ts || 0);
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    const code = h.toString(36).toUpperCase().padStart(6, '0').slice(-6);
    return 'GN-' + ymd + '-' + code;
  }

  function generate(result, ts, recipient) {
    recipient = recipient || {};
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: 'pt', format: 'a4' });
    const W = doc.internal.pageSize.getWidth();   // ~595
    const H = doc.internal.pageSize.getHeight();  // ~842
    const M = 44;
    const CW = W - M * 2;
    let y = 0;

    const tier = result.verdict || 'safe';
    const vColor = C[tier] || C.brand;
    const reportId = reportIdFor(result, ts);
    const signals = result.signals || [];
    const hits = signals.filter((s) => s.hit).sort((a, b) => b.weight - a.weight);
    const clean = signals.filter((s) => !s.hit);
    const whyByLabel = {};
    (result.explanation && result.explanation.threats || []).forEach((t) => { whyByLabel[t.label] = t.why; });

    /* ============================ low-level helpers ============================ */
    const setFill = (c) => doc.setFillColor(c[0], c[1], c[2]);
    const setStroke = (c) => doc.setDrawColor(c[0], c[1], c[2]);
    const setText = (c) => doc.setTextColor(c[0], c[1], c[2]);
    const font = (style, size) => { doc.setFont('helvetica', style); doc.setFontSize(size); };

    function arc(cx, cy, r, startDeg, endDeg, color, width) {
      setStroke(color); doc.setLineWidth(width); doc.setLineCap('round');
      const steps = Math.max(2, Math.round(Math.abs(endDeg - startDeg) / 5));
      let px = null, py = null;
      for (let i = 0; i <= steps; i++) {
        const a = (startDeg + (endDeg - startDeg) * (i / steps)) * Math.PI / 180;
        const x = cx + r * Math.cos(a), yy = cy + r * Math.sin(a);
        if (px !== null) doc.line(px, py, x, yy);
        px = x; py = yy;
      }
      doc.setLineCap('butt');
    }

    function card(x, yy, w, h, opt) {
      opt = opt || {};
      setFill(opt.fill || C.white);
      doc.roundedRect(x, yy, w, h, opt.r != null ? opt.r : 9, opt.r != null ? opt.r : 9, 'F');
      if (opt.border !== false) {
        setStroke(opt.border || C.line); doc.setLineWidth(opt.lw || 0.8);
        doc.roundedRect(x, yy, w, h, opt.r != null ? opt.r : 9, opt.r != null ? opt.r : 9, 'S');
      }
    }

    // Auto-sized pill. Returns its width. align: 'left'|'right' anchors at x.
    function pill(x, yy, text, fg, bg, opt) {
      opt = opt || {};
      const size = opt.size || 8, padX = opt.padX || 8, h = opt.h || 16;
      font(opt.bold ? 'bold' : 'normal', size);
      const w = doc.getTextWidth(text) + padX * 2;
      const xx = opt.align === 'right' ? x - w : x;
      if (bg) { setFill(bg); doc.roundedRect(xx, yy, w, h, h / 2, h / 2, 'F'); }
      if (opt.borderC) { setStroke(opt.borderC); doc.setLineWidth(0.8); doc.roundedRect(xx, yy, w, h, h / 2, h / 2, 'S'); }
      setText(fg);
      doc.text(text, xx + w / 2, yy + h / 2 + size * 0.35, { align: 'center' });
      return w;
    }

    /* ---- vector icons (relative to a size-s box at top-left x,y) ---- */
    function iconCheck(x, yy, s, color) {
      setStroke(color); doc.setLineWidth(s * 0.16); doc.setLineCap('round');
      doc.line(x + s * 0.12, yy + s * 0.55, x + s * 0.4, yy + s * 0.82);
      doc.line(x + s * 0.4, yy + s * 0.82, x + s * 0.9, yy + s * 0.2);
      doc.setLineCap('butt');
    }
    function iconWarn(x, yy, s, color) {
      setFill(color);
      doc.triangle(x + s / 2, yy + s * 0.04, x + s * 0.02, yy + s * 0.96, x + s * 0.98, yy + s * 0.96, 'F');
      setStroke(C.white); doc.setLineWidth(s * 0.1); doc.setLineCap('round');
      doc.line(x + s / 2, yy + s * 0.36, x + s / 2, yy + s * 0.64);
      setFill(C.white); doc.circle(x + s / 2, yy + s * 0.8, s * 0.05, 'F');
      doc.setLineCap('butt');
    }
    function iconShield(x, yy, s, color) {
      setFill(color);
      const cx = x + s / 2;
      doc.triangle(x + s * 0.08, yy + s * 0.18, x + s * 0.92, yy + s * 0.18, cx, yy + s * 0.18, 'F');
      doc.rect(x + s * 0.08, yy + s * 0.12, s * 0.84, s * 0.42, 'F');
      doc.triangle(x + s * 0.08, yy + s * 0.5, x + s * 0.92, yy + s * 0.5, cx, yy + s * 0.98, 'F');
      iconCheck(x + s * 0.2, yy + s * 0.05, s * 0.6, C.white);
    }

    /* ============================ page chrome ============================ */
    function topStrip() {
      setFill(C.navy); doc.rect(0, 0, W, 48, 'F');
      setFill(C.brand); doc.rect(0, 48, W, 2, 'F');
      const hl = !!logoData;
      if (hl) { try { doc.addImage(logoData, 'JPEG', M, 11, 26, 26); } catch (e) {} }
      const tsx = hl ? M + 34 : M;
      font('bold', 12); setText(C.white); doc.text('GarudaNetra', tsx, 29);
      font('normal', 8); setText(C.headSub);
      doc.text('THREAT INTELLIGENCE REPORT', tsx + 90, 29);
      setText([200, 212, 235]); doc.text(reportId, W - M, 29, { align: 'right' });
      y = 76;
    }
    function newPage() { doc.addPage(); topStrip(); }
    function ensure(h) { if (y + h > H - 58) newPage(); }

    function sectionHeading(label, note) {
      ensure(34); y += 12;
      setFill(vColor); doc.roundedRect(M, y - 9, 3.5, 14, 1.5, 1.5, 'F');
      font('bold', 12.5); setText(C.ink); doc.text(label, M + 12, y + 2);
      if (note) { font('normal', 8.5); setText(C.faint); doc.text(note, W - M, y + 1, { align: 'right' }); }
      y += 18;
    }

    /* ============================ HEADER ============================ */
    setFill(C.navy); doc.rect(0, 0, W, 116, 'F');
    setFill(C.navy2); doc.rect(0, 92, W, 24, 'F');
    setFill(vColor); doc.rect(0, 116, W, 3.5, 'F');   // verdict-colored accent underline
    const hasLogo = !!logoData;
    if (hasLogo) { try { doc.addImage(logoData, 'JPEG', M, 24, 50, 50); } catch (e) {} }
    const htx = hasLogo ? M + 64 : M;
    font('bold', 23); setText(C.white); doc.text('GarudaNetra', htx, 48);
    font('normal', 10); setText(C.headSub);
    doc.text('QR & URL THREAT INTELLIGENCE REPORT', htx, 66);
    // classification + report id (top-right)
    pill(W - M, 30, 'CONFIDENTIAL', [210, 220, 245], null, { align: 'right', size: 7.5, bold: true, h: 15, borderC: [70, 90, 150] });
    font('normal', 7.5); setText([120, 138, 188]); doc.text('REPORT ID', W - M, 60, { align: 'right' });
    font('bold', 11); setText([214, 224, 248]); doc.text(reportId, W - M, 74, { align: 'right' });

    /* ============================ META BAND ============================ */
    let by = 116 + 3.5;
    setFill(C.panel); doc.rect(0, by, W, 42, 'F');
    setStroke(C.line); doc.setLineWidth(0.8); doc.line(0, by + 42, W, by + 42);
    const metaCols = [
      ['PREPARED FOR', recipient.name ? recipient.name : '—', C.ink],
      ['SCAN DATE', fmtDate(ts), C.ink],
      ['SCAN SOURCE', String(result.source || 'manual').toUpperCase(), C.ink],
      ['STATUS', tier.toUpperCase(), vColor],
    ];
    const mcW = CW / 4;
    metaCols.forEach((col, i) => {
      const x = M + i * mcW;
      font('bold', 7); setText(C.dim); doc.text(col[0], x, by + 17);
      font('bold', 10.5); setText(col[2]); doc.text(String(col[1]).slice(0, 30), x, by + 32);
    });
    y = by + 42 + 18;

    /* ============================ NON-URL SHORT REPORT ============================ */
    if (result.isUrl === false) {
      sectionHeading('Decoded Content');
      const lines = doc.splitTextToSize(String(result.url || ''), CW - 28);
      const h = Math.max(56, lines.length * 13 + 30);
      card(M, y, CW, h, { fill: C.panel });
      iconShield(M + 14, y + 14, 22, C.safe);
      font('bold', 11); setText(C.ink); doc.text('Non-URL QR payload', M + 46, y + 22);
      font('courier', 10); setText(C.body); doc.text(lines, M + 46, y + 40);
      y += h + 14;
      sectionHeading('Assessment');
      card(M, y, CW, 50, { fill: TINT.safe, border: false });
      font('normal', 10); setText(C.body);
      doc.text(doc.splitTextToSize(result.summary || 'No URL threat analysis applies to this payload.', CW - 28), M + 16, y + 22);
      y += 64;
      drawFooter();
      return finish();
    }

    /* ============================ EXECUTIVE SUMMARY (hero) ============================ */
    sectionHeading('Executive Summary');
    const heroH = 128;
    card(M, y, CW, heroH);
    // risk gauge
    const gx = M + 74, gy = y + heroH / 2, gr = 44, gw = 9;
    arc(gx, gy, gr, 0, 360, C.track, gw);
    arc(gx, gy, gr, -90, -90 + 360 * (Math.min(100, result.score) / 100), vColor, gw);
    font('bold', 7); setText(C.dim); doc.text('RISK SCORE', gx, gy - 16, { align: 'center' });
    font('bold', 30); setText(vColor); doc.text(String(result.score), gx, gy + 8, { align: 'center' });
    font('normal', 8); setText(C.dim); doc.text('/ 100', gx, gy + 22, { align: 'center' });
    // verdict + summary
    const rx = M + 152;
    font('bold', 7.5); setText(C.dim); doc.text('ASSESSED THREAT LEVEL', rx, y + 28);
    font('bold', 22); setText(vColor); doc.text(tier.toUpperCase(), rx, y + 52);
    // small risk dot before verdict
    setFill(vColor); doc.circle(rx - 0, y + 24, 0, 'F');
    font('normal', 9.5); setText(C.body);
    doc.text(doc.splitTextToSize(result.summary || '', CW - 152 - 16), rx, y + 72);
    y += heroH + 14;

    /* ============================ CLASSIFICATION SCALE ============================ */
    ensure(64);
    font('bold', 7.5); setText(C.dim); doc.text('RISK CLASSIFICATION SCALE', M, y);
    y += 8;
    const segGap = 5, avail = CW - segGap * 2, h = 9;
    const segs = [
      { w: avail * 0.35, c: C.safe, label: 'SAFE', range: '0–34' },
      { w: avail * 0.30, c: C.suspicious, label: 'SUSPICIOUS', range: '35–64' },
      { w: avail * 0.35, c: C.dangerous, label: 'DANGEROUS', range: '65–100' },
    ];
    const barTop = y + 14;
    let sx = M;
    segs.forEach((s) => {
      setFill(s.c); doc.roundedRect(sx, barTop, s.w, h, h / 2, h / 2, 'F');
      sx += s.w + segGap;
    });
    // marker
    const mx = M + CW * Math.min(100, Math.max(0, result.score)) / 100;
    setFill(C.ink);
    doc.triangle(mx - 4, barTop - 7, mx + 4, barTop - 7, mx, barTop - 1, 'F');
    font('bold', 8); setText(C.ink); doc.text(String(result.score), mx, barTop - 10, { align: 'center' });
    // zone labels
    font('bold', 7.5); sx = M;
    segs.forEach((s) => {
      setText(s.c); doc.text(s.label, sx + s.w / 2, barTop + h + 11, { align: 'center' });
      font('normal', 7); setText(C.faint); doc.text(s.range, sx + s.w / 2, barTop + h + 20, { align: 'center' });
      font('bold', 7.5);
      sx += s.w + segGap;
    });
    y = barTop + h + 30;

    /* ============================ KPI STAT CARDS ============================ */
    ensure(66);
    const kpis = [
      { label: 'THREAT LEVEL', value: tier.toUpperCase(), color: vColor },
      { label: 'RISK SCORE', value: result.score + ' / 100', color: vColor },
      { label: 'SIGNALS TRIGGERED', value: String(hits.length), color: hits.length ? C.dangerous : C.safe },
      { label: 'CHECKS PASSED', value: clean.length + ' / ' + signals.length, color: C.safe },
    ];
    const kGap = 10, kW = (CW - kGap * 3) / 4, kH = 54;
    kpis.forEach((k, i) => {
      const x = M + i * (kW + kGap);
      card(x, y, kW, kH);
      setFill(k.color); doc.rect(x, y + 9, 3, kH - 18, 'F');
      font('bold', 6.8); setText(C.dim); doc.text(k.label, x + 12, y + 20);
      font('bold', 14); setText(k.color); doc.text(String(k.value), x + 12, y + 40);
    });
    y += kH + 6;

    /* ============================ SCANNED TARGET ============================ */
    sectionHeading('Scanned Target');
    const urlLines = doc.splitTextToSize(result.url, CW - 28);
    const uH = urlLines.length * 13 + 20;
    card(M, y, CW, uH, { fill: C.panel });
    font('courier', 10); setText(C.ink); doc.text(urlLines, M + 14, y + 18);
    y += uH + 10;
    // host / protocol / tld / path chips
    if (result.meta) {
      const chips = [];
      if (result.meta.host) chips.push(['HOST', result.meta.host]);
      if (result.meta.protocol) chips.push(['PROTOCOL', result.meta.protocol]);
      if (result.meta.tld) chips.push(['TLD', result.meta.tld]);
      if (result.meta.path) chips.push(['PATH', String(result.meta.path).slice(0, 40)]);
      let cx2 = M;
      ensure(22);
      chips.forEach((ch) => {
        const txt = ch[0] + ' ' + ch[1];
        font('normal', 8); const w = doc.getTextWidth(txt) + 30;
        if (cx2 + w > M + CW) { cx2 = M; y += 24; ensure(22); }
        // label part bold + value
        setFill([241, 244, 249]); doc.roundedRect(cx2, y - 2, w, 18, 9, 9, 'F');
        font('bold', 7.5); setText(C.dim); doc.text(ch[0], cx2 + 9, y + 10);
        font('normal', 8); setText(C.ink);
        doc.text(String(ch[1]), cx2 + 9 + doc.getTextWidth(ch[0]) + 5, y + 10);
        cx2 += w + 7;
      });
      y += 24;
    }

    /* ============================ THREAT ASSESSMENT ============================ */
    if (result.explanation) {
      sectionHeading('Threat Assessment');
      const lead = doc.splitTextToSize(result.explanation.headline, CW - 56);
      const aH = lead.length * 12 + 30;
      ensure(aH + 6);
      card(M, y, CW, aH, { fill: TINT[tier] || TINT.suspicious, border: false });
      setFill(vColor); doc.roundedRect(M, y, 4, aH, 2, 2, 'F');
      iconWarn(M + 16, y + 14, 22, vColor);
      font('normal', 9.5); setText(C.body); doc.text(lead, M + 48, y + 22);
      y += aH + 12;
    } else if (!hits.length) {
      sectionHeading('Threat Assessment');
      const aH = 56;
      card(M, y, CW, aH, { fill: TINT.safe, border: false });
      iconShield(M + 16, y + 16, 24, C.safe);
      font('bold', 11); setText([15, 130, 90]); doc.text('No threat indicators detected', M + 50, y + 24);
      font('normal', 9); setText(C.body);
      doc.text(doc.splitTextToSize(result.summary || '', CW - 64), M + 50, y + 40);
      y += aH + 12;
    }

    /* ============================ THREAT INDICATOR CARDS ============================ */
    if (hits.length) {
      sectionHeading('Threat Indicators', hits.length + ' triggered');
      const sev = (w) => w >= 20 ? { n: 'HIGH', c: C.dangerous } : w >= 12 ? { n: 'MEDIUM', c: C.suspicious } : { n: 'LOW', c: C.brand };
      hits.forEach((s) => {
        const why = whyByLabel[s.label] || s.info || '';
        const cons = doc.splitTextToSize(why, CW - 36);
        const cH = 42 + cons.length * 11;
        ensure(cH + 6);
        const top = y;
        card(M, top, CW, cH);
        const sv = sev(s.weight);
        setFill(sv.c); doc.roundedRect(M + 8, top + 9, 3.5, cH - 18, 1.5, 1.5, 'F');
        // label + detail
        font('bold', 10.5); setText(C.ink); doc.text(s.label, M + 22, top + 20);
        if (s.detail) {
          const lw = doc.getTextWidth(s.label);
          font('normal', 8.5); setText(C.dim); doc.text('(' + s.detail + ')', M + 26 + lw, top + 20);
        }
        // right side: weight pill + severity pill
        const sevW = pill(W - M - 12, top + 8, sv.n, C.white, sv.c, { align: 'right', size: 7, bold: true, h: 15, padX: 7 });
        pill(W - M - 12 - sevW - 6, top + 8, '+' + s.weight + ' pts', sv.c, [245, 247, 250], { align: 'right', size: 7.5, bold: true, h: 15, padX: 7 });
        // weight contribution bar (relative to max signal weight 30)
        const bw = 150, bx = M + 22, byy = top + 27;
        setFill(C.track); doc.roundedRect(bx, byy, bw, 4, 2, 2, 'F');
        setFill(sv.c); doc.roundedRect(bx, byy, Math.max(4, bw * Math.min(1, s.weight / 30)), 4, 2, 2, 'F');
        // consequence
        font('normal', 8.7); setText(C.body); doc.text(cons, M + 22, top + 42);
        y = top + cH + 8;
      });
    }

    /* ============================ SECURITY RECOMMENDATIONS ============================ */
    if (result.explanation && result.explanation.recommendations.length) {
      sectionHeading('Security Recommendations');
      result.explanation.recommendations.forEach((r, i) => {
        const lines = doc.splitTextToSize(r, CW - 42);
        const rH = Math.max(24, lines.length * 12 + 10);
        ensure(rH);
        const top = y;
        setFill(vColor); doc.circle(M + 11, top + 11, 8, 'F');
        font('bold', 9); setText(C.white); doc.text(String(i + 1), M + 11, top + 14, { align: 'center' });
        font('normal', 9.3); setText(C.body); doc.text(lines, M + 30, top + 12);
        y = top + rH;
      });
      y += 6;
    }

    /* ============================ DETECTION COVERAGE ============================ */
    sectionHeading('Detection Coverage', signals.length + ' checks run');
    const total = signals.length || 1;
    const cbH = 11, cbTop = y + 2;
    setFill(C.track); doc.roundedRect(M, cbTop, CW, cbH, cbH / 2, cbH / 2, 'F');
    const passW = CW * (clean.length / total);
    setFill(C.safe); doc.roundedRect(M, cbTop, Math.max(cbH, passW), cbH, cbH / 2, cbH / 2, 'F');
    if (hits.length) { setFill(C.dangerous); doc.roundedRect(M + passW, cbTop, Math.max(cbH, CW - passW), cbH, cbH / 2, cbH / 2, 'F'); }
    y = cbTop + cbH + 16;
    // legend
    setFill(C.safe); doc.circle(M + 4, y - 3, 3.5, 'F');
    font('bold', 8.5); setText(C.ink); doc.text(clean.length + ' Passed', M + 12, y);
    let lx = M + 12 + doc.getTextWidth(clean.length + ' Passed') + 18;
    setFill(C.dangerous); doc.circle(lx, y - 3, 3.5, 'F');
    doc.text(hits.length + ' Triggered', lx + 8, y);
    font('normal', 8.5); setText(C.dim);
    doc.text('of ' + signals.length + ' total checks', W - M, y, { align: 'right' });
    y += 16;
    if (clean.length) {
      font('normal', 8.5);
      const passed = doc.splitTextToSize(clean.map((s) => s.label).join('   ·   '), CW);
      ensure(passed.length * 11 + 22);   // keep heading + list together
      font('bold', 8); setText(C.dim); doc.text('PASSED CHECKS', M, y); y += 14;
      font('normal', 8.5); setText(C.body); doc.text(passed, M, y); y += passed.length * 11;
    }

    drawFooter();
    return finish();

    /* ============================ footer + save ============================ */
    function drawFooter() {
      const pages = doc.internal.getNumberOfPages();
      for (let p = 1; p <= pages; p++) {
        doc.setPage(p);
        setStroke(C.line); doc.setLineWidth(0.6); doc.line(M, H - 42, W - M, H - 42);
        font('bold', 7.5); setText(C.ink); doc.text('GarudaNetra', M, H - 28);
        font('normal', 7.5); setText(C.dim);
        doc.text('Threat Intelligence Report  ·  ' + reportId + '  ·  ' + fmtDate(ts), M + doc.getTextWidth('GarudaNetra') + 6, H - 28);
        doc.text('Page ' + p + ' of ' + pages, W - M, H - 28, { align: 'right' });
        setText(C.faint);
        doc.text('Heuristic, client-side analysis — assistive guidance, not a security guarantee. Verify independently before acting.', M, H - 16);
      }
    }
    function finish() {
      const safeName = (result.meta && result.meta.host ? result.meta.host : 'scan').replace(/[^a-z0-9.-]/gi, '_');
      doc.save('GarudaNetra_' + safeName + '_' + result.score + '.pdf');
    }
  }

  return { generate };
})();
