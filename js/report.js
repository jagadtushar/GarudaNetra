/* ===========================================================
   report.js — generate a branded PDF threat report with jsPDF
   =========================================================== */
const Report = (() => {
  const COLORS = {
    safe: [22, 199, 132],
    suspicious: [245, 165, 36],
    dangerous: [245, 69, 92],
    brand: [77, 139, 255],
    pink: [255, 77, 210],
    dark: [11, 15, 32],
    ink: [26, 34, 51],
    dim: [110, 120, 140],
    line: [225, 230, 240],
  };

  // Preload the logo so it's ready by the time a report is generated.
  const logoImg = new Image();
  logoImg.src = 'logo.jpeg';

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
    const W = doc.internal.pageSize.getWidth();
    const M = 48;
    let y = 0;

    const vColor = COLORS[result.verdict] || COLORS.brand;
    const reportId = reportIdFor(result, ts);

    /* ---- Header band (dark, to suit the neon logo) ---- */
    doc.setFillColor(...COLORS.dark);
    doc.rect(0, 0, W, 104, 'F');
    // neon accent underline
    doc.setFillColor(...COLORS.brand);
    doc.rect(0, 104, W, 3, 'F');
    // logo (black background blends into the dark band)
    try {
      if (logoImg.complete && logoImg.naturalWidth) {
        doc.addImage(logoImg, 'JPEG', M, 26, 52, 52);
      }
    } catch (e) { /* logo not ready — skip gracefully */ }
    // title
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(23);
    doc.text('GarudaNetra', M + 66, 50);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(10.5);
    doc.setTextColor(170, 188, 235);
    doc.text('QR & URL Threat Analysis Report', M + 66, 70);
    // header meta: report id only (date lives in the footer)
    doc.setFontSize(8.5); doc.setTextColor(120, 135, 185);
    doc.text('REPORT ID', W - M, 46, { align: 'right' });
    doc.setFont('helvetica', 'bold'); doc.setFontSize(11); doc.setTextColor(210, 220, 245);
    doc.text(reportId, W - M, 62, { align: 'right' });

    /* ---- Prepared-for line ---- */
    y = 132;
    doc.setFont('helvetica', 'normal'); doc.setFontSize(8);
    doc.setTextColor(...COLORS.dim);
    doc.text('PREPARED FOR', M, y);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(11.5);
    doc.setTextColor(...COLORS.ink);
    const who = (recipient.name || '—') + (recipient.email ? '   <' + recipient.email + '>' : '');
    doc.text(who, M, y + 15);
    y += 46;

    /* ---- Verdict card ---- */
    doc.setFillColor(248, 250, 253);
    doc.roundedRect(M, y - 28, W - M * 2, 96, 8, 8, 'F');

    // Score circle
    const cx = M + 50, cy = y + 20, r = 34;
    doc.setDrawColor(...COLORS.line); doc.setLineWidth(7);
    doc.circle(cx, cy, r, 'S');
    doc.setDrawColor(...vColor); doc.setLineWidth(7);
    // approximate arc with a full circle tinted by verdict for simplicity
    doc.circle(cx, cy, r, 'S');
    doc.setTextColor(...vColor);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(26);
    doc.text(String(result.score), cx, cy + 4, { align: 'center' });
    doc.setFontSize(7); doc.setTextColor(...COLORS.dim);
    doc.text('RISK / 100', cx, cy + 18, { align: 'center' });

    // Verdict text
    doc.setTextColor(...vColor);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(20);
    doc.text(result.verdict.toUpperCase(), M + 110, y + 6);
    doc.setTextColor(...COLORS.dim);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5);
    const sum = doc.splitTextToSize(result.summary || '', W - M * 2 - 120);
    doc.text(sum, M + 110, y + 26);

    y += 96;

    /* ---- Scanned URL ---- */
    doc.setTextColor(...COLORS.ink);
    doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
    doc.text('Scanned Target', M, y);
    y += 16;
    doc.setFillColor(245, 247, 251);
    const urlLines = doc.splitTextToSize(result.url, W - M * 2 - 24);
    const urlH = urlLines.length * 13 + 18;
    doc.roundedRect(M, y - 12, W - M * 2, urlH, 6, 6, 'F');
    doc.setFont('courier', 'normal'); doc.setFontSize(9.5);
    doc.setTextColor(...COLORS.ink);
    doc.text(urlLines, M + 12, y + 4);
    y += urlH + 14;

    /* ---- Metadata ---- */
    if (result.meta) {
      const entries = Object.entries(result.meta);
      doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.setTextColor(...COLORS.ink);
      doc.text('Details', M, y); y += 14;
      doc.setFontSize(9);
      const colW = (W - M * 2) / 2;
      entries.forEach((e, i) => {
        const col = i % 2, row = Math.floor(i / 2);
        const x = M + col * colW;
        const yy = y + row * 16;
        doc.setFont('helvetica', 'bold'); doc.setTextColor(...COLORS.dim);
        doc.text(String(e[0]).toUpperCase() + ':', x, yy);
        doc.setFont('courier', 'normal'); doc.setTextColor(...COLORS.ink);
        doc.text(String(e[1]).slice(0, 48), x + 70, yy);
      });
      y += Math.ceil(entries.length / 2) * 16 + 12;
    }

    /* ---- Threat explanation (risky links only) ---- */
    if (result.explanation) {
      const ex = result.explanation;
      if (y > 640) { doc.addPage(); y = 60; }
      // Tinted callout with headline.
      const tint = result.verdict === 'dangerous' ? [254, 240, 242] : [255, 248, 235];
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5);
      const lead = doc.splitTextToSize(ex.headline, W - M * 2 - 24);
      const boxH = lead.length * 12 + 40;
      doc.setFillColor(...tint);
      doc.roundedRect(M, y - 12, W - M * 2, boxH, 6, 6, 'F');
      doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.setTextColor(...vColor);
      doc.text('Why this link is ' + result.verdict, M + 12, y + 6);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5);
      doc.setTextColor(...COLORS.ink);
      doc.text(lead, M + 12, y + 22);
      y += boxH + 6;

      // Recommended actions.
      if (y > 700) { doc.addPage(); y = 60; }
      doc.setFont('helvetica', 'bold'); doc.setFontSize(10);
      doc.setTextColor(...COLORS.ink);
      doc.text('Recommended actions', M, y); y += 6;
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
      doc.setTextColor(...COLORS.dim);
      ex.recommendations.forEach((r) => {
        if (y > 760) { doc.addPage(); y = 60; }
        y += 14;
        const lines = doc.splitTextToSize(r, W - M * 2 - 16);
        doc.setTextColor(...vColor); doc.text('•', M + 2, y);
        doc.setTextColor(...COLORS.dim); doc.text(lines, M + 14, y);
        y += (lines.length - 1) * 11;
      });
      y += 10;
    }

    /* ---- Detection signals ---- */
    doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
    doc.setTextColor(...COLORS.ink);
    doc.text('Detection Signals', M, y); y += 8;

    const hits = (result.signals || []).filter((s) => s.hit);
    const clean = (result.signals || []).filter((s) => !s.hit);

    const drawSignal = (s, hit) => {
      if (y > 760) { doc.addPage(); y = 60; }
      y += 18;
      const c = hit ? COLORS.dangerous : COLORS.safe;
      doc.setFillColor(...c);
      doc.circle(M + 4, y - 3, 3, 'F');
      doc.setFont('helvetica', 'bold'); doc.setFontSize(9.5);
      doc.setTextColor(...COLORS.ink);
      doc.text(s.label + (s.detail ? '  (' + s.detail + ')' : ''), M + 16, y);
      doc.setTextColor(...c);
      doc.text((hit ? '+' + s.weight : 'clear'), W - M, y, { align: 'right' });
      doc.setFont('helvetica', 'normal'); doc.setFontSize(8);
      doc.setTextColor(...COLORS.dim);
      const info = doc.splitTextToSize(s.info, W - M * 2 - 60);
      doc.text(info, M + 16, y + 11);
      y += info.length * 9 + 4;
    };

    if (hits.length) {
      hits.forEach((s) => drawSignal(s, true));
    } else {
      y += 18;
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5);
      doc.setTextColor(...COLORS.safe);
      doc.text('No risk signals were triggered for this link.', M + 16, y);
    }

    // Passed checks summary
    if (clean.length) {
      if (y > 730) { doc.addPage(); y = 60; }
      y += 22;
      doc.setFont('helvetica', 'bold'); doc.setFontSize(9);
      doc.setTextColor(...COLORS.dim);
      doc.text(`Passed ${clean.length} checks: ` +
        clean.map((s) => s.label).join(', '),
        M, y, { maxWidth: W - M * 2 });
    }

    /* ---- Footer on every page ---- */
    const pages = doc.internal.getNumberOfPages();
    for (let p = 1; p <= pages; p++) {
      doc.setPage(p);
      const H = doc.internal.pageSize.getHeight();
      doc.setDrawColor(...COLORS.line); doc.setLineWidth(0.5);
      doc.line(M, H - 44, W - M, H - 44);
      // line 1: report id + generated date (left), page (right)
      doc.setFont('helvetica', 'bold'); doc.setFontSize(7.5);
      doc.setTextColor(...COLORS.ink);
      doc.text('Report ID: ' + reportId, M, H - 30);
      doc.setFont('helvetica', 'normal'); doc.setTextColor(...COLORS.dim);
      doc.text('  ·  Generated ' + fmtDate(ts), M + doc.getTextWidth('Report ID: ' + reportId), H - 30);
      doc.text(`Page ${p} / ${pages}`, W - M, H - 30, { align: 'right' });
      // line 2: disclaimer
      doc.setFontSize(7.5); doc.setTextColor(...COLORS.dim);
      doc.text('GarudaNetra · Heuristic analysis — assistive, not a guarantee.', M, H - 18);
    }

    const safeName = (result.meta && result.meta.host ? result.meta.host : 'scan')
      .replace(/[^a-z0-9.-]/gi, '_');
    doc.save(`GarudaNetra_${safeName}_${result.score}.pdf`);
  }

  return { generate };
})();
