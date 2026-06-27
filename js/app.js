/* ===========================================================
   app.js — routing, theme, scan flow, result rendering, history
   =========================================================== */
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  let lastResult = null;   // most recent analysis (for PDF/report actions)
  let lastTs = null;

  const VIEW_META = {
    home: ['Welcome to GarudaNetra', 'Scan QR codes and URLs to detect phishing — fully private, in your browser.'],
    scan: ['Scan', 'Decode a QR code or paste a URL to analyze for phishing.'],
    history: ['History', 'Every link you have scanned, searchable and exportable.'],
    about: ['About', 'How GarudaNetra scores threats and what each signal means.'],
  };

  /* ---------------- THEME ---------------- */
  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    $('#themeToggle').innerHTML = `<svg class="icon"><use href="#i-${t === 'dark' ? 'moon' : 'sun'}"/></svg>`;
    const favicon = $('#favicon');
    if (favicon) favicon.href = t === 'dark' ? 'dark2.jpeg' : 'light2.jpeg';
    Store.setTheme(t);
  }
  $('#themeToggle').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });

  /* ---------------- ROUTING ---------------- */
  function go(view) {
    $$('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + view));
    $$('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.view === view));
    if (view === 'home') Dashboard.render();
    if (view === 'history') renderHistory();
    closeNav();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    location.hash = view;
  }
  $$('[data-view]').forEach((el) => el.addEventListener('click', () => go(el.dataset.view)));
  $('#quickScanBtn').addEventListener('click', () => go('scan'));

  /* ---------------- MOBILE NAV ---------------- */
  const nav = $('#nav');
  function closeNav() { nav.classList.remove('open'); }
  $('#menuToggle').addEventListener('click', (e) => {
    e.stopPropagation();
    nav.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (nav.classList.contains('open') && !nav.contains(e.target) && e.target.id !== 'menuToggle') closeNav();
  });

  /* ---------------- SCAN TABS ---------------- */
  $$('#scanTabs .tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('#scanTabs .tab').forEach((t) => t.classList.toggle('active', t === tab));
      $$('.tab-pane').forEach((p) => p.classList.toggle('active', p.id === 'pane-' + tab.dataset.tab));
      if (tab.dataset.tab !== 'camera') Scanner.stopCamera($('#video'));
    });
  });

  /* ---------------- UPLOAD ---------------- */
  const dropzone = $('#dropzone');
  const fileInput = $('#fileInput');

  ['dragenter', 'dragover'].forEach((e) =>
    dropzone.addEventListener(e, (ev) => { ev.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((e) =>
    dropzone.addEventListener(e, (ev) => { ev.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', (ev) => {
    const file = ev.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  async function handleFile(file) {
    toast('Decoding QR code…');
    try {
      const { payload, dataUrl } = await Scanner.decodeFile(file);
      const img = $('#previewImg');
      img.src = dataUrl; img.hidden = false;
      if (!Analyzer.looksLikeUrl(payload)) return showNeedsUrl(payload);
      processScan(payload, 'upload');
    } catch (err) {
      toast(err.message, 'err');
    }
  }

  /* ---------------- CAMERA ---------------- */
  const video = $('#video');
  $('#startCam').addEventListener('click', async () => {
    $('#camHint').textContent = 'Starting camera…';
    const ok = await Scanner.startCamera(video,
      (payload) => {
        $('#startCam').disabled = false; $('#stopCam').disabled = true;
        $('#camHint').textContent = 'QR detected!';
        toast('QR code detected', 'ok');
        if (!Analyzer.looksLikeUrl(payload)) return showNeedsUrl(payload);
        processScan(payload, 'camera');
      },
      (msg) => { $('#camHint').textContent = msg; toast(msg, 'err'); });
    if (ok) {
      $('#startCam').disabled = true; $('#stopCam').disabled = false;
      $('#camHint').textContent = 'Scanning… point the camera at a QR code.';
    }
  });
  $('#stopCam').addEventListener('click', () => {
    Scanner.stopCamera(video);
    $('#startCam').disabled = false; $('#stopCam').disabled = true;
    $('#camHint').textContent = 'Camera stopped.';
  });

  /* ---------------- MANUAL ---------------- */
  $('#analyzeManual').addEventListener('click', runManual);
  $('#manualUrl').addEventListener('keydown', (e) => { if (e.key === 'Enter') runManual(); });
  function runManual() {
    const val = $('#manualUrl').value.trim();
    if (!val) return toast('Enter a URL to analyze.', 'warn');
    if (!Analyzer.looksLikeUrl(val)) {
      toast('That doesn’t look like a URL. Enter a proper link, e.g. https://example.com', 'warn');
      $('#manualUrl').focus();
      return;
    }
    processScan(val, 'manual');
  }

  /* ---------------- CORE SCAN FLOW ---------------- */
  function processScan(payload, source) {
    go('scan'); // ensure scan view visible
    renderProcessing(payload);

    // Walk the checklist while the (instant) analysis "runs", so the user
    // sees clear processing feedback before the verdict appears.
    const steps = $$('#resultBody .scan-steps li');
    steps.forEach((li, idx) => setTimeout(() => {
      steps.forEach((s, j) => { if (j < idx) s.classList.add('done'); });
      li.classList.remove('done'); li.classList.add('active');
    }, idx * 260));

    setTimeout(() => {
      steps.forEach((s) => { s.classList.remove('active'); s.classList.add('done'); });
      const result = Analyzer.analyze(payload);
      result.source = source;
      lastResult = result;
      lastTs = Date.now();
      const record = Store.add(result);
      lastTs = record.ts;
      renderResult(result, record.ts);
      const labels = { safe: 'ok', suspicious: 'warn', dangerous: 'err' };
      toast(`Verdict: ${result.verdict.toUpperCase()} · score ${result.score}`, labels[result.verdict] || 'ok');
    }, steps.length * 260 + 220);
  }

  // Shown when a QR code decodes to plain text / non-URL data (e.g. a note,
  // wifi config) instead of a web link — ask the user for a proper URL.
  function showNeedsUrl(payload) {
    go('scan');
    toast('QR code doesn’t contain a valid URL.', 'warn');
    $('#emptyResult').hidden = true;
    const body = $('#resultBody');
    body.hidden = false;
    body.innerHTML = `
      <div class="result-head">
        <div class="verdict-block">
          <div class="verdict-label suspicious">Not a URL</div>
          <p class="verdict-summary">This QR code doesn’t contain a proper web link, so there's nothing to analyze. Scan a QR code — or paste a link — that contains a full URL like <b>https://example.com</b>.</p>
        </div>
      </div>
      ${payload ? `<div class="url-box"><span class="url-text">${esc(payload)}</span>
        <button class="copy-btn" data-copy="${esc(payload)}" title="Copy">⧉</button></div>` : ''}`;
    bindCopy(body);
  }

  // Animated "analyzing" placeholder shown in the result panel during a scan.
  function renderProcessing(payload) {
    $('#emptyResult').hidden = true;
    const body = $('#resultBody');
    body.hidden = false;
    body.innerHTML = `
      <div class="scanning">
        <div class="scan-radar"></div>
        <h3 class="scanning-title">Analyzing…</h3>
        <p class="scanning-url">${esc(payload)}</p>
        <ul class="scan-steps">
          <li>Reading input</li>
          <li>Inspecting URL structure</li>
          <li>Matching threat signals</li>
          <li>Calculating risk score</li>
        </ul>
      </div>`;
  }

  function renderResult(result, ts) {
    $('#emptyResult').hidden = true;
    const body = $('#resultBody');
    body.hidden = false;

    if (!result.isUrl) {
      body.innerHTML = `
        <div class="result-head">
          <div class="verdict-block">
            <div class="verdict-label safe">QR Decoded</div>
            <p class="verdict-summary">${esc(result.summary)}</p>
          </div>
        </div>
        <div class="url-box"><span class="url-text">${esc(result.url)}</span>
          <button class="copy-btn" data-copy="${esc(result.url)}" title="Copy">⧉</button></div>`;
      bindCopy(body);
      return;
    }

    const vColorVar = `var(--${result.verdict === 'safe' ? 'safe' : result.verdict === 'suspicious' ? 'sus' : 'danger'})`;

    const hits = result.signals.filter((s) => s.hit);
    const clean = result.signals.filter((s) => !s.hit);

    const signalRow = (s) => `
      <div class="signal-row ${s.hit ? 'hit' : ''}">
        <span class="signal-icon"><svg class="icon"><use href="#i-${s.hit ? 'alert' : 'check-circle'}"/></svg></span>
        <span class="signal-text">
          <div class="signal-name">${esc(s.label)}${s.detail ? ` <span class="muted">(${esc(s.detail)})</span>` : ''}</div>
          <div class="signal-desc">${esc(s.info)}</div>
        </span>
        <span class="signal-weight">${s.hit ? '+' + s.weight : '<svg class="icon"><use href="#i-check"/></svg>'}</span>
      </div>`;

    body.innerHTML = `
      <div class="result-head">
        <div class="rh-top">
          <div class="verdict-label ${result.verdict}">${cap(result.verdict)}</div>
          <div class="score-readout"><b style="color:${vColorVar}">${result.score}</b><small>Risk / 100</small></div>
        </div>
        <div class="risk-bar">
          <div class="risk-bar-fill ${result.verdict}" style="width:0%"></div>
          <span class="risk-tick" style="left:35%"></span>
          <span class="risk-tick" style="left:65%"></span>
        </div>
        <div class="risk-scale">
          <span class="zone safe">Safe</span>
          <span class="zone sus">Suspicious</span>
          <span class="zone danger">Dangerous</span>
        </div>
        <p class="verdict-summary">${esc(result.summary)}</p>
      </div>

      <div class="url-box">
        <span class="url-text">${esc(result.url)}</span>
        <button class="copy-btn" data-copy="${esc(result.url)}" title="Copy URL">⧉</button>
      </div>

      ${result.explanation ? explanationBlock(result) : ''}

      <div class="section-title">Details</div>
      <div class="meta-grid">
        ${Object.entries(result.meta).map(([k, v]) =>
          `<div class="meta-item"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join('')}
      </div>

      <div class="section-title">Threat Signals — ${hits.length} triggered</div>
      ${hits.length ? hits.map(signalRow).join('') : '<p class="hint">No threat signals were triggered.</p>'}

      <details style="margin-top:14px">
        <summary class="muted" style="cursor:pointer">Show ${clean.length} passed checks</summary>
        ${clean.map(signalRow).join('')}
      </details>

      <div class="result-actions">
        <button class="primary-btn" id="pdfBtn">Download PDF Report</button>
        <button class="ghost-btn" id="openBtn">Open Safely</button>
        <button class="ghost-btn" id="rescanBtn"><svg class="icon"><use href="#i-refresh"/></svg> New Scan</button>
      </div>`;

    bindCopy(body);
    // Animate the risk bar from 0 to the score after layout.
    const fill = body.querySelector('.risk-bar-fill');
    if (fill) requestAnimationFrame(() => { fill.style.width = result.score + '%'; });
    $('#pdfBtn').addEventListener('click', () => openReportModal(result, ts));
    $('#openBtn').addEventListener('click', () => {
      if (result.verdict !== 'safe') {
        if (!confirm(`This link is rated ${result.verdict.toUpperCase()} (risk ${result.score}).\n\nOpen it anyway?`)) return;
      }
      window.open(result.url, '_blank', 'noopener,noreferrer');
    });
    $('#rescanBtn').addEventListener('click', () => {
      body.hidden = true; $('#emptyResult').hidden = false;
      $('#previewImg').hidden = true; $('#manualUrl').value = '';
    });
  }

  function explanationBlock(result) {
    const ex = result.explanation;
    return `
      <div class="explain ${result.verdict}">
        <div class="explain-head">
          <div>
            <div class="explain-title">Why this link is ${esc(result.verdict)}</div>
            <p class="explain-lead">${esc(ex.headline)}</p>
          </div>
        </div>
        <div class="explain-sub">What the warning signs mean</div>
        <ul class="explain-list">
          ${ex.threats.map((t) => `
            <li>
              <b>${esc(t.label)}${t.detail ? ` <span class="muted">(${esc(t.detail)})</span>` : ''}</b>
              <span>${esc(t.why)}</span>
            </li>`).join('')}
        </ul>
        <div class="explain-sub">Recommended actions</div>
        <ul class="explain-recs">
          ${ex.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}
        </ul>
      </div>`;
  }

  function bindCopy(root) {
    $$('[data-copy]', root).forEach((btn) =>
      btn.addEventListener('click', () => {
        navigator.clipboard?.writeText(btn.dataset.copy);
        toast('Copied to clipboard', 'ok');
      }));
  }

  /* ---------------- HISTORY ---------------- */
  function renderHistory() {
    const q = $('#historySearch').value.toLowerCase();
    const all = Store.load();
    let list = all;
    if (q) list = list.filter((r) => r.url.toLowerCase().includes(q));

    const body = $('#historyBody');
    const empty = $('#emptyHistory');
    empty.hidden = list.length > 0;
    // Distinguish "no scans at all" from "search hid everything".
    if (list.length === 0) {
      empty.querySelector('p').textContent = all.length > 0
        ? 'No scans match your search. Clear it to see all ' + all.length + ' scans.'
        : 'No scans yet. Your scan history will appear here.';
    }
    body.innerHTML = list.map((r) => `
      <tr>
        <td><span class="risk-pill ${r.verdict}">${r.verdict}</span></td>
        <td class="h-url" title="${esc(r.url)}">${esc(r.url)}</td>
        <td class="h-score">${r.score}</td>
        <td><span class="muted">${esc(r.source)}</span></td>
        <td class="muted">${new Date(r.ts).toLocaleString()}</td>
        <td>
          <div class="h-actions">
            <button class="mini-btn" data-act="view" data-id="${r.id}" title="View"><svg class="icon"><use href="#i-eye"/></svg></button>
            <button class="mini-btn" data-act="pdf" data-id="${r.id}" title="PDF"><svg class="icon"><use href="#i-file"/></svg></button>
            <button class="mini-btn" data-act="del" data-id="${r.id}" title="Delete"><svg class="icon"><use href="#i-trash"/></svg></button>
          </div>
        </td>
      </tr>`).join('');

    $$('#historyBody [data-act]').forEach((btn) =>
      btn.addEventListener('click', () => handleHistoryAction(btn.dataset.act, btn.dataset.id)));
  }

  function handleHistoryAction(act, id) {
    const rec = Store.get(id);
    if (!rec) return;
    if (act === 'del') {
      Store.remove(id); renderHistory(); Dashboard.render(); toast('Scan deleted'); return;
    }
    if (act === 'pdf') { openReportModal(rec, rec.ts); return; }
    if (act === 'view') {
      go('scan');
      renderResult(rec, rec.ts);
    }
  }
  $('#historySearch').addEventListener('input', renderHistory);
  $('#clearHistory').addEventListener('click', () => {
    if (!Store.load().length) return toast('History is already empty.', 'warn');
    if (confirm('Delete all scan history? This cannot be undone.')) {
      Store.clear(); renderHistory(); Dashboard.render(); toast('History cleared');
    }
  });

  /* ---------------- REPORT MODAL ---------------- */
  let pendingReport = null;
  const modal = $('#reportModal');
  const nameInput = $('#rptName');
  const emailInput = $('#rptEmail');

  function openReportModal(rec, ts) {
    pendingReport = { rec, ts };
    const saved = Store.getRecipient();
    nameInput.value = saved.name || '';
    emailInput.value = saved.email || '';
    clearFieldErrors();
    modal.hidden = false;
    setTimeout(() => nameInput.focus(), 50);
  }
  function closeReportModal() { modal.hidden = true; pendingReport = null; }

  function clearFieldErrors() {
    $('#rptNameErr').hidden = true; $('#rptEmailErr').hidden = true;
    nameInput.classList.remove('invalid'); emailInput.classList.remove('invalid');
  }

  function submitReport() {
    if (!pendingReport) return;
    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    clearFieldErrors();

    let ok = true;
    if (!name) {
      $('#rptNameErr').hidden = false; nameInput.classList.add('invalid'); nameInput.focus(); ok = false;
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      $('#rptEmailErr').hidden = false; emailInput.classList.add('invalid');
      if (ok) emailInput.focus();
      ok = false;
    }
    if (!ok) return;

    const recipient = { name, email };
    Store.setRecipient(recipient);
    Report.generate(pendingReport.rec, pendingReport.ts, recipient);
    closeReportModal();
    toast('PDF report downloaded', 'ok');
  }

  $('#rptGenerate').addEventListener('click', submitReport);
  $('#rptCancel').addEventListener('click', closeReportModal);
  $('#rptClose').addEventListener('click', closeReportModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) closeReportModal(); });
  [nameInput, emailInput].forEach((inp) =>
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitReport(); }));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !modal.hidden) closeReportModal(); });

  /* ---------------- CONTACT / FEEDBACK FORM ---------------- */
  const CONTACT_EMAIL = 'jagadtusharn@gmail.com';
  const fbForm = $('#feedbackForm');

  function fbErr(inputSel, errSel, valid) {
    $(errSel).hidden = valid;
    $(inputSel).classList.toggle('invalid', !valid);
  }

  if (fbForm) {
    fbForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const name = $('#fbName').value.trim();
      const email = $('#fbEmail').value.trim();
      const topic = $('#fbType').value;
      const msg = $('#fbMessage').value.trim();
      const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      let ok = true;
      fbErr('#fbName', '#fbNameErr', !!name); if (!name) ok = false;
      fbErr('#fbEmail', '#fbEmailErr', emailOk); if (!emailOk) ok = false;
      fbErr('#fbMessage', '#fbMsgErr', !!msg); if (!msg) ok = false;
      if (!ok) return;

      Store.addFeedback({ name, email, topic, message: msg });

      const subject = `[GarudaNetra] ${topic} from ${name}`;
      const body = `${msg}\n\n— ${name} (${email})`;
      window.location.href =
        `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

      fbForm.reset();
      toast('Thanks! Your message is ready in your email app.', 'ok');
    });
  }

  /* ---------------- ABOUT signal docs ---------------- */
  function renderSignalDocs() {
    const ul = $('#signalDocList');
    ul.innerHTML = Analyzer.signalDocs()
      .sort((a, b) => b.weight - a.weight)
      .map((s) => `<li><span>${esc(s.label)}</span><b>+${s.weight}</b></li>`).join('');
  }

  /* ---------------- HELPERS ---------------- */
  let toastTimer;
  function toast(msg, type = '') {
    const el = $('#toast');
    el.textContent = msg;
    el.className = 'toast show ' + type;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
  }
  const esc = Dashboard.esc;
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

  /* ---------------- INIT ---------------- */
  applyTheme(Store.getTheme());
  renderSignalDocs();
  const startView = (location.hash || '#home').slice(1);
  go(VIEW_META[startView] ? startView : 'home');

  // Warn if scans won't survive a reload in this context (file://, private mode, etc.)
  if (!Store.persistent()) {
    setTimeout(() => toast('Heads up: scan history can’t be saved here. Open the app via http://localhost:8000 to keep history.', 'warn'), 800);
  }
})();
