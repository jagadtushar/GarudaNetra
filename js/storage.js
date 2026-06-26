/* ===========================================================
   storage.js — scan history + theme persistence (localStorage)
   =========================================================== */
const Store = (() => {
  const HISTORY_KEY = 'qrshield.history.v1';
  const THEME_KEY = 'qrshield.theme';

  function load() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
      return [];
    }
  }

  function save(list) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
      return true;
    } catch (e) {
      console.warn('GarudaNetra: could not save history —', e);
      return false;
    }
  }

  /** True when localStorage can actually persist data in this context. */
  function persistent() {
    try {
      const k = '__gn_probe__';
      localStorage.setItem(k, '1');
      localStorage.removeItem(k);
      return true;
    } catch {
      return false;
    }
  }

  /** Add a scan result to the front of history. Returns the stored record. */
  function add(result) {
    const list = load();
    const record = {
      id: 'scan_' + Date.now() + '_' + Math.floor(Math.random() * 1e4),
      url: result.url,
      score: result.score,
      verdict: result.verdict,
      source: result.source || 'manual',
      signals: result.signals,
      meta: result.meta,
      summary: result.summary,
      explanation: result.explanation,
      ts: Date.now(),
    };
    list.unshift(record);
    // Keep history bounded.
    if (list.length > 500) list.length = 500;
    save(list);
    return record;
  }

  function remove(id) {
    save(load().filter((r) => r.id !== id));
  }

  function clear() {
    save([]);
  }

  function get(id) {
    return load().find((r) => r.id === id);
  }

  /* ---- theme ---- */
  function getTheme() {
    try { return localStorage.getItem(THEME_KEY) || 'dark'; }
    catch { return 'dark'; }
  }
  function setTheme(t) {
    try { localStorage.setItem(THEME_KEY, t); } catch {}
  }

  /* ---- report recipient (prefill) ---- */
  function getRecipient() {
    try { return JSON.parse(localStorage.getItem('qrshield.recipient')) || {}; }
    catch { return {}; }
  }
  function setRecipient(r) {
    try { localStorage.setItem('qrshield.recipient', JSON.stringify(r)); } catch {}
  }

  /* ---- feedback (local copy of messages sent) ---- */
  function addFeedback(fb) {
    try {
      const list = JSON.parse(localStorage.getItem('qrshield.feedback') || '[]');
      list.unshift({ ...fb, ts: Date.now() });
      localStorage.setItem('qrshield.feedback', JSON.stringify(list.slice(0, 100)));
    } catch {}
  }

  return { load, add, remove, clear, get, persistent, getRecipient, setRecipient, addFeedback, getTheme, setTheme };
})();
