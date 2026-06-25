/* ===========================================================
   analyzer.js — heuristic URL phishing analysis engine
   Produces a 0–100 risk score, a verdict, and per-signal detail.
   100% client-side; no network calls.
   =========================================================== */
const Analyzer = (() => {
  // Known URL shorteners (often used to obscure phishing destinations).
  const SHORTENERS = [
    'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly','adf.ly',
    'bit.do','cutt.ly','rebrand.ly','shorturl.at','t.ly','rb.gy','tiny.cc','soo.gd',
  ];

  // Free / abused TLDs disproportionately used in phishing campaigns.
  const RISKY_TLDS = [
    'zip','mov','xyz','top','tk','ml','ga','cf','gq','work','click','link','country',
    'kim','science','party','review','stream','download','racing','win','bid','loan',
    'date','men','rest','fit','cam',
  ];

  // Brands commonly impersonated in phishing.
  const BRANDS = [
    'paypal','apple','microsoft','google','amazon','netflix','facebook','instagram',
    'whatsapp','linkedin','bankofamerica','wellsfargo','chase','citibank','hsbc',
    'coinbase','binance','metamask','dhl','fedex','ups','usps','irs','hmrc',
    'outlook','office365','icloud','dropbox','adobe','steam','roblox','snapchat',
  ];

  // Sensitive-action keywords that phishing pages favour.
  const SUS_WORDS = [
    'login','signin','verify','verification','account','secure','update','confirm',
    'password','billing','payment','wallet','unlock','suspended','recover','validate',
    'authenticate','webscr','ebayisapi','security-alert','support',
  ];

  /** Each signal: id, label, weight, and a test(ctx) -> {hit, detail?}. */
  const SIGNALS = [
    {
      id: 'no-https', label: 'No HTTPS encryption', weight: 12,
      info: 'The link uses plain HTTP, so traffic is not encrypted.',
      test: (c) => ({ hit: c.protocol === 'http:' }),
    },
    {
      id: 'ip-host', label: 'IP address as host', weight: 22,
      info: 'Legitimate sites use domain names, not raw IP addresses.',
      test: (c) => ({ hit: /^(\d{1,3}\.){3}\d{1,3}$/.test(c.host) || c.host.includes('[') }),
    },
    {
      id: 'at-symbol', label: '"@" in URL', weight: 20,
      info: 'An "@" can hide the real destination after the visible text.',
      test: (c) => ({ hit: c.raw.split('?')[0].includes('@') }),
    },
    {
      id: 'punycode', label: 'Punycode / homograph domain', weight: 24,
      info: 'Encoded "xn--" domains can mimic real brands with look-alike characters.',
      test: (c) => ({ hit: c.host.includes('xn--') }),
    },
    {
      id: 'shortener', label: 'URL shortener', weight: 14,
      info: 'Shorteners hide the true destination of the link.',
      test: (c) => ({ hit: SHORTENERS.includes(c.host.replace(/^www\./, '')) }),
    },
    {
      id: 'risky-tld', label: 'High-risk top-level domain', weight: 16,
      info: 'This TLD is frequently abused for phishing and malware.',
      test: (c) => {
        const tld = c.host.split('.').pop();
        return { hit: RISKY_TLDS.includes(tld), detail: '.' + tld };
      },
    },
    {
      id: 'many-subdomains', label: 'Excessive subdomains', weight: 14,
      info: 'Many subdomains are used to bury a fake domain or look official.',
      test: (c) => {
        const parts = c.host.split('.');
        const n = Math.max(0, parts.length - 2);
        return { hit: n >= 3, detail: n + ' levels' };
      },
    },
    {
      id: 'brand-in-subdomain', label: 'Brand name misuse', weight: 20,
      info: 'A well-known brand appears outside its official domain.',
      test: (c) => {
        const labels = c.host.split('.');
        const root = labels.slice(-2).join('.');
        for (const b of BRANDS) {
          const inHost = c.host.includes(b);
          const isOfficial = root === b + '.com';
          if (inHost && !isOfficial) return { hit: true, detail: b };
        }
        return { hit: false };
      },
    },
    {
      id: 'lookalike', label: 'Look-alike / typo domain', weight: 18,
      info: 'The domain swaps characters to imitate a trusted brand (e.g. paypa1).',
      test: (c) => {
        const host = c.host.replace(/^www\./, '');
        for (const b of BRANDS) {
          // brand with digits/extra chars substituted
          const fuzzy = b.replace(/o/g, '[o0]').replace(/i/g, '[i1l]').replace(/e/g, '[e3]').replace(/a/g, '[a@4]');
          const re = new RegExp('(^|[.-])' + fuzzy);
          if (re.test(host) && !host.includes(b + '.')) {
            // only flag if it's NOT an exact clean brand match
            if (!new RegExp('(^|[.-])' + b + '([.-]|$)').test(host)) {
              return { hit: true, detail: 'mimics ' + b };
            }
          }
        }
        return { hit: false };
      },
    },
    {
      id: 'sus-keywords', label: 'Sensitive-action keywords', weight: 10,
      info: 'Words like "login", "verify" or "secure" are common in phishing URLs.',
      test: (c) => {
        const found = SUS_WORDS.filter((w) => c.raw.toLowerCase().includes(w));
        return { hit: found.length >= 2, detail: found.slice(0, 3).join(', ') };
      },
    },
    {
      id: 'many-hyphens', label: 'Many hyphens in domain', weight: 8,
      info: 'Phishers chain words with hyphens (secure-login-update).',
      test: (c) => {
        const n = (c.host.match(/-/g) || []).length;
        return { hit: n >= 3, detail: n + ' hyphens' };
      },
    },
    {
      id: 'long-url', label: 'Unusually long URL', weight: 8,
      info: 'Very long URLs hide malicious parameters and look intimidating.',
      test: (c) => ({ hit: c.raw.length > 90, detail: c.raw.length + ' chars' }),
    },
    {
      id: 'port', label: 'Non-standard port', weight: 12,
      info: 'Explicit unusual ports can point to a rogue server.',
      test: (c) => ({ hit: !!c.port && !['80','443',''].includes(c.port), detail: c.port }),
    },
    {
      id: 'encoded', label: 'Encoded / obfuscated characters', weight: 12,
      info: 'Percent-encoding or hex can disguise the real address.',
      test: (c) => {
        const hits = (c.raw.match(/%[0-9a-f]{2}/gi) || []).length;
        return { hit: hits >= 4 || /0x[0-9a-f]+/i.test(c.host), detail: hits + ' sequences' };
      },
    },
    {
      id: 'data-uri', label: 'Data / javascript URI', weight: 30,
      info: 'Non-web schemes can execute code or embed hidden payloads.',
      test: (c) => ({ hit: /^(data|javascript|vbscript|file):/i.test(c.raw) }),
    },
    {
      id: 'credentials', label: 'Embedded credentials', weight: 16,
      info: 'A username:password inside the URL is a classic deception trick.',
      test: (c) => ({ hit: /\/\/[^/@\s]+:[^/@\s]+@/.test(c.raw) }),
    },
    {
      id: 'fake-extension', label: 'Disguised file/path', weight: 14,
      info: 'Paths ending in .exe, .scr, .apk or double extensions may drop malware.',
      test: (c) => ({ hit: /\.(exe|scr|apk|bat|cmd|msi|dmg|jar)(\?|$)/i.test(c.path) ||
                          /\.(pdf|doc|jpg|png)\.(exe|scr|zip|html?)/i.test(c.raw) }),
    },
  ];

  // Per-signal "what the attacker is doing / what could happen" explanation,
  // used to build a plain-language threat write-up for risky links.
  const CONSEQUENCE = {
    'no-https': 'Anything you type — passwords, card numbers — travels in clear text and can be read or altered by anyone on the network.',
    'ip-host': 'Hiding behind a bare IP avoids domain reputation checks and is typical of throwaway servers hosting scam or malware pages.',
    'at-symbol': 'Everything before the "@" is ignored by the browser, so the page you actually land on is not the one shown in the visible text.',
    'punycode': 'Look-alike letters from other alphabets are used to forge a trusted brand’s domain (e.g. “аpple” with a Cyrillic “а”).',
    'shortener': 'The real destination is hidden behind a redirect, so you cannot tell where the link leads until it is too late.',
    'risky-tld': 'This domain extension is cheap or free and is heavily abused for disposable phishing and malware sites.',
    'many-subdomains': 'A long chain of subdomains is used to push the real (untrusted) domain out of sight and make the link look official.',
    'brand-in-subdomain': 'A trusted brand name is placed where it does not belong to trick you into thinking this is the brand’s real site.',
    'lookalike': 'The domain deliberately misspells a well-known brand to impersonate it and harvest your credentials.',
    'sus-keywords': 'Words like “login”, “verify” and “secure” are bait designed to create urgency and push you to enter sensitive data.',
    'many-hyphens': 'Stringing brand and action words together with hyphens is a common way to fake an official-looking address.',
    'long-url': 'An overly long address is used to bury redirects and malicious parameters and to discourage close inspection.',
    'port': 'Connecting on an unusual port often points to a rogue or compromised server rather than a normal website.',
    'encoded': 'Heavy percent/hex encoding disguises the true address and any payload from both you and basic filters.',
    'data-uri': 'This is not a normal web link — it can run script or embed a hidden payload directly in your browser.',
    'credentials': 'A username and password baked into the link is a classic trick to make a hostile host look like a trusted login.',
    'fake-extension': 'The link points at an executable or a double-extension file that can install malware if opened.',
  };

  // Recommendations triggered by specific signals (deduped at build time).
  const REC_BY_SIGNAL = {
    'no-https': 'Never enter passwords or payment details on a non-HTTPS page.',
    'shortener': 'Expand the shortened link with a preview service before trusting it.',
    'punycode': 'Type the brand’s address yourself instead of clicking — do not trust the displayed name.',
    'lookalike': 'Check the spelling of the domain character by character against the real brand.',
    'brand-in-subdomain': 'Go to the brand’s official site directly; legitimate brands do not host logins on unrelated domains.',
    'fake-extension': 'Do not download or open any file this link offers.',
    'data-uri': 'Close this link — do not allow it to run in your browser.',
    'credentials': 'Treat any link that contains a username:password as hostile.',
  };

  function buildExplanation(verdict, hits, meta) {
    if (verdict === 'safe' || !hits.length) return null;
    const sorted = hits.slice().sort((a, b) => b.weight - a.weight);

    const threats = sorted.map((s) => ({
      label: s.label,
      detail: s.detail,
      why: CONSEQUENCE[s.id] || s.info,
    }));

    // Build a short narrative headline.
    const top = sorted[0];
    const host = meta && meta.host ? meta.host : 'this link';
    let headline;
    if (verdict === 'dangerous') {
      headline = `This link shows strong signs of a phishing or malware attempt. The clearest red flag is “${top.label.toLowerCase()}”. It is most likely trying to impersonate a trusted service and steal your credentials, payment details, or install malware.`;
    } else {
      headline = `This link has several traits commonly seen in phishing. The main concern is “${top.label.toLowerCase()}”. Treat it as untrusted until you can independently confirm where it really leads.`;
    }

    // Recommendations: signal-specific first, then sensible defaults.
    const recs = [];
    const seen = new Set();
    sorted.forEach((s) => {
      const r = REC_BY_SIGNAL[s.id];
      if (r && !seen.has(r)) { recs.push(r); seen.add(r); }
    });
    const defaults = [
      'Do not enter passwords, card numbers, or personal information.',
      `Verify by typing the official website address yourself rather than following ${host}.`,
      'If you received this in an email or message, report it to your IT/security team and delete it.',
    ];
    defaults.forEach((r) => { if (!seen.has(r)) { recs.push(r); seen.add(r); } });

    return { headline, threats, recommendations: recs.slice(0, 6) };
  }

  function parse(raw) {
    raw = (raw || '').trim();
    // Add scheme if a bare domain was provided.
    let normalized = raw;
    if (!/^[a-z][a-z0-9+.-]*:/i.test(raw)) normalized = 'http://' + raw;
    let u;
    try {
      u = new URL(normalized);
    } catch {
      return null;
    }
    return {
      raw,
      protocol: u.protocol,
      host: u.hostname.toLowerCase(),
      port: u.port,
      path: u.pathname,
      query: u.search,
      url: u,
    };
  }

  /**
   * Analyze a raw string (URL or QR payload).
   * Returns { url, isUrl, score, verdict, signals[], meta }.
   */
  function analyze(raw) {
    const ctx = parse(raw);

    // Non-URL QR payloads (wifi, contact, plain text) — report separately.
    if (!ctx || (!/^https?:/i.test(ctx.protocol) && !/^(data|javascript|vbscript|file):/i.test(ctx.raw))) {
      const isScheme = ctx && /^(data|javascript|vbscript|file):/i.test(ctx.raw);
      if (!isScheme) {
        return {
          url: raw, isUrl: false, score: 0, verdict: 'safe',
          signals: [], meta: { type: 'Non-URL payload' },
          summary: 'This QR code does not contain a web link. No URL threat analysis applies.',
        };
      }
    }

    const results = SIGNALS.map((s) => {
      const r = s.test(ctx);
      return { id: s.id, label: s.label, weight: s.weight, info: s.info,
               hit: !!r.hit, detail: r.detail || '' };
    });

    const hits = results.filter((r) => r.hit);
    let score = hits.reduce((sum, r) => sum + r.weight, 0);
    score = Math.min(100, score);

    let verdict = 'safe';
    if (score >= 65) verdict = 'dangerous';
    else if (score >= 35) verdict = 'suspicious';

    const meta = {
      host: ctx.host,
      protocol: ctx.protocol.replace(':', '').toUpperCase(),
      tld: '.' + ctx.host.split('.').pop(),
      path: ctx.path || '/',
    };

    return {
      url: ctx.raw,
      isUrl: true,
      score,
      verdict,
      signals: results,
      meta,
      summary: buildSummary(verdict, hits),
      explanation: buildExplanation(verdict, hits, meta),
    };
  }

  function buildSummary(verdict, hits) {
    const top = hits.slice().sort((a, b) => b.weight - a.weight)[0];
    if (verdict === 'safe') {
      return hits.length
        ? 'Minor signals detected, but nothing that strongly indicates phishing.'
        : 'No phishing indicators found in this link.';
    }
    const lead = top ? `Key concern: ${top.label.toLowerCase()}.` : '';
    if (verdict === 'dangerous')
      return `This link shows strong signs of phishing or abuse. ${lead} Do not enter any personal data.`;
    return `This link has several suspicious traits and should be treated with caution. ${lead}`;
  }

  // Expose signal docs for the About page.
  function signalDocs() {
    return SIGNALS.map((s) => ({ label: s.label, weight: s.weight }));
  }

  return { analyze, signalDocs };
})();
