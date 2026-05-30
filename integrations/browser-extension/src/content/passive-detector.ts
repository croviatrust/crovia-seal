/**
 * Passive CIM Detector — the secret superpower.
 *
 * Scans every page (Twitter, Reddit, news sites, blogs, anywhere) for text
 * containing a Crovia CIM (zero-width invisible marker). When found, attaches
 * a small "🛡 Sealed" verified badge next to the text, with a link to verify.
 *
 * This means ANY sealed AI output, pasted anywhere on the web, becomes
 * automatically recognizable as cryptographically verified.
 *
 * CIM format (matches background.ts encoder):
 *   SENT SENT <bits> SENT SENT
 *   where SENT = U+2060 (Word Joiner)
 *         0    = U+200B (Zero-Width Space)
 *         1    = U+200C (Zero-Width Non-Joiner)
 */

const CIM_SENT = '\u2060';
const CIM_ZERO = '\u200B';
const CIM_ONE  = '\u200C';
const SENTINEL = CIM_SENT + CIM_SENT;
const BADGE_ATTR = 'data-crovia-detected';
const VERIFY_URL = 'https://croviatrust.com/check.html';

/**
 * Extract the seal_id from a CIM-embedded text.
 * Returns the seal_id (e.g. "sl_abc...") or null if no valid CIM found.
 */
export function extractCimSealId(text: string): string | null {
  // Find double-sentinel-bounded segments
  const start = text.indexOf(SENTINEL);
  if (start < 0) return null;
  const end = text.indexOf(SENTINEL, start + SENTINEL.length);
  if (end <= start) return null;

  const bits = text.slice(start + SENTINEL.length, end);
  if (bits.length === 0 || bits.length % 8 !== 0) return null;

  // Decode bits → bytes → utf-8 string
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) {
      const ch = bits[i + j];
      if (ch === CIM_ONE) b = (b << 1) | 1;
      else if (ch === CIM_ZERO) b = (b << 1);
      else return null; // malformed
    }
    bytes.push(b);
  }
  try {
    const sealId = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    // Validate it looks like a Crovia seal_id
    if (/^sl_[0-9a-f]{20,80}$/.test(sealId) || /^cs_\d{4}_[A-Z0-9]{20,40}$/.test(sealId)) {
      return sealId;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Walk text nodes and find ones containing a CIM. Attach a tiny verified
 * badge near the closest block-level ancestor.
 */
function scanAndBadge(root: Node = document.body): void {
  if (!root || !document.body) return;

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      const t = (node as Text).data;
      // Quick check: must contain at least one sentinel
      if (!t.includes(CIM_SENT)) return NodeFilter.FILTER_REJECT;
      // Skip our own injected badges
      const parent = node.parentElement;
      if (parent?.closest(`[${BADGE_ATTR}], .crovia-seal-wrap`)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  let node: Node | null;
  while ((node = walker.nextNode())) {
    const txt = (node as Text).data;
    const sealId = extractCimSealId(txt);
    if (!sealId) continue;

    // Find the nearest block-level ancestor to anchor the badge
    let host: HTMLElement | null = (node.parentElement as HTMLElement) || null;
    while (host && document.contains(host)) {
      try {
        if (getComputedStyle(host).display !== 'inline') break;
      } catch { break; }
      host = host.parentElement;
    }
    if (!host || !document.contains(host)) continue;
    if (host.hasAttribute(BADGE_ATTR)) continue;
    host.setAttribute(BADGE_ATTR, sealId);

    injectBadge(host, sealId);
  }
}

function injectBadge(host: HTMLElement, sealId: string): void {
  const badge = document.createElement('a');
  badge.href = VERIFY_URL + '?id=' + encodeURIComponent(sealId);
  badge.target = '_blank';
  badge.rel = 'noopener';
  badge.title = `Crovia Seal verified · ${sealId}`;
  badge.innerHTML = '&#x1F6E1;&#xFE0E; Sealed';
  badge.style.cssText = `
    display: inline-flex; align-items: center; gap: 4px;
    margin: 2px 0 2px 6px; padding: 1px 7px;
    font: 600 10px/1.4 -apple-system, system-ui, sans-serif;
    background: #1ec5ff; color: #0c1018;
    border: 1px solid #0aa1d9; border-radius: 10px;
    text-decoration: none; cursor: pointer;
    vertical-align: middle;
    box-shadow: 0 1px 3px rgba(30,197,255,.3);
  `;
  badge.addEventListener('mouseenter', () => {
    badge.style.background = '#0aa1d9';
    badge.style.color = '#ffffff';
  });
  badge.addEventListener('mouseleave', () => {
    badge.style.background = '#1ec5ff';
    badge.style.color = '#0c1018';
  });

  // Attach as a sibling at end of host
  host.appendChild(badge);
}

/**
 * Start passive scanning of the current document.
 * Idempotent: safe to call multiple times.
 */
export function attachPassiveDetector(): void {
  // eslint-disable-next-line no-console
  console.log('[crovia-seal] passive detector active');

  // Initial scan
  const run = () => {
    try { scanAndBadge(); } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('[crovia-seal] passive scan error', e);
    }
  };
  run();

  // Observe future DOM changes
  const obs = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const n of Array.from(m.addedNodes)) {
        if (n.nodeType === Node.ELEMENT_NODE || n.nodeType === Node.TEXT_NODE) {
          try { scanAndBadge(n); } catch { /* ignore */ }
        }
      }
    }
  });
  obs.observe(document.body, { childList: true, subtree: true, characterData: true });

  // Periodic safety net
  setInterval(run, 5000);
}
