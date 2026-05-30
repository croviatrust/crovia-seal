/**
 * Host adapters.
 *
 * Each adapter tells the generic detector-base HOW to find, extract, and
 * post-process messages on one specific site. Selectors are kept at the
 * top of each adapter so the inevitable DOM drift is a one-line fix.
 *
 * Robustness strategy (2026):
 *   - always prefer data-* attribute selectors over class names (stable)
 *   - provide deep fallback selector lists for each site
 *   - isFullyRendered checks MULTIPLE streaming signals in order of reliability
 *   - extractAssistantText probes multiple descendants before falling back to
 *     the whole bubble's innerText
 *   - buttonHost tries multiple anchor strategies before returning the el itself
 *   - all adapters log diagnostics via [crovia-seal:<name>] console prefix
 */
import type { HostAdapter } from './detector-base';

// ── selector list helpers ─────────────────────────────────────────────────────

/** Try each selector in order; return the first matching element or null. */
function firstMatch(root: Element | Document, selectors: string[]): HTMLElement | null {
  for (const s of selectors) {
    try {
      const el = root.querySelector<HTMLElement>(s);
      if (el) return el;
    } catch { /* invalid selector for this browser version */ }
  }
  return null;
}

/** Build a combined CSS selector string from an array (joined with ", "). */
function join(...selectors: string[]): string {
  return selectors.join(', ');
}

// ----------------------------------------------------------------------
// ChatGPT (chatgpt.com, chat.openai.com)
// ----------------------------------------------------------------------

export const chatgpt: HostAdapter = {
  name: 'ChatGPT',
  generatorId: 'openai/chatgpt-web',
  // data-message-author-role="assistant" is canonical; the rest are layered
  // fallbacks for recent layout rewrites (2025 "canvas" UI, 2026 "4o" UI).
  assistantSelector: join(
    '[data-message-author-role="assistant"]',
    'article[data-testid^="conversation-turn-"] .agent-turn',
    'article .agent-turn',
    'div.agent-turn',
    'article[data-testid^="conversation-turn-"] [data-message-author-role="assistant"]',
  ),
  extractAssistantText(el) {
    const inner = firstMatch(el, ['.markdown', '.markdown-body', '.prose', '[class*="prose"]']);
    return (inner ?? el).innerText.trim();
  },
  findPrecedingUserText(el) {
    const turn = el.closest<HTMLElement>(
      'article[data-testid^="conversation-turn-"], [data-testid^="conversation-turn-"]',
    );
    if (turn) {
      let prev = turn.previousElementSibling;
      while (prev) {
        const u = firstMatch(prev, [
          '[data-message-author-role="user"]',
          '.user-turn',
          '[data-testid="user-message"]',
        ]);
        if (u) return u.innerText.trim();
        prev = prev.previousElementSibling;
      }
    }
    return fallbackPreviousUser(el, '[data-message-author-role="user"], .user-turn, [data-testid="user-message"]');
  },
  isFullyRendered(el) {
    return !el.querySelector('.result-streaming, .cursor-blink, [data-is-streaming="true"]');
  },
  buttonHost(assistantEl) {
    const turn =
      assistantEl.closest<HTMLElement>('article[data-testid^="conversation-turn-"]') ||
      assistantEl.closest<HTMLElement>('[data-testid^="conversation-turn-"]') ||
      assistantEl.parentElement?.parentElement ||
      assistantEl;
    const anyActionBtn = firstMatch(turn, [
      'button[data-testid$="-turn-action-button"]',
      'button[data-testid="copy-turn-action-button"]',
      'button[aria-label="Copy"]',
      'button[data-testid*="copy"]',
    ]);
    if (anyActionBtn?.parentElement) return anyActionBtn.parentElement as HTMLElement;
    const toolbar = firstMatch(turn, [
      'div.flex.items-center.gap-1',
      'div.flex.justify-start',
      'div[class*="actions"]',
      'div[class*="toolbar"]',
    ]);
    if (toolbar && toolbar.querySelectorAll('button').length >= 1) return toolbar;
    return assistantEl;
  },
};

// ----------------------------------------------------------------------
// Claude (claude.ai)
// ----------------------------------------------------------------------

// Selector confirmed via live DOM diagnostic on claude.ai (May 2026):
//   The message container is: div[data-is-streaming]  (class: "group relative relative pb-3")
//   data-is-streaming="false" = fully rendered assistant message
//   data-is-streaming="true"  = still streaming
// Legacy selectors kept as fallback for older Claude UI versions.
const CLAUDE_ASSISTANT_SELECTORS = [
  // PRIMARY (confirmed 2026): div with data-is-streaming attribute = assistant message container
  'div[data-is-streaming="false"]',
  'div[data-is-streaming="true"]',
  // Legacy 2024 fallbacks
  'div.font-claude-message',
  // data-testid fallbacks (may appear in future versions)
  '[data-testid="assistant-message"]',
];

export const claude: HostAdapter = {
  name: 'Claude',
  generatorId: 'anthropic/claude-web',
  assistantSelector: join(...CLAUDE_ASSISTANT_SELECTORS),
  extractAssistantText(el) {
    // Claude 2026: the data-is-streaming div IS the message container.
    // Inner content may be in a .prose or .grid-cols-1 child, or directly in el.
    const inner = firstMatch(el, [
      '.prose',
      '.grid-cols-1',
      '[class*="prose"]',
      '[class*="message-content"]',
    ]);
    const text = (inner ?? el).innerText.trim();
    return text;
  },
  findPrecedingUserText(el) {
    return fallbackPreviousUser(el, join(
      '[data-testid="user-message"]',
      '[data-testid="human-message"]',
      '[data-testid^="message-human"]',
      '.font-user-message',
      '[class*="user-message"]',
    ));
  },
  isFullyRendered(el) {
    // data-is-streaming is the canonical signal; also check for any loading
    // spinner or cursor that Anthropic uses in newer UI revisions.
    const streaming = el.getAttribute('data-is-streaming');
    if (streaming === 'true') return false;
    // Check parent/ancestor for streaming state (v2+ wraps multiple elements)
    const turnAncestor = el.closest<HTMLElement>('[data-is-streaming]');
    if (turnAncestor && turnAncestor.getAttribute('data-is-streaming') === 'true') return false;
    // Extra: no loading spinner or blinking cursor inside
    if (el.querySelector('[data-testid="loading-indicator"], .loading-indicator, .cursor-blink')) return false;
    return true;
  },
  buttonHost(assistantEl) {
    // Claude 2026: action-bar-copy is a sibling element near the streaming div,
    // not a descendant. Walk up to find the shared parent, then scan for it.
    const parent = assistantEl.parentElement;
    if (parent) {
      // Look for the action bar copy button in the parent scope
      const copyBtn = firstMatch(parent, [
        'button[data-testid="action-bar-copy"]',
        'button[aria-label="Copy"]',
      ]);
      if (copyBtn?.parentElement) return copyBtn.parentElement as HTMLElement;
      // Check grandparent too (one level deeper nesting)
      const gp = parent.parentElement;
      if (gp) {
        const copyBtn2 = firstMatch(gp, [
          'button[data-testid="action-bar-copy"]',
          'button[aria-label="Copy"]',
        ]);
        if (copyBtn2?.parentElement) return copyBtn2.parentElement as HTMLElement;
      }
    }
    return assistantEl;
  },
};

// ----------------------------------------------------------------------
// Gemini (gemini.google.com)
// ----------------------------------------------------------------------

// Gemini uses Angular custom elements. Observed across versions:
//   v1 (2024):  <model-response>  with  <message-content>  inside
//   v2 (2025):  <ms-cmark-node>  or  <response-container>  variants
//   v3 (2026):  custom elements may still be present; also data-chunk-id attrs
const GEMINI_ASSISTANT_SELECTORS = [
  // Most stable custom elements
  'model-response',
  'response-container',
  // Fallback: any element with a state="done" or similar
  '[data-response-id]',
  '[data-chunk-id]',
  // Generic large prose block heuristic (last resort)
  'message-content',
];

export const gemini: HostAdapter = {
  name: 'Gemini',
  generatorId: 'google/gemini-web',
  assistantSelector: join(...GEMINI_ASSISTANT_SELECTORS),
  extractAssistantText(el) {
    const inner = firstMatch(el, [
      'message-content',
      'ms-cmark-node',
      '.markdown',
      '[class*="response-text"]',
      '[class*="message-body"]',
    ]);
    const text = (inner ?? el).innerText.trim();
    // eslint-disable-next-line no-console
    console.debug('[crovia-seal:Gemini] extract len=' + text.length);
    return text;
  },
  findPrecedingUserText(el) {
    // Walk backwards over siblings looking for the user query element.
    let prev: Element | null = el.previousElementSibling;
    while (prev) {
      const tag = prev.tagName.toLowerCase();
      if (tag === 'user-query') {
        const t = firstMatch(prev, [
          '.query-text',
          '.user-query-container',
          '[class*="query-text"]',
          'p',
        ]);
        return (t ?? (prev as HTMLElement)).innerText.trim();
      }
      // Newer layout may use a div wrapper instead of custom element
      const inner = firstMatch(prev, [
        'user-query',
        '[data-testid="user-query"]',
        '[class*="user-query"]',
        '[class*="human-turn"]',
      ]);
      if (inner) return inner.innerText.trim();
      prev = prev.previousElementSibling;
    }
    return fallbackPreviousUser(el, 'user-query, [class*="user-query"], [class*="human-turn"]');
  },
  isFullyRendered(el) {
    // Gemini sets state="streaming" on the host custom element during generation.
    if (el.getAttribute('state') === 'streaming') return false;
    // Also check for loading spinners inside (newer UI uses mat-spinner or similar)
    if (el.querySelector('mat-spinner, [class*="spinner"], [class*="loading"]')) return false;
    // Check children of response container
    const rc = el.querySelector('[state="streaming"]');
    if (rc) return false;
    return true;
  },
  buttonHost(el) {
    return firstMatch(el, [
      '.response-footer',
      '.actions-container',
      'message-actions',
      '[class*="action"]',
      '[class*="footer"]',
      '[class*="toolbar"]',
    ]) ?? el;
  },
};

// ----------------------------------------------------------------------
// Perplexity (www.perplexity.ai, perplexity.ai)
// ----------------------------------------------------------------------

// Perplexity has had several DOM overhauls. Observed selectors:
//   v1 (2024):  [data-testid="answer"]  +  .prose
//   v2 (2025):  [data-testid="answer-block"]  or  [data-testid="response"]
//   v3 (2026):  [data-message-type="assistant"]  or generic large prose blocks
const PERPLEXITY_ASSISTANT_SELECTORS = [
  '[data-testid="answer"]',
  '[data-testid="answer-block"]',
  '[data-testid="response"]',
  '[data-testid^="answer"]',
  '[data-message-type="assistant"]',
  '[data-message-role="assistant"]',
  // Structural: the main prose block in a search result
  'div[class*="answer"] .prose',
  '.prose',
];

export const perplexity: HostAdapter = {
  name: 'Perplexity',
  generatorId: 'perplexity/pplx-web',
  assistantSelector: join(...PERPLEXITY_ASSISTANT_SELECTORS),
  extractAssistantText(el) {
    const inner = firstMatch(el, ['.prose', '[class*="prose"]', '[class*="answer-text"]']);
    const text = (inner ?? el).innerText.trim();
    // eslint-disable-next-line no-console
    console.debug('[crovia-seal:Perplexity] extract len=' + text.length);
    return text;
  },
  findPrecedingUserText(el) {
    return fallbackPreviousUser(el, join(
      '[data-testid="question"]',
      '[data-testid="search-title"]',
      '[data-testid^="question"]',
      '[data-message-type="human"]',
      '[data-message-role="user"]',
      '.search-title',
      'h1',
    ));
  },
  isFullyRendered(el) {
    // Loading indicator during streaming
    if (el.querySelector('[data-testid="answer-loading"], [class*="loading"], [class*="spinner"]')) return false;
    // Also check for a pulsing cursor or streaming class
    if (el.querySelector('.result-streaming, [class*="streaming"]')) return false;
    return true;
  },
  buttonHost(el) {
    return firstMatch(el, [
      '[class*="action"]',
      '[class*="toolbar"]',
      '[class*="controls"]',
      '[class*="footer"]',
    ]) ?? el;
  },
};

// ----------------------------------------------------------------------
// Shared helper
// ----------------------------------------------------------------------

function fallbackPreviousUser(el: HTMLElement, selector: string): string | null {
  // Walk up the DOM tree scanning previous siblings at each level.
  let cur: Element | null = el;
  for (let i = 0; i < 8 && cur; i++) {
    let prev = cur.previousElementSibling;
    while (prev) {
      try {
        const match = prev.matches(selector)
          ? (prev as HTMLElement)
          : prev.querySelector<HTMLElement>(selector);
        if (match) return match.innerText.trim();
      } catch { /* invalid selector */ }
      prev = prev.previousElementSibling;
    }
    cur = cur.parentElement;
  }
  return null;
}
