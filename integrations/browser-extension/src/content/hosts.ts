/**
 * Host adapters.
 *
 * Each adapter tells the generic detector-base HOW to find, extract, and
 * post-process messages on one specific site. Selectors are kept at the
 * top of each adapter so the inevitable DOM drift is a one-line fix.
 *
 * Robustness strategy:
 *   - we always prefer attribute selectors (data-*) over class names
 *   - we fall back to innerText on the whole bubble when a markdown
 *     descendant selector misses (sites evolve)
 *   - `isFullyRendered` uses absence of a streaming indicator; if in doubt
 *     we treat the message as NOT ready (fail-safe: worst case the user
 *     clicks Seal a second later)
 */
import type { HostAdapter } from './detector-base';

// ----------------------------------------------------------------------
// ChatGPT (chatgpt.com, chat.openai.com)
// ----------------------------------------------------------------------

export const chatgpt: HostAdapter = {
  name: 'ChatGPT',
  generatorId: 'openai/chatgpt-web',
  assistantSelector: '[data-message-author-role="assistant"]',
  extractAssistantText(el) {
    const md = el.querySelector<HTMLElement>('.markdown');
    return (md ?? el).innerText.trim();
  },
  findPrecedingUserText(el) {
    const turn = el.closest('[data-testid^="conversation-turn-"]') as HTMLElement | null;
    if (!turn) return fallbackPreviousUser(el, '[data-message-author-role="user"]');
    let prev = turn.previousElementSibling;
    while (prev) {
      const u = prev.querySelector('[data-message-author-role="user"]');
      if (u instanceof HTMLElement) return u.innerText.trim();
      prev = prev.previousElementSibling;
    }
    return null;
  },
  isFullyRendered(el) {
    return !el.querySelector('.result-streaming, .cursor-blink');
  },
};

// ----------------------------------------------------------------------
// Claude (claude.ai)
// ----------------------------------------------------------------------

export const claude: HostAdapter = {
  name: 'Claude',
  generatorId: 'anthropic/claude-web',
  // Claude marks assistant messages with data-test-render-count or
  // className "font-claude-message"; the attribute-based one is more stable.
  assistantSelector: 'div[data-is-streaming="false"].font-claude-message, div.font-claude-message',
  extractAssistantText(el) {
    // Claude renders markdown into a direct child with class "grid-cols-1".
    const inner = el.querySelector<HTMLElement>('.grid-cols-1') ?? el;
    return inner.innerText.trim();
  },
  findPrecedingUserText(el) {
    // Claude's user turns are `data-testid="user-message"` OR simply the
    // nearest sibling that contains `.font-user-message`.
    return fallbackPreviousUser(el, '[data-testid="user-message"], .font-user-message');
  },
  isFullyRendered(el) {
    // When streaming, Claude sets `data-is-streaming="true"`.
    const attr = el.getAttribute('data-is-streaming');
    return attr === null || attr === 'false';
  },
};

// ----------------------------------------------------------------------
// Gemini (gemini.google.com)
// ----------------------------------------------------------------------

export const gemini: HostAdapter = {
  name: 'Gemini',
  generatorId: 'google/gemini-web',
  // Gemini uses custom elements; <message-content> inside <model-response>.
  assistantSelector: 'model-response',
  extractAssistantText(el) {
    const inner = el.querySelector<HTMLElement>('message-content, .markdown') ?? el;
    return inner.innerText.trim();
  },
  findPrecedingUserText(el) {
    // Gemini's user turn is <user-query> with a `.query-text` inside.
    let prev: Element | null = el.previousElementSibling;
    while (prev) {
      if (prev.tagName.toLowerCase() === 'user-query') {
        const t = prev.querySelector<HTMLElement>('.query-text, .user-query-container');
        if (t) return t.innerText.trim();
        return (prev as HTMLElement).innerText.trim();
      }
      prev = prev.previousElementSibling;
    }
    return fallbackPreviousUser(el, 'user-query');
  },
  isFullyRendered(el) {
    // Gemini toggles `.response-container` with `.response-container-content`
    // + attribute `state="streaming"` on the host element during generation.
    const state = el.getAttribute('state');
    return state !== 'streaming';
  },
  buttonHost(el) {
    // Gemini's `model-response` is a shadow-less custom element; appending
    // directly to it is fine but we prefer the action-bar footer when present.
    return (el.querySelector<HTMLElement>('.response-footer, .actions-container') as HTMLElement) ?? el;
  },
};

// ----------------------------------------------------------------------
// Perplexity (www.perplexity.ai)
// ----------------------------------------------------------------------

export const perplexity: HostAdapter = {
  name: 'Perplexity',
  generatorId: 'perplexity/pplx-web',
  // Perplexity renders answers inside a div with `data-testid="answer"`.
  // Fallback: any `.prose` within the main column.
  assistantSelector: '[data-testid="answer"], .prose',
  extractAssistantText(el) {
    return el.innerText.trim();
  },
  findPrecedingUserText(el) {
    // The user's question lives in `[data-testid="question"]` or a preceding
    // `h1`/`h2` "search-title" element.
    return fallbackPreviousUser(
      el,
      '[data-testid="question"], .search-title, [data-testid="search-title"]',
    );
  },
  isFullyRendered(el) {
    // When streaming, Perplexity shows a loader spinner with
    // `[data-testid="answer-loading"]` inside the answer element.
    return !el.querySelector('[data-testid="answer-loading"]');
  },
};

// ----------------------------------------------------------------------
// Shared helper
// ----------------------------------------------------------------------

function fallbackPreviousUser(el: HTMLElement, selector: string): string | null {
  // Walk up until we find a container, then scan its previous siblings.
  let cur: Element | null = el;
  for (let i = 0; i < 8 && cur; i++) {
    let prev = cur.previousElementSibling;
    while (prev) {
      const match = prev.matches(selector)
        ? (prev as HTMLElement)
        : prev.querySelector<HTMLElement>(selector);
      if (match) return match.innerText.trim();
      prev = prev.previousElementSibling;
    }
    cur = cur.parentElement;
  }
  return null;
}
