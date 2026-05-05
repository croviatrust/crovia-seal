/**
 * ChatGPT detector.
 *
 * STRATEGY: ChatGPT's web UI renders user messages with
 *   [data-message-author-role="user"]
 * and assistant messages with
 *   [data-message-author-role="assistant"]
 *
 * We observe the turn container. For each NEW assistant message that has
 * finished rendering (no typing cursor), we:
 *   1. Walk back to find the most recent preceding user message.
 *   2. Extract plain text from both.
 *   3. Attach a small "Seal" button at the bottom-right of the assistant bubble.
 *   4. On click: send to service worker, get Seal + CIM, inject CIM into the
 *      visible DOM text (invisible), flash a toast with seal_id.
 *
 * This script does NOT auto-seal. Emission requires a user click, because
 * auto-sealing every message would be noisy and might conflict with the
 * user's privacy expectations on some conversations.
 */
import type { SealOutputRequest, SealOutputResponse } from '../lib/messaging';

const SEAL_BTN_CLASS = 'crovia-seal-btn';
const SEAL_STATE_ATTR = 'data-crovia-seal-state';

function getAssistantText(el: HTMLElement): string {
  // ChatGPT renders markdown; the rendered plain text is typically in a
  // descendant `.markdown` div. Fallback: innerText of the bubble.
  const md = el.querySelector<HTMLElement>('.markdown');
  return (md ?? el).innerText.trim();
}

function findPrecedingUserMessage(assistantEl: HTMLElement): string | null {
  let cur: Element | null = assistantEl;
  while (cur) {
    cur = cur.previousElementSibling;
    if (!cur) break;
    if (cur instanceof HTMLElement && cur.querySelector('[data-message-author-role="user"]')) {
      const u = cur.querySelector<HTMLElement>('[data-message-author-role="user"]');
      return u?.innerText.trim() ?? null;
    }
  }
  // Fallback: look up the tree for the conversation container, then find
  // the most recent user message.
  const turn = assistantEl.closest('[data-testid^="conversation-turn-"]') as HTMLElement | null;
  if (!turn) return null;
  let prev = turn.previousElementSibling;
  while (prev) {
    const u = prev.querySelector('[data-message-author-role="user"]');
    if (u instanceof HTMLElement) return u.innerText.trim();
    prev = prev.previousElementSibling;
  }
  return null;
}

function toast(msg: string, kind: 'ok' | 'err' = 'ok'): void {
  const div = document.createElement('div');
  div.textContent = msg;
  div.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 2147483647;
    max-width: 320px; padding: 10px 14px; border-radius: 8px;
    font: 13px/1.4 -apple-system, system-ui, sans-serif;
    background: ${kind === 'ok' ? '#064e3b' : '#7f1d1d'};
    color: #ecfdf5; box-shadow: 0 6px 24px rgba(0,0,0,.3);
  `;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 4200);
}

async function onSealClick(assistantEl: HTMLElement, btn: HTMLElement): Promise<void> {
  btn.setAttribute(SEAL_STATE_ATTR, 'pending');
  btn.textContent = 'sealing...';
  const outputText = getAssistantText(assistantEl);
  const inputText = findPrecedingUserMessage(assistantEl) ?? '';
  if (!outputText) {
    toast('No text to seal', 'err');
    btn.setAttribute(SEAL_STATE_ATTR, 'err');
    btn.textContent = 'Seal';
    return;
  }
  const req: SealOutputRequest = {
    type: 'seal_output',
    inputText,
    outputText,
    generatorId: 'openai/chatgpt-web',
    generatorVersion: null as unknown as string,
    site: window.location.hostname,
  };
  try {
    const resp = await chrome.runtime.sendMessage<SealOutputRequest, SealOutputResponse>(req);
    if (!resp.ok || !resp.seal || !resp.cim) {
      toast(`Seal failed: ${resp.error ?? 'unknown'}`, 'err');
      btn.setAttribute(SEAL_STATE_ATTR, 'err');
      btn.textContent = 'Seal';
      return;
    }
    // Inject CIM directly into the last text node inside .markdown so the
    // zero-width chars live *inside* real content. Hosts like ChatGPT run
    // custom copy handlers that strip extension-injected spans; appending to
    // an existing Text node bypasses that class of stripping.
    const md = assistantEl.querySelector<HTMLElement>('.markdown') ?? assistantEl;
    const walker = document.createTreeWalker(md, NodeFilter.SHOW_TEXT, null);
    let last: Text | null = null;
    let node: Node | null;
    while ((node = walker.nextNode())) {
      if ((node as Text).data.length > 0) last = node as Text;
    }
    if (last) {
      last.data = last.data + resp.cim;
    } else {
      md.appendChild(document.createTextNode(resp.cim));
    }

    // Also stage the sealed text in the clipboard so a subsequent Ctrl+V
    // always carries the CIM, even against hostile copy handlers.
    const sealed = getAssistantText(assistantEl);
    try {
      await navigator.clipboard.writeText(sealed);
    } catch {
      /* clipboard perm may be denied; DOM injection still works. */
    }

    btn.setAttribute(SEAL_STATE_ATTR, 'ok');
    btn.textContent = `Sealed ${resp.seal.seal_id.slice(-8)} - copied`;
    toast(`Sealed: ${resp.seal.seal_id} (copied to clipboard)`, 'ok');
  } catch (e) {
    toast(`Seal error: ${(e as Error).message}`, 'err');
    btn.setAttribute(SEAL_STATE_ATTR, 'err');
    btn.textContent = 'Seal';
  }
}

function injectSealButton(assistantEl: HTMLElement): void {
  if (assistantEl.querySelector(`.${SEAL_BTN_CLASS}`)) return;
  const btn = document.createElement('button');
  btn.className = SEAL_BTN_CLASS;
  btn.type = 'button';
  btn.textContent = 'Seal';
  btn.title = 'Sigilla questa risposta con Crovia Seal';
  btn.style.cssText = `
    margin-top: 8px; padding: 4px 10px; font-size: 12px; font-weight: 600;
    background: #0f766e; color: #ecfdf5; border: 0; border-radius: 6px;
    cursor: pointer; user-select: none;
  `;
  btn.addEventListener('click', () => void onSealClick(assistantEl, btn));
  assistantEl.appendChild(btn);
}

function isFullyRendered(el: HTMLElement): boolean {
  // During streaming ChatGPT often keeps a cursor span alive. If any element
  // with role="presentation" has class matching "result-streaming" we wait.
  return !el.querySelector('.result-streaming, .cursor-blink');
}

export function attachChatGptDetector(): void {
  const obs = new MutationObserver(() => {
    const nodes = document.querySelectorAll<HTMLElement>(
      '[data-message-author-role="assistant"]',
    );
    nodes.forEach((n) => {
      if (!isFullyRendered(n)) return;
      injectSealButton(n);
    });
  });
  obs.observe(document.body, { childList: true, subtree: true });
  // eslint-disable-next-line no-console
  console.log('[crovia-seal] ChatGPT detector attached');
}
