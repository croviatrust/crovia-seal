/**
 * Abstract host detector.
 *
 * Every AI chat UI (ChatGPT, Claude, Gemini, Perplexity) differs in the DOM
 * it produces, but the workflow that turns an answer into a Crovia Seal is
 * identical:
 *
 *     1. Observe the page for new assistant messages.
 *     2. Wait until they finish streaming (no cursor / "stop" button gone).
 *     3. Inject a "Seal" button at the bottom of each completed answer.
 *     4. On click: send (input_text, output_text) to the background worker,
 *        receive the Seal + CIM, inject the CIM into the rendered DOM text,
 *        and copy the sealed text to the clipboard so subsequent paste
 *        operations carry the invisible mark.
 *
 * This base class encodes the shared machinery. Subclasses supply only the
 * host-specific selectors and extraction functions (small `HostAdapter`
 * object). Any future host (Mistral Chat, HuggingChat, xAI Grok, ...) can
 * be added in ~20 lines.
 */
import type { SealOutputRequest, SealOutputResponse } from '../lib/messaging';

export interface HostAdapter {
  /** Short host label used for logs and the `generator_id` sent to the background. */
  readonly name: string;

  /** CSS selector matching every assistant message element on the page. */
  readonly assistantSelector: string;

  /** Return the plain-text content of an assistant element (without the Seal button). */
  extractAssistantText(el: HTMLElement): string;

  /** Find the user message immediately preceding `assistantEl`, or null. */
  findPrecedingUserText(assistantEl: HTMLElement): string | null;

  /** True once the element has finished streaming. */
  isFullyRendered(el: HTMLElement): boolean;

  /** Host-specific generator_id embedded in the Seal. */
  readonly generatorId: string;

  /**
   * Where to inject the CIM payload:
   * either append it to the LAST text node inside the assistant element
   * (default, maximizes copy survival), or a host-specific custom logic.
   */
  injectCim?: (assistantEl: HTMLElement, cim: string) => void;

  /** Where to append the Seal button (default: assistantEl itself). */
  buttonHost?: (assistantEl: HTMLElement) => HTMLElement;
}

const SEAL_BTN_CLASS = 'crovia-seal-btn';
const SEAL_STATE_ATTR = 'data-crovia-seal-state';

/**
 * Public entry point: call once per document with the adapter for the
 * current host.
 */
export function attachDetector(adapter: HostAdapter): void {
  const observe = () => {
    const nodes = document.querySelectorAll<HTMLElement>(adapter.assistantSelector);
    nodes.forEach((n) => {
      if (!adapter.isFullyRendered(n)) return;
      injectSealButton(n, adapter);
    });
  };
  const obs = new MutationObserver(observe);
  obs.observe(document.body, { childList: true, subtree: true });
  // Do an initial sweep so existing answers on page load are sealed-capable.
  observe();
  // eslint-disable-next-line no-console
  console.log(`[crovia-seal] ${adapter.name} detector attached`);
}

function injectSealButton(assistantEl: HTMLElement, adapter: HostAdapter): void {
  if (assistantEl.querySelector(`.${SEAL_BTN_CLASS}`)) return;
  const btn = document.createElement('button');
  btn.className = SEAL_BTN_CLASS;
  btn.type = 'button';
  btn.textContent = 'Seal';
  btn.title = `Sigilla questa risposta con Crovia Seal (${adapter.name})`;
  btn.style.cssText = `
    margin-top: 8px; padding: 4px 10px; font-size: 12px; font-weight: 600;
    background: #0f766e; color: #ecfdf5; border: 0; border-radius: 6px;
    cursor: pointer; user-select: none;
  `;
  btn.addEventListener('click', () => void onSealClick(assistantEl, btn, adapter));
  const host = adapter.buttonHost ? adapter.buttonHost(assistantEl) : assistantEl;
  host.appendChild(btn);
}

async function onSealClick(
  assistantEl: HTMLElement,
  btn: HTMLButtonElement,
  adapter: HostAdapter,
): Promise<void> {
  btn.setAttribute(SEAL_STATE_ATTR, 'pending');
  btn.textContent = 'sealing...';
  const outputText = adapter.extractAssistantText(assistantEl);
  const inputText = adapter.findPrecedingUserText(assistantEl) ?? '';
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
    generatorId: adapter.generatorId,
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
    if (adapter.injectCim) {
      adapter.injectCim(assistantEl, resp.cim);
    } else {
      defaultInjectCim(assistantEl, resp.cim);
    }
    try {
      await navigator.clipboard.writeText(adapter.extractAssistantText(assistantEl));
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

function defaultInjectCim(assistantEl: HTMLElement, cim: string): void {
  const walker = document.createTreeWalker(assistantEl, NodeFilter.SHOW_TEXT, null);
  let last: Text | null = null;
  let node: Node | null;
  while ((node = walker.nextNode())) {
    if ((node as Text).data.length > 0) last = node as Text;
  }
  if (last) {
    last.data = last.data + cim;
  } else {
    assistantEl.appendChild(document.createTextNode(cim));
  }
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
