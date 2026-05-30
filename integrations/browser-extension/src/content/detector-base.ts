/**
 * Abstract host detector.
 *
 * Workflow:
 *   1. Observe the page for new assistant messages.
 *   2. Wait until they finish streaming.
 *   3. Inject a compact "Seal" pill at the bottom of each completed answer.
 *   4. On click: POST to seal.croviatrust.com/v1/sign, get the Seal + CIM,
 *      write sealed text (output + CIM) to clipboard, show seal card.
 */
import type { SealOutputRequest, SealOutputResponse } from '../lib/messaging';

export interface HostAdapter {
  readonly name: string;
  readonly assistantSelector: string;
  extractAssistantText(el: HTMLElement): string;
  findPrecedingUserText(assistantEl: HTMLElement): string | null;
  isFullyRendered(el: HTMLElement): boolean;
  readonly generatorId: string;
  injectCim?: (assistantEl: HTMLElement, cim: string) => void;
  buttonHost?: (assistantEl: HTMLElement) => HTMLElement;
}

const PROCESSED_ATTR = 'data-crovia-processed';

/**
 * Public entry point: call once per document with the adapter for the
 * current host.
 */
export function attachDetector(adapter: HostAdapter): void {
  // eslint-disable-next-line no-console
  console.log(`[crovia-seal] ${adapter.name} detector starting`);

  const observe = () => {
    const raw = Array.from(document.querySelectorAll<HTMLElement>(adapter.assistantSelector));
    // Deduplicate: keep only the most specific (innermost) match per message
    const nodes = raw.filter((el) => {
      return !raw.some(other => other !== el && other.contains(el));
    });
    nodes.forEach((n) => {
      if (n.hasAttribute(PROCESSED_ATTR)) return;
      if (n.closest(`[${PROCESSED_ATTR}]`)) return;
      if (!adapter.isFullyRendered(n)) return;
      n.setAttribute(PROCESSED_ATTR, '1');
      injectWhenToolbarReady(n, adapter);
    });
  };
  const obs = new MutationObserver(observe);
  obs.observe(document.body, { childList: true, subtree: true });
  observe();
  setInterval(observe, 3000);
  // eslint-disable-next-line no-console
  console.log(`[crovia-seal] ${adapter.name} detector attached`);
}

// ────────── UI: Seal button (native-toolbar style) ──────────

/**
 * The native action toolbar on ChatGPT/Claude often appears a moment AFTER
 * the message is "fully rendered". We watch for it locally for up to 5s
 * before injecting. If it never appears, fall back to a floating pill.
 */
function injectWhenToolbarReady(assistantEl: HTMLElement, adapter: HostAdapter): void {
  const tryInject = (): boolean => {
    const host = adapter.buttonHost ? adapter.buttonHost(assistantEl) : assistantEl;
    const isNativeToolbar = isToolbarLike(host, assistantEl);
    injectSealButton(assistantEl, adapter, host, isNativeToolbar);
    return true; // always succeed once attempted
  };

  // Best case: toolbar is already there
  const host0 = adapter.buttonHost ? adapter.buttonHost(assistantEl) : assistantEl;
  if (isToolbarLike(host0, assistantEl)) {
    injectSealButton(assistantEl, adapter, host0, true);
    return;
  }

  // Otherwise: observe for up to 5s; inject as soon as we see a toolbar.
  let injected = false;
  const localObs = new MutationObserver(() => {
    if (injected) return;
    const host = adapter.buttonHost ? adapter.buttonHost(assistantEl) : assistantEl;
    if (isToolbarLike(host, assistantEl)) {
      injected = true;
      localObs.disconnect();
      injectSealButton(assistantEl, adapter, host, true);
    }
  });
  const root =
    assistantEl.closest<HTMLElement>('article, [data-testid^="conversation-turn-"]') ||
    assistantEl.parentElement || assistantEl;
  localObs.observe(root, { childList: true, subtree: true });

  setTimeout(() => {
    if (injected) return;
    injected = true;
    localObs.disconnect();
    // Fallback: append our own visible pill at the end of the message
    tryInject();
  }, 5000);
}

/**
 * Heuristic: a "toolbar-like" host is one that already contains at least one
 * native <button> sibling (Copy / Like / Regenerate / …). We attach to such
 * a host with native-mimicking styling, so the user perceives a single,
 * coherent action bar.
 */
function isToolbarLike(host: HTMLElement, assistantEl: HTMLElement): boolean {
  if (host === assistantEl) return false;
  const btns = host.querySelectorAll('button');
  return btns.length >= 1;
}

function injectSealButton(
  assistantEl: HTMLElement,
  adapter: HostAdapter,
  host: HTMLElement,
  nativeStyle: boolean,
): void {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'crovia-seal-btn';
  btn.title = 'Seal this AI output (Crovia Seal)';
  btn.setAttribute('aria-label', 'Seal with Crovia');
  btn.innerHTML = sealIconSVG() + '<span class="crovia-seal-label">Seal</span>';

  if (nativeStyle) {
    // Native-toolbar style: ghost icon button, mimics Copy/Like/etc.
    btn.style.cssText = `
      display: inline-flex; align-items: center; gap: 4px;
      padding: 6px 8px; min-height: 28px;
      font: 600 12.5px/1 -apple-system,system-ui,'Segoe UI',sans-serif;
      background: transparent; color: inherit;
      border: 0; border-radius: 6px; cursor: pointer;
      opacity: .75; transition: opacity .15s, background .15s, color .15s;
      vertical-align: middle;
    `;
    btn.addEventListener('mouseenter', () => {
      if (btn.dataset.sealed) return;
      btn.style.opacity = '1';
      btn.style.background = 'rgba(127,127,127,.12)';
      btn.style.color = '#0aa1d9';
    });
    btn.addEventListener('mouseleave', () => {
      if (btn.dataset.sealed) return;
      btn.style.opacity = '.75';
      btn.style.background = 'transparent';
      btn.style.color = 'inherit';
    });
  } else {
    // Fallback floating pill when no native toolbar was found
    btn.style.cssText = `
      display: inline-flex; align-items: center; gap: 5px;
      margin-top: 10px;
      padding: 6px 14px; font: 700 12px -apple-system,system-ui,sans-serif;
      background: #1ec5ff; color: #0c1018;
      border: 1px solid #1ec5ff; border-radius: 16px;
      cursor: pointer; box-shadow: 0 1px 6px rgba(30,197,255,.35);
    `;
  }

  btn.addEventListener('click', () => void onSealClick(assistantEl, btn, adapter));
  host.appendChild(btn);
}

function sealIconSVG(): string {
  // 16px shield icon — color inherits via currentColor
  return (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
    '</svg>'
  );
}

// ────────── Seal Flow ──────────

async function onSealClick(
  assistantEl: HTMLElement,
  btn: HTMLButtonElement,
  adapter: HostAdapter,
): Promise<void> {
  if (btn.dataset.sealed) return; // already sealed
  const labelEl = btn.querySelector<HTMLElement>('.crovia-seal-label');
  setBtnLabel(btn, labelEl, 'Sealing…');
  btn.style.cursor = 'wait';
  btn.style.opacity = '.6';

  const outputText = adapter.extractAssistantText(assistantEl);
  const inputText = adapter.findPrecedingUserText(assistantEl) ?? '';
  if (!outputText) {
    toast('No text to seal', 'err');
    resetButton(btn, labelEl);
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

  // Pre-flight: extension context might be invalidated after a reload
  if (typeof chrome === 'undefined' || !chrome.runtime?.id) {
    showStaleContextHint(btn, labelEl);
    return;
  }

  let resp: SealOutputResponse;
  try {
    resp = await chrome.runtime.sendMessage<SealOutputRequest, SealOutputResponse>(req);
  } catch (err) {
    const msg = (err as Error).message || '';
    if (msg.includes('Extension context invalidated') ||
        msg.includes('message channel closed') ||
        msg.includes('receiving end does not exist')) {
      showStaleContextHint(btn, labelEl);
      return;
    }
    toast(`Error: ${msg || 'connection failed'}`, 'err');
    resetButton(btn, labelEl);
    return;
  }

  try {
    if (!resp.ok || !resp.seal || !resp.cim) {
      toast(`Seal failed: ${resp.error ?? 'unknown error'}`, 'err');
      resetButton(btn, labelEl);
      return;
    }

    const sealId = resp.seal.seal_id;
    // Visible tagline: a single line ANYONE can see and click to verify.
    // The invisible CIM remains as a forensic backup (some platforms strip
    // zero-width chars, but plain URLs always survive copy/paste).
    const tagline = `\n\n\u2014 sealed: croviatrust.com/v/${sealId} \u2713`;
    // CIM goes BEFORE the tagline so that stripping from '— sealed:' to end
    // removes both the tagline and any trailing zero-width chars cleanly.
    const sealedText = outputText + resp.cim + tagline;

    // Inject visible tagline + invisible CIM into DOM (for Ctrl+C from page)
    appendVisibleTagline(assistantEl, sealId);
    if (adapter.injectCim) {
      adapter.injectCim(assistantEl, resp.cim);
    } else {
      defaultInjectCim(assistantEl, resp.cim);
    }

    // Write sealed text to clipboard (output + visible tagline + invisible CIM).
    // Use two strategies: modern Clipboard API first, execCommand fallback second.
    // NOTE: ChatGPT has a custom Ctrl+C handler that strips zero-width chars.
    // The ONLY reliable path is this programmatic clipboard write on seal click.
    let clipboardOk = false;
    try {
      await navigator.clipboard.writeText(sealedText);
      clipboardOk = true;
    } catch {
      // Fallback: create hidden textarea, select, execCommand
      try {
        const ta = document.createElement('textarea');
        ta.value = sealedText;
        ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        clipboardOk = document.execCommand('copy');
        ta.remove();
      } catch { /* ignore */ }
    }

    // Update button to sealed state — checkmark + green tint
    btn.dataset.sealed = '1';
    btn.dataset.sealId = sealId;
    btn.style.color = '#16a34a';
    btn.style.opacity = '1';
    btn.style.cursor = 'pointer';
    setBtnIcon(btn, checkIconSVG());
    setBtnLabel(btn, labelEl, 'Sealed');
    btn.title = `Sealed: ${sealId} — click to copy ID, or right-click to verify`;

    // Click again on a sealed button → re-copy the full sealed text
    btn.addEventListener('click', async (e) => {
      if (!btn.dataset.sealed) return;
      e.preventDefault();
      try {
        await navigator.clipboard.writeText(sealedText);
        toast(`Sealed text re-copied · ${sealId.slice(0, 12)}…`, 'ok');
      } catch { /* ignore */ }
    });

    // One unobtrusive toast — grandmother gets a clear confirmation
    toast(clipboardOk
      ? `Sealed ✓ — copied to clipboard. Paste anywhere as proof.`
      : `Sealed ✓ — click the Seal button again to copy text with proof.`,
    'ok');

  } catch (e) {
    toast(`Error: ${(e as Error).message}`, 'err');
    resetButton(btn, labelEl);
  }
}

function setBtnIcon(btn: HTMLButtonElement, svg: string): void {
  const old = btn.querySelector('svg');
  if (old) {
    const tpl = document.createElement('template');
    tpl.innerHTML = svg;
    old.replaceWith(tpl.content);
  }
}

function setBtnLabel(btn: HTMLButtonElement, labelEl: HTMLElement | null, text: string): void {
  if (labelEl) labelEl.textContent = text;
}

function checkIconSVG(): string {
  return (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="20 6 9 17 4 12"/>' +
    '</svg>'
  );
}

function resetButton(btn: HTMLButtonElement, labelEl: HTMLElement | null): void {
  setBtnIcon(btn, sealIconSVG());
  setBtnLabel(btn, labelEl, 'Seal');
  btn.style.color = 'inherit';
  btn.style.opacity = '.75';
  btn.style.cursor = 'pointer';
}

/**
 * Called when the extension was reloaded but this page is still on an
 * old content-script. We can no longer talk to the background. Make the
 * button useful: turn it into a "Reload" CTA and show one clear toast.
 */
function showStaleContextHint(btn: HTMLButtonElement, labelEl: HTMLElement | null): void {
  setBtnIcon(btn, reloadIconSVG());
  setBtnLabel(btn, labelEl, 'Reload');
  btn.style.color = '#dc2626';
  btn.style.opacity = '1';
  btn.style.cursor = 'pointer';
  btn.title = 'Crovia Seal was updated. Click to reload this page.';
  btn.onclick = () => window.location.reload();
  toast('Crovia Seal was updated — click "Reload" to reactivate.', 'err');
}

function reloadIconSVG(): string {
  return (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="23 4 23 10 17 10"/>' +
    '<path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>' +
    '</svg>'
  );
}

// ────────── Visible tagline injection ──────────

/**
 * Append a small, visible "— sealed: croviatrust.com/v/<id> ✓" line to the
 * end of the assistant message. The line is plain text (not styled link)
 * so it survives Ctrl+C copy as readable text. Idempotent: refuses to add
 * a second tagline to the same message.
 */
function appendVisibleTagline(assistantEl: HTMLElement, sealId: string): void {
  if (assistantEl.querySelector('.crovia-tagline')) return;
  const wrap = document.createElement('div');
  wrap.className = 'crovia-tagline';
  wrap.style.cssText = `
    margin-top: 14px; padding-top: 10px;
    border-top: 1px dashed rgba(127,127,127,.35);
    font: 500 12.5px ui-monospace,Menlo,Consolas,monospace;
    color: rgba(127,127,127,.85);
    user-select: text;
  `;
  // Build as plain text so Ctrl+C captures the readable URL
  const url = `croviatrust.com/v/${sealId}`;
  const prefix = document.createTextNode('— sealed: ');
  const link = document.createElement('a');
  link.href = `https://${url}`;
  link.target = '_blank';
  link.rel = 'noopener';
  link.textContent = url;
  link.style.cssText = `
    color: #0aa1d9; text-decoration: underline; font: inherit;
  `;
  const suffix = document.createTextNode(' \u2713');
  wrap.appendChild(prefix);
  wrap.appendChild(link);
  wrap.appendChild(suffix);
  assistantEl.appendChild(wrap);
}

// ────────── CIM DOM injection ──────────

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

// ────────── Toast ──────────

function toast(msg: string, kind: 'ok' | 'err' = 'ok'): void {
  const div = document.createElement('div');
  div.textContent = msg;
  div.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 2147483647;
    max-width: 360px; padding: 10px 16px; border-radius: 8px;
    font: 13px/1.4 -apple-system, system-ui, sans-serif;
    background: ${kind === 'ok' ? '#1ec5ff' : '#dc2626'};
    border: 1px solid ${kind === 'ok' ? '#0aa1d9' : '#ef4444'};
    color: ${kind === 'ok' ? '#0c1018' : '#ffffff'};
    font-weight: 600;
    box-shadow: 0 6px 24px rgba(0,0,0,.4);
    animation: crovia-fade-in .2s ease;
  `;
  document.body.appendChild(div);
  setTimeout(() => {
    div.style.opacity = '0';
    div.style.transition = 'opacity .3s';
    setTimeout(() => div.remove(), 300);
  }, 3500);
}
