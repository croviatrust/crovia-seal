/**
 * Universal Verifier - drag / paste any text, extract CIMs, optionally
 * verify a raw Seal JSON. Runs entirely in the extension page context.
 */
import { extractAllCims, containsCimMarker } from '../lib/stego';
import type { VerifySealRequest, VerifySealResponse } from '../lib/messaging';

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]!));
}

function renderVerdict(
  kind: 'ok' | 'warn' | 'err',
  label: string,
  kv: Array<[string, string]>,
  errors: string[] = [],
): string {
  const kvRows = kv
    .map(([k, v]) => `<div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div>`)
    .join('');
  const errList = errors.length
    ? `<ul class="error-list">${errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul>`
    : '';
  return `
    <span class="verdict ${kind}">${escapeHtml(label)}</span>
    <div class="kv">${kvRows}</div>
    ${errList}
  `;
}

async function analyzeText(text: string): Promise<void> {
  const results = $('results');
  const body = $('result-body');
  results.hidden = false;

  if (!text.trim()) {
    body.innerHTML = renderVerdict('warn', 'no input', [['status', 'provide some text to analyze']]);
    return;
  }

  const hasMarker = containsCimMarker(text);
  const cims = extractAllCims(text);

  if (cims.length === 0) {
    if (hasMarker) {
      body.innerHTML = renderVerdict('err', 'mark corrupted', [
        ['length', `${text.length} chars`],
        ['status', 'CIM start-marker present but CRC invalid or truncated'],
      ]);
    } else {
      body.innerHTML = renderVerdict('warn', 'no crovia mark', [
        ['length', `${text.length} chars`],
        ['status', 'text contains no Crovia Invisible Mark'],
      ]);
    }
    return;
  }

  const parts = cims.map((c, i) => {
    return `
      <div class="kv" style="margin-top:10px">
        <div class="k">CIM #${i + 1}</div><div class="v"></div>
        <div class="k">seal_id</div><div class="v">${escapeHtml(c.sealId)}</div>
        <div class="k">base32</div><div class="v">${escapeHtml(c.base32)}</div>
        <div class="k">inferred year</div><div class="v">${c.year}</div>
        <div class="k">at index</div><div class="v">${c.startIndex} - ${c.endIndex}</div>
        <div class="k">crc</div><div class="v">valid</div>
      </div>
    `;
  });

  body.innerHTML = `
    <span class="verdict ok">${cims.length} valid mark(s)</span>
    <p class="dim" style="margin-top:8px">
      The text carries ${cims.length} Crovia Invisible Mark(s). The
      <code>seal_id</code>(s) below uniquely identify the signed provenance
      receipt(s). Full verification requires fetching the receipt from a
      transparency log (next sprint) or pasting the raw Seal JSON below.
    </p>
    ${parts.join('')}
  `;
}

async function analyzeRawSealJson(): Promise<void> {
  const raw = prompt('Paste raw Seal JSON:');
  if (!raw) return;
  let seal: unknown;
  try { seal = JSON.parse(raw); } catch (e) {
    alert('Not valid JSON: ' + (e as Error).message);
    return;
  }
  const req: VerifySealRequest = { type: 'verify_seal', seal };
  const resp = await chrome.runtime.sendMessage<VerifySealRequest, VerifySealResponse>(req);
  const body = $('result-body');
  $('results').hidden = false;
  if (resp.ok) {
    body.innerHTML = renderVerdict('ok', 'seal verified', [
      ['seal_id', resp.sealId ?? '(none)'],
    ]);
  } else {
    body.innerHTML = renderVerdict('err', 'seal INVALID', [], resp.errors ?? ['unknown error']);
  }
}

function initDrop(): void {
  const dz = $('drop-zone');
  const ta = $<HTMLTextAreaElement>('input');
  dz.addEventListener('dragover', (e) => {
    e.preventDefault();
    dz.classList.add('hover');
  });
  dz.addEventListener('dragleave', () => dz.classList.remove('hover'));
  dz.addEventListener('drop', async (e) => {
    e.preventDefault();
    dz.classList.remove('hover');
    let text = '';
    if (e.dataTransfer) {
      text = e.dataTransfer.getData('text/plain');
      if (!text && e.dataTransfer.files.length > 0) {
        const f = e.dataTransfer.files[0]!;
        text = await f.text();
      }
    }
    ta.value = text;
    await analyzeText(text);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initDrop();
  $<HTMLButtonElement>('analyze').addEventListener('click', () => {
    void analyzeText($<HTMLTextAreaElement>('input').value);
  });
  $<HTMLButtonElement>('paste-seal').addEventListener('click', () => {
    void analyzeRawSealJson();
  });
});
