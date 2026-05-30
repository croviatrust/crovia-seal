/**
 * Popup UI script.
 */
import type {
  GetPublicIdentityRequest, GetPublicIdentityResponse,
  ListRecentSealsRequest, ListRecentSealsResponse,
} from '../lib/messaging';


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

async function refreshIdentity(): Promise<void> {
  const r = await chrome.runtime.sendMessage<GetPublicIdentityRequest, GetPublicIdentityResponse>(
    { type: 'get_public_identity' },
  );
  if (!r.ok) {
    $('issuer-id').textContent = 'error: ' + (r.error ?? 'unknown');
    return;
  }
  $('issuer-id').textContent = r.issuerId ?? '';
  $('pubkey').textContent = r.publicHex ?? '';
  $('created').textContent = r.createdAt
    ? 'created ' + new Date(r.createdAt).toLocaleString()
    : '';
}

async function refreshRecent(): Promise<void> {
  const r = await chrome.runtime.sendMessage<ListRecentSealsRequest, ListRecentSealsResponse>(
    { type: 'list_recent_seals', limit: 20 },
  );
  if (!r.ok || !r.seals) return;
  $('count').textContent = r.seals.length.toString();
  const ul = $<HTMLUListElement>('recent-list');
  ul.innerHTML = '';
  if (r.seals.length === 0) {
    const li = document.createElement('li');
    li.className = 'dim';
    li.textContent = 'No seals yet. Click the "Seal" button on an AI answer.';
    ul.appendChild(li);
    return;
  }
  for (const s of r.seals) {
    const li = document.createElement('li');
    li.innerHTML = `
      <div class="seal-id">${escapeHtml(s.sealId)}</div>
      <div class="seal-excerpt">${escapeHtml(s.excerpt)}</div>
      <div class="seal-site">${escapeHtml(s.site)} - ${escapeHtml(new Date(s.emittedAt).toLocaleString())}</div>
    `;
    ul.appendChild(li);
  }
}

function openVerifier(ev: Event): void {
  ev.preventDefault();
  chrome.tabs.create({ url: 'https://croviatrust.com/check.html' });
}

function openAbout(ev: Event): void {
  ev.preventDefault();
  chrome.tabs.create({ url: 'https://croviatrust.com/seal/' });
}

function openPrivacy(ev: Event): void {
  ev.preventDefault();
  chrome.tabs.create({ url: 'https://croviatrust.com/seal/privacy.html' });
}

document.addEventListener('DOMContentLoaded', () => {
  $<HTMLAnchorElement>('open-verify').addEventListener('click', openVerifier);
  const about = document.getElementById('open-about');
  if (about) about.addEventListener('click', openAbout);
  const privacy = document.getElementById('open-privacy');
  if (privacy) privacy.addEventListener('click', openPrivacy);
  void refreshIdentity();
  void refreshRecent();
});
