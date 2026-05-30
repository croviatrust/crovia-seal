/**
 * Background service worker (MV3) — Server-backed mode.
 *
 * All seals are issued by the Crovia Trust server (seal.croviatrust.com).
 * The extension does NOT hold private keys. Instead it:
 *   - seal_output:  POST /v1/sign  → signed seal (sl_ format) + CIM
 *   - verify_seal:  GET  /v1/seal/{id}
 *   - get_public_identity: fetch trust-root for server's public key
 *   - list_recent_seals: historical queries from IndexedDB
 *
 * Crypto conformance: the server applies CSC-1 canonicalization + Ed25519
 * signature with domain prefix "CROVIA-SEAL-v1\n" as specified in
 * draft-crovia-seal-01 (IETF). The extension is a thin client.
 */

import { putSeal, listRecentSeals } from './lib/storage';
import type {
  AnyRequest, AnyResponse,
  SealOutputRequest, SealOutputResponse,
  VerifySealRequest, VerifySealResponse,
  GetPublicIdentityResponse,
  ListRecentSealsResponse,
} from './lib/messaging';

const SEAL_API = 'https://seal.croviatrust.com';

// ────────── CIM encoding (matches production check.html extractCim) ──────────
// Format: SENT SENT <bits> SENT SENT
//   0 = U+200B (ZWSP),  1 = U+200C (ZWNJ),  sentinel = U+2060 (Word Joiner)
const CIM_ZERO = '\u200B';
const CIM_ONE  = '\u200C';
const CIM_SENT = '\u2060';

function encodeCimForSealId(sealId: string): string {
  const bytes = new TextEncoder().encode(sealId);
  let bits = '';
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits += ((b >> i) & 1) ? CIM_ONE : CIM_ZERO;
    }
  }
  return CIM_SENT + CIM_SENT + bits + CIM_SENT + CIM_SENT;
}

// ────────── SHA-256 hex ──────────
// Always normalize to NFC before hashing so accented chars (è, à, é),
// symbols (€, @, #) and emoji produce a consistent hash regardless of
// whether the source string is NFC, NFD or NFKD.
async function sha256Hex(text: string): Promise<string> {
  const normalized = text.normalize('NFC');
  const buf = new TextEncoder().encode(normalized);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ────────── Handlers ──────────

async function handleSealOutput(req: SealOutputRequest): Promise<SealOutputResponse> {
  try {
    // PRIVACY MODE: hash everything client-side, server never sees plaintext
    const inputHash  = 'sha256:' + await sha256Hex(req.inputText);
    const outputHash = 'sha256:' + await sha256Hex(req.outputText);
    const outputLength = new TextEncoder().encode(req.outputText).length;

    const parts = req.generatorId.split('/');
    const vendor = parts[0] || 'unknown';
    const model = parts.slice(1).join('/') || 'unknown';

    const res = await fetch(SEAL_API + '/v1/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        output_hash: outputHash,
        output_length: outputLength,
        input_hash: inputHash,
        generator: { vendor, model },
        issuer_app: 'crovia-seal-extension/0.7.0',
      }),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => `HTTP ${res.status}`);
      return { ok: false, error: `seal service: ${detail}` };
    }

    const data = await res.json();
    const seal = data.seal;
    const sealId: string = data.seal_id || seal?.seal_id || '';
    const cim = encodeCimForSealId(sealId);

    await putSeal({
      seal,
      emittedAt: seal.issued_at || new Date().toISOString(),
      site: req.site,
      visibleExcerpt: req.outputText.slice(0, 140),
    });

    return { ok: true, seal, cim };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function handleVerifySeal(req: VerifySealRequest): Promise<VerifySealResponse> {
  try {
    const res = await fetch(
      SEAL_API + '/v1/seal/' + encodeURIComponent(req.sealId),
      { cache: 'no-store' },
    );
    if (res.status === 404) {
      return { ok: false, errors: ['Seal not found in public index'], sealId: req.sealId };
    }
    if (!res.ok) {
      return { ok: false, errors: [`HTTP ${res.status}`], sealId: req.sealId };
    }
    const seal = await res.json();
    return { ok: true, seal, sealId: req.sealId };
  } catch (e) {
    return { ok: false, errors: [(e as Error).message], sealId: req.sealId };
  }
}

async function handleGetPublicIdentity(): Promise<GetPublicIdentityResponse> {
  try {
    const res = await fetch(SEAL_API + '/trust-root.json', { cache: 'no-store' });
    if (!res.ok) return { ok: false, error: `trust-root: HTTP ${res.status}` };
    const root = await res.json();
    return {
      ok: true,
      issuerId: root.issuer?.id || SEAL_API,
      publicHex: root.issuer?.pubkey || '',
      createdAt: root.issued_at || '',
    };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function handleListRecentSeals(limit: number | undefined): Promise<ListRecentSealsResponse> {
  try {
    const entries = await listRecentSeals(limit ?? 50);
    return {
      ok: true,
      seals: entries.map((e) => ({
        sealId: e.seal.seal_id,
        emittedAt: e.emittedAt,
        site: e.site,
        excerpt: e.visibleExcerpt,
      })),
    };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}


chrome.runtime.onMessage.addListener(
  (req: AnyRequest, _sender, sendResponse: (r: AnyResponse) => void) => {
    (async () => {
      switch (req.type) {
        case 'seal_output':
          sendResponse(await handleSealOutput(req));
          break;
        case 'verify_seal':
          sendResponse(await handleVerifySeal(req));
          break;
        case 'get_public_identity':
          sendResponse(await handleGetPublicIdentity());
          break;
        case 'list_recent_seals':
          sendResponse(await handleListRecentSeals(req.limit));
          break;
        default: {
          const _exhaustive: never = req;
          sendResponse({ ok: false, error: 'unknown request type' } as AnyResponse);
          return _exhaustive;
        }
      }
    })();
    return true;
  },
);

// eslint-disable-next-line no-console
console.log('[crovia-seal] background service worker ready (server: ' + SEAL_API + ')');
