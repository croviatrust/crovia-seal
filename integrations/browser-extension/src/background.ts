/**
 * Background service worker (MV3).
 *
 * Handles all operations that require the local private key:
 *   - seal_output: build a Seal over input/output, return the Seal + CIM
 *   - verify_seal: re-verify any Seal
 *   - get_public_identity / reset_identity
 *   - list_recent_seals: historical queries from popup
 *
 * Runs isolated: no access to page DOM, only chrome.* APIs and imports
 * from @crovia/seal. The private key never leaves this context.
 */
import { emitSeal, verifySeal, type Modality } from '@crovia/seal';

import { getOrCreateIssuer, getPublicIdentity, resetIssuer } from './lib/issuer';
import { encodeCim } from './lib/stego';
import { putSeal, listRecentSeals } from './lib/storage';
import type {
  AnyRequest, AnyResponse,
  SealOutputRequest, SealOutputResponse,
  VerifySealRequest, VerifySealResponse,
  GetPublicIdentityResponse,
  ResetIdentityResponse,
  ListRecentSealsResponse,
} from './lib/messaging';


async function handleSealOutput(req: SealOutputRequest): Promise<SealOutputResponse> {
  try {
    const issuer = await getOrCreateIssuer();
    const enc = new TextEncoder();
    const seal = emitSeal({
      issuerKey: issuer,
      inputBytes: enc.encode(req.inputText),
      outputBytes: enc.encode(req.outputText),
      modality: 'text' as Modality,
      generatorId: req.generatorId,
      generatorVersion: req.generatorVersion ?? null,
    });
    const cim = encodeCim(seal.seal_id);
    await putSeal({
      seal,
      emittedAt: seal.timestamp.emitted_at,
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
    const r = verifySeal(req.seal, { issuerPubkeyHex: req.pinnedPubkeyHex });
    return { ok: r.ok, errors: r.errors, sealId: r.sealId };
  } catch (e) {
    return { ok: false, errors: [(e as Error).message], sealId: null };
  }
}

async function handleGetPublicIdentity(): Promise<GetPublicIdentityResponse> {
  try {
    await getOrCreateIssuer(); // ensure one exists
    const id = await getPublicIdentity();
    if (!id) return { ok: false, error: 'no issuer after init' };
    return { ok: true, ...id };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function handleResetIdentity(): Promise<ResetIdentityResponse> {
  try {
    const issuer = await resetIssuer();
    return { ok: true, publicHex: issuer.publicHex };
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
        case 'reset_identity':
          sendResponse(await handleResetIdentity());
          break;
        case 'list_recent_seals':
          sendResponse(await handleListRecentSeals(req.limit));
          break;
        default: {
          const _exhaustive: never = req;
          sendResponse({ ok: false, error: `unknown request type` } as AnyResponse);
          return _exhaustive;
        }
      }
    })();
    return true; // keep message channel open for async sendResponse
  },
);

// eslint-disable-next-line no-console
console.log('[crovia-seal] background service worker ready');
