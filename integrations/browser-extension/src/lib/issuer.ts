/**
 * Local issuer key management.
 *
 * PRIVACY PRINCIPLE: the private key is generated locally on first run and
 * never leaves the browser. We store it in `chrome.storage.local` because
 * that API is:
 *   - scoped to the extension (not shared with any web page);
 *   - persisted across browser restarts;
 *   - small and fast (~5 MiB quota is irrelevant for a 32-byte key).
 *
 * The issuer id is derived from the first 8 bytes of the public key,
 * base32-encoded. Users can customize it via the popup (optional). Until
 * they do, the default id is:
 *     urn:crovia:seal-issuer:user-<8 base32 chars of pubkey>
 *
 * This makes every installation unique and self-identifying without
 * requiring any account creation or server communication.
 */
import { IssuerKey, loadIssuerKey, generateIssuerKey } from '@crovia/seal';

const STORAGE_KEY = 'crovia_issuer_v1';

interface StoredIssuer {
  version: 1;
  issuerId: string;
  privateHex: string;     // kept in extension-private storage
  publicHex: string;
  createdAt: string;
}

function chromeStorageGet<T = unknown>(key: string): Promise<T | undefined> {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (items) => resolve(items[key] as T | undefined));
  });
}

function chromeStorageSet(key: string, value: unknown): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: value }, () => resolve());
  });
}

function defaultIssuerIdFromPub(publicHex: string): string {
  // Use first 40 bits = 5 bytes = 8 base32 chars for a short readable id.
  // We prefer base32 to hex because it is shorter and matches seal_id style.
  const first5bytes = publicHex.slice(0, 10); // 5 bytes = 10 hex chars
  // Convert hex -> bytes -> base32.
  const bytes = new Uint8Array(5);
  for (let i = 0; i < 5; i++) {
    bytes[i] = parseInt(first5bytes.slice(i * 2, i * 2 + 2), 16);
  }
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let b32 = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      b32 += alphabet[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) b32 += alphabet[(value << (5 - bits)) & 0x1f];
  return `urn:crovia:seal-issuer:user-${b32}`;
}


/** Load the user's issuer key, generating a new one on first run. */
export async function getOrCreateIssuer(): Promise<IssuerKey> {
  const existing = await chromeStorageGet<StoredIssuer>(STORAGE_KEY);
  if (existing && existing.version === 1) {
    return loadIssuerKey(existing.issuerId, existing.privateHex);
  }
  const tempIssuerId = 'urn:crovia:seal-issuer:user-bootstrap';
  const tmpKey = generateIssuerKey(tempIssuerId);
  // Derive the real self-identifying issuer_id from the freshly generated pubkey.
  const finalId = defaultIssuerIdFromPub(tmpKey.publicHex);
  const finalKey = loadIssuerKey(finalId, tmpKey.privateHex());
  const stored: StoredIssuer = {
    version: 1,
    issuerId: finalId,
    privateHex: finalKey.privateHex(),
    publicHex: finalKey.publicHex,
    createdAt: new Date().toISOString(),
  };
  await chromeStorageSet(STORAGE_KEY, stored);
  return finalKey;
}

/** Read the public identity of the local issuer without instantiating keys. */
export async function getPublicIdentity(): Promise<{
  issuerId: string; publicHex: string; createdAt: string;
} | null> {
  const existing = await chromeStorageGet<StoredIssuer>(STORAGE_KEY);
  if (!existing) return null;
  return { issuerId: existing.issuerId, publicHex: existing.publicHex, createdAt: existing.createdAt };
}

/** Reset the issuer, discarding the current key and generating a new one. */
export async function resetIssuer(): Promise<IssuerKey> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.remove(STORAGE_KEY, () => resolve());
  });
  return getOrCreateIssuer();
}
