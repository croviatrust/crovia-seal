/**
 * IndexedDB-backed storage for emitted Seals.
 *
 * Why IndexedDB rather than chrome.storage.local:
 *   - chrome.storage.local has a ~5 MiB default quota; a power user emitting
 *     seals all day can blow past it in a week.
 *   - IndexedDB supports structured queries we will need later (by-site,
 *     by-date, by-model).
 *   - It works the same way in every MV3 context (popup, content script via
 *     messaging, verify page).
 *
 * The database is intentionally minimal: a single object store `seals`
 * keyed by `seal_id`, plus a secondary index on `timestamp.emitted_at`.
 */
import type { ServerSeal } from './messaging';

const DB_NAME = 'crovia-seal-extension';
const DB_VERSION = 3;
const STORE_NAME = 'seals';

export interface StoredSeal {
  seal: ServerSeal;
  emittedAt: string;     // seal.issued_at
  site: string;          // host where the output was captured
  visibleExcerpt: string; // first ~140 chars of the output, for UI preview
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // If a previous (buggy) version of the store exists, drop and recreate.
      if (db.objectStoreNames.contains(STORE_NAME)) {
        db.deleteObjectStore(STORE_NAME);
      }
      const store = db.createObjectStore(STORE_NAME, { keyPath: 'seal.seal_id' });
      store.createIndex('emittedAt', 'emittedAt', { unique: false });
      store.createIndex('site', 'site', { unique: false });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function putSeal(entry: StoredSeal): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(entry);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function getSeal(sealId: string): Promise<StoredSeal | null> {
  const db = await openDb();
  try {
    return await new Promise<StoredSeal | null>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(sealId);
      req.onsuccess = () => resolve((req.result as StoredSeal | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function listRecentSeals(limit = 50): Promise<StoredSeal[]> {
  const db = await openDb();
  try {
    return await new Promise<StoredSeal[]>((resolve, reject) => {
      const out: StoredSeal[] = [];
      const tx = db.transaction(STORE_NAME, 'readonly');
      const idx = tx.objectStore(STORE_NAME).index('emittedAt');
      const req = idx.openCursor(null, 'prev');
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor || out.length >= limit) { resolve(out); return; }
        out.push(cursor.value as StoredSeal);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function countSeals(): Promise<number> {
  const db = await openDb();
  try {
    return await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}
