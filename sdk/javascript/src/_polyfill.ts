/**
 * Crypto polyfill — MUST be imported before any module that captures
 * `globalThis.crypto` at load time (notably @noble/ed25519 v2.x).
 *
 * ESM modules are evaluated depth-first in declaration order, so a
 * top-level `import "./_polyfill.js"` before the noble imports gives
 * us a deterministic ordering.
 *
 * In browsers and modern Node (19+), this is a no-op because
 * globalThis.crypto already exists. In Node 18.x ESM, we install
 * webcrypto from "node:crypto" via top-level await.
 */
const g = globalThis as {
  crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array };
};

if (!g.crypto || typeof g.crypto.getRandomValues !== "function") {
  try {
    const nc = (await import("node:crypto")) as unknown as {
      webcrypto?: { getRandomValues: (a: Uint8Array) => Uint8Array };
    };
    if (nc.webcrypto?.getRandomValues) {
      (globalThis as { crypto?: unknown }).crypto = nc.webcrypto;
    }
  } catch {
    // Not Node — leave whatever is there. If both browser and Node fail,
    // noble-ed25519 will throw with its own clear error.
  }
}

export {};
