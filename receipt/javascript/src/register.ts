/**
 * `register()` — optional opt-in: post a receipt to the Crovia substrate.
 *
 * The substrate accepts the receipt, returns an anchor id and a position
 * in the public continuity graph. This is OPTIONAL — `seal()` and
 * `verify()` work fully offline. Calling `register()` is what causes the
 * receipt to participate in the public substrate's continuity graph.
 */
import type {
  Receipt,
  RegisterOptions,
  RegisterResult,
} from "./types.js";

const DEFAULT_ENDPOINT = "https://croviatrust.com";
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Register a receipt with the Crovia substrate.
 *
 * @returns A result describing whether the substrate accepted the receipt.
 *          Never throws on transport errors — they are returned as fields.
 */
export async function register(
  receipt: Receipt,
  opts: RegisterOptions = {},
): Promise<RegisterResult> {
  const endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchFn = opts.fetch ?? globalThis.fetch;

  if (typeof fetchFn !== "function") {
    return {
      accepted: false,
      status: 0,
      error: "fetch is not available; pass opts.fetch",
    };
  }

  const url = endpoint.replace(/\/+$/, "") + "/api/anchor";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "crovia-seal/0.1.0",
      },
      body: JSON.stringify({ receipt }),
      signal: controller.signal,
    });

    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // ignore — body may be empty on errors
    }
    const b = body as { anchor_id?: string; error?: string } | null;

    if (res.ok) {
      return {
        accepted: true,
        status: res.status,
        anchorId: b?.anchor_id,
      };
    }
    return {
      accepted: false,
      status: res.status,
      error: b?.error ?? `HTTP ${res.status}`,
    };
  } catch (e) {
    return {
      accepted: false,
      status: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    clearTimeout(timer);
  }
}
