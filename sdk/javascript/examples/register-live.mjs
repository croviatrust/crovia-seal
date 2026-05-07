/**
 * Live registration test — signs a receipt with the SDK and posts it
 * to the real production anchor service.
 *
 * Run: node examples/register-live.mjs
 */
import { seal, verify, register, generateKeySync } from "../dist/index.js";

const key = generateKeySync();
console.log("[test] generated key, signer =", key.publicHex.slice(0, 20) + "…");

const payload = {
  test: "live-register",
  timestamp_local: new Date().toISOString(),
  random: Math.floor(Math.random() * 1e9),
};

const r = await seal(payload, { key, payloadType: "test/live" });
console.log("[test] sealed:", r.id);

const v = await verify(r, payload);
console.log("[test] local verify:", v.valid ? "VALID" : "INVALID");
if (!v.valid) {
  console.error("[test] cannot register an invalid local seal");
  process.exit(1);
}

console.log("[test] posting to https://croviatrust.com/api/anchor …");
const result = await register(r);
console.log("[test] register result:", result);

if (!result.accepted) {
  console.error("[test] registration FAILED");
  process.exit(1);
}

// Idempotency: posting the same receipt again must succeed and return the same anchor.
const result2 = await register(r);
console.log("[test] re-register (idempotent):", result2);

// Tampered receipt must be rejected.
const tampered = { ...r, sig: r.sig.replace(/^./, (c) => (c === "0" ? "1" : "0")) };
const result3 = await register(tampered);
console.log(
  "[test] register tampered (must reject):",
  result3.accepted ? "ACCEPTED ✗ BUG" : `REJECTED ✓ (${result3.error})`,
);
