/**
 * Basic example: seal, verify, chain.
 * Run with: npx tsx examples/basic.ts
 */
import { seal, verify, verifyChain, generateKeySync } from "../src/index.js";

async function main(): Promise<void> {
  const key = generateKeySync();
  console.log("Generated key. signer =", key.publicHex.slice(0, 16) + "…");

  // Seal a payload.
  const payload = {
    model: "openai/gpt-4o",
    output: "Hello, continuity.",
    timestamp_local: new Date().toISOString(),
  };
  const r1 = await seal(payload, { key, payloadType: "ai-output" });
  console.log("\nReceipt 1:", r1.id);
  console.log("  payload_hash:", r1.payload_hash);
  console.log("  seq:", r1.seq, "prev:", r1.prev);

  // Verify it (with payload — full check).
  const v1 = await verify(r1, payload);
  console.log("\nVerify (with payload):", v1.valid ? "VALID" : "INVALID");

  // Chain a second receipt.
  const r2 = await seal(
    { model: "openai/gpt-4o", output: "Continuity, hello." },
    { key, prevReceipt: r1, payloadType: "ai-output" },
  );
  console.log("\nReceipt 2:", r2.id);
  console.log("  prev:", r2.prev, "seq:", r2.seq);

  // Verify the whole chain.
  const chainResult = await verifyChain([r1, r2]);
  console.log(
    "\nVerify chain:",
    chainResult.valid ? "VALID" : "INVALID",
    chainResult.errors,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
