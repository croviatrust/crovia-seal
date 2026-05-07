/**
 * End-to-end tests for seal/verify.
 */
import { describe, expect, it } from "vitest";

import {
  generateKeySync,
  seal,
  verify,
  verifyChain,
  validateReceiptShape,
} from "../src/index.js";

describe("seal()", () => {
  it("produces a structurally-valid receipt", async () => {
    const key = generateKeySync();
    const r = await seal({ hello: "world" }, { key });
    expect(validateReceiptShape(r)).toBeNull();
    expect(r.v).toBe("crovia.receipt.v1");
    expect(r.signer).toBe(key.publicHex);
    expect(r.prev).toBeNull();
    expect(r.seq).toBe(0);
  });

  it("genesis: prev=null and seq=0", async () => {
    const r = await seal({ x: 1 });
    expect(r.prev).toBeNull();
    expect(r.seq).toBe(0);
  });

  it("chains: r2.prev = r1.id, seq increments", async () => {
    const key = generateKeySync();
    const r1 = await seal({ v: 1 }, { key });
    const r2 = await seal({ v: 2 }, { key, prevReceipt: r1 });
    expect(r2.prev).toBe(r1.id);
    expect(r2.seq).toBe(1);
    expect(r2.signer).toBe(r1.signer);
  });

  it("attaches optional payload_type", async () => {
    const r = await seal({ x: 1 }, { payloadType: "model-card" });
    expect(r.payload_type).toBe("model-card");
  });

  it("two seals over the same payload have different ids", async () => {
    const key = generateKeySync();
    const r1 = await seal({ x: 1 }, { key });
    const r2 = await seal({ x: 1 }, { key });
    expect(r1.id).not.toBe(r2.id);
  });
});

describe("verify()", () => {
  it("accepts a fresh seal", async () => {
    const r = await seal({ msg: "hi" });
    const result = await verify(r);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("validates payload_hash when payload provided", async () => {
    const payload = { a: 1, b: "x" };
    const r = await seal(payload);
    const result = await verify(r, payload);
    expect(result.valid).toBe(true);
  });

  it("rejects mismatched payload", async () => {
    const r = await seal({ a: 1 });
    const result = await verify(r, { a: 2 });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toMatch(/payload_hash mismatch/);
  });

  it("rejects tampered signature", async () => {
    const r = await seal({ x: 1 });
    const tampered = { ...r, sig: r.sig.replace(/^./, (c) => (c === "0" ? "1" : "0")) };
    const result = await verify(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("signature: invalid");
  });

  it("rejects tampered fields (signature breaks)", async () => {
    const r = await seal({ x: 1 });
    const tampered = { ...r, issued_at: "2099-01-01T00:00:00.000Z" };
    const result = await verify(tampered);
    expect(result.valid).toBe(false);
  });

  it("rejects malformed receipts (schema fail-closed)", async () => {
    const result = await verify({ not: "a receipt" });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toMatch(/^schema:/);
  });
});

describe("verifyChain()", () => {
  it("accepts a valid chain of three", async () => {
    const key = generateKeySync();
    const r1 = await seal({ v: 1 }, { key });
    const r2 = await seal({ v: 2 }, { key, prevReceipt: r1 });
    const r3 = await seal({ v: 3 }, { key, prevReceipt: r2 });
    const result = await verifyChain([r1, r2, r3]);
    expect(result.valid).toBe(true);
  });

  it("rejects a chain with a gap in seq", async () => {
    const key = generateKeySync();
    const r1 = await seal({ v: 1 }, { key });
    const r3 = await seal({ v: 3 }, { key, prevReceipt: r1 });
    // Manually skip r2 — r3 has seq=1, r1 has seq=0, but the chain
    // needs r3.seq=1 follows r1.seq=0 → ok actually. So construct
    // a real gap by faking seq:
    const fakeR3 = { ...r3, seq: 5 };
    const result = await verifyChain([r1, fakeR3]);
    expect(result.valid).toBe(false);
  });

  it("rejects a chain with mismatched prev", async () => {
    const key = generateKeySync();
    const r1 = await seal({ v: 1 }, { key });
    const r2 = await seal({ v: 2 }, { key, prevReceipt: r1 });
    const fakeR2 = { ...r2, prev: "cr_2026_FAKEFAKEFAKEFAKEFAKEFAKEFA" };
    const result = await verifyChain([r1, fakeR2]);
    expect(result.valid).toBe(false);
  });

  it("rejects a chain with a different signer mid-way", async () => {
    const k1 = generateKeySync();
    const k2 = generateKeySync();
    const r1 = await seal({ v: 1 }, { key: k1 });
    // r2 chains from r1 but signed by a different key — chain says no.
    const r2 = await seal({ v: 2 }, { key: k2, prevReceipt: r1 });
    const result = await verifyChain([r1, r2]);
    expect(result.valid).toBe(false);
  });
});
