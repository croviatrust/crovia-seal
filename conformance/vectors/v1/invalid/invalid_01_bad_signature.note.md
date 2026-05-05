# invalid_01_bad_signature

**Expected verifier error:** `BadSignature`

## Description

Signature byte 0 flipped; Ed25519 verify MUST fail.

## Derivation

Base: `seal_001_genesis.json`

A single, deliberate corruption has been applied. All other bytes are identical.
