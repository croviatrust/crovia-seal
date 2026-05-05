# invalid_03_tampered_field

**Expected verifier error:** `SignatureMismatch`

## Description

output_hash tampered after signing; canonical payload hash differs, Ed25519 verify MUST fail.

## Derivation

Base: `seal_001_genesis.json`

A single, deliberate corruption has been applied. All other bytes are identical.
