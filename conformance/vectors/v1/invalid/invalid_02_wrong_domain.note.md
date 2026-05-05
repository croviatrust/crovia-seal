# invalid_02_wrong_domain

**Expected verifier error:** `WrongDomain`

## Description

signature.domain does not match the canonical domain prefix. Verifier MUST refuse to recompute the payload with a different prefix.

## Derivation

Base: `seal_001_genesis.json`

A single, deliberate corruption has been applied. All other bytes are identical.
