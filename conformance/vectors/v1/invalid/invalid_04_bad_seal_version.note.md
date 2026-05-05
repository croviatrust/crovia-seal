# invalid_04_bad_seal_version

**Expected verifier error:** `UnknownSealVersion`

## Description

seal_version is not 'crovia.seal.v1'. v1 verifier MUST fail closed and refuse to interpret the document.

## Derivation

Base: `seal_001_genesis.json`

A single, deliberate corruption has been applied. All other bytes are identical.
