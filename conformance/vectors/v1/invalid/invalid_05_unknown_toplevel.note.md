# invalid_05_unknown_toplevel

**Expected verifier error:** `UnknownTopLevelField`

## Description

An unknown top-level field was injected. Per SPEC 4.1, unknown top-level fields MUST cause verification to fail.

## Derivation

Base: `seal_001_genesis.json`

A single, deliberate corruption has been applied. All other bytes are identical.
