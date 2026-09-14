from protocol_profiles import Profile, classify_profile


def draft_seal():
    return {
        "seal_version": "crovia.seal.v1",
        "issuer": {"id": "urn:example", "pubkey": {"alg": "ed25519", "key_hex": "00" * 32}},
        "timestamp": {"emitted_at": "2026-09-14T00:00:00.000Z", "nonce": "A" * 26},
        "chain": {"sequence": 0, "prev_seal_hash": None},
        "signature": {"alg": "ed25519", "canon": "csc-1", "sig_hex": "00" * 64},
    }


def legacy_seal():
    return {
        "seal_version": "crovia-seal-v1",
        "issuer": {"id": "urn:example", "pubkey_alg": "Ed25519", "pubkey": "00" * 32},
        "issued_at": "2026-05-04T00:00:00Z",
        "signature": "Ed25519:" + "00" * 64,
    }


def test_draft_01_is_distinct():
    assert classify_profile(draft_seal()) is Profile.DRAFT_01


def test_historical_legacy_is_distinct():
    assert classify_profile(legacy_seal()) is Profile.LEGACY_V1


def test_mixed_shape_is_ambiguous():
    seal = draft_seal()
    seal["issued_at"] = "2026-05-04T00:00:00Z"
    assert classify_profile(seal) is Profile.AMBIGUOUS


def test_draft_identifier_with_legacy_shape_is_ambiguous():
    seal = legacy_seal()
    seal["seal_version"] = "crovia.seal.v1"
    assert classify_profile(seal) is Profile.AMBIGUOUS


def test_unknown_version_fails_closed():
    assert classify_profile({"seal_version": "future"}) is Profile.UNSUPPORTED


def test_non_object_fails_closed():
    assert classify_profile([]) is Profile.UNSUPPORTED
