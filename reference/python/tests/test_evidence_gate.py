import copy
import json
import subprocess
import sys

import pytest

from crovia_seal import canonicalize, emit_seal, generate_issuer_key, verify_seal
from crovia_seal.evidence_gate import PROFILE, attest_check, create_challenge, evaluate

ARTIFACT = b'{"commit":"exact bytes"}\n'
NOW = 1794052800


@pytest.fixture
def request_data():
    keys = {name: generate_issuer_key(f"urn:crovia:seal-issuer:ci-{name}") for name in ("unit", "security")}
    policy = {
        "profile": PROFILE,
        "audience": "deploy/production",
        "action": "promote",
        "required": {name: {"issuer_id": key.issuer_id, "public_key": key.public_hex}
                     for name, key in keys.items()},
    }
    challenge = create_challenge(policy, ARTIFACT, now=NOW)
    return keys, policy, challenge


def test_requires_every_configured_check(request_data):
    keys, policy, challenge = request_data
    unit = attest_check(policy, challenge, ARTIFACT, "unit", True, keys["unit"], now=NOW)
    security = attest_check(policy, challenge, ARTIFACT, "security", True, keys["security"], now=NOW)
    result = evaluate(policy, challenge, ARTIFACT, [unit], now=NOW)
    assert result["status"] == "blocked"
    assert result["missing"] == ["security"]
    result = evaluate(policy, challenge, ARTIFACT, [security, unit], now=NOW)
    assert result["status"] == "ready"
    assert set(result["verified"]) == {"unit", "security"}
    duplicate = evaluate(policy, challenge, ARTIFACT, [unit, security, unit], now=NOW)
    assert duplicate["status"] == "blocked"
    assert duplicate["invalid"][0]["reason"] == "unexpected or duplicate check"


def test_signed_failure_is_a_failure(request_data):
    keys, policy, challenge = request_data
    checks = [attest_check(policy, challenge, ARTIFACT, name, name == "unit", key, now=NOW)
              for name, key in keys.items()]
    result = evaluate(policy, challenge, ARTIFACT, checks, now=NOW)
    assert result["status"] == "blocked"
    assert result["failed"] == ["security"]
    assert result["missing"] == []


def test_valid_seal_cannot_be_reused_for_another_request_or_policy(request_data):
    keys, policy, challenge = request_data
    seal = attest_check(policy, challenge, ARTIFACT, "unit", True, keys["unit"], now=NOW)
    assert verify_seal(seal, issuer_pubkey_hex=keys["unit"].public_hex).ok
    another = create_challenge(policy, ARTIFACT, now=NOW)
    result = evaluate(policy, another, ARTIFACT, [seal], now=NOW)
    assert result["invalid"][0]["reason"] == "request or artifact binding mismatch"
    for field in ("audience", "action"):
        other_policy = {**policy, field: "different"}
        with pytest.raises(ValueError, match=field):
            evaluate(other_policy, challenge, ARTIFACT, [seal], now=NOW)
    with pytest.raises(ValueError, match="policy mismatch"):
        evaluate({**policy, "required": {"unit": policy["required"]["unit"]}},
                 challenge, ARTIFACT, [seal], now=NOW)
    with pytest.raises(ValueError, match="artifact mismatch"):
        evaluate(policy, challenge, ARTIFACT.strip(), [seal], now=NOW)
    with pytest.raises(ValueError, match="expired"):
        evaluate(policy, challenge, ARTIFACT, [seal], now=challenge["expires_at"])


def test_issuer_key_claim_and_exact_artifact_are_verified(request_data):
    keys, policy, challenge = request_data
    claim = {PROFILE: {"check": "security", "passed": True}}
    rogue = generate_issuer_key(keys["security"].issuer_id)
    def sign(key, artifact):
        return emit_seal(issuer_key=key, input_bytes=canonicalize(challenge),
                         output_bytes=artifact, modality="multimodal",
                         generator_id=PROFILE, checks=claim)

    legitimate = sign(keys["security"], ARTIFACT)
    altered = copy.deepcopy(legitimate)
    altered["checks"][PROFILE]["passed"] = False
    malformed = copy.deepcopy(legitimate)
    malformed["subject"]["modality"] = {}
    for seal in (sign(rogue, ARTIFACT), sign(keys["unit"], ARTIFACT), altered, malformed,
                 sign(keys["security"], ARTIFACT.strip())):
        result = evaluate(policy, challenge, ARTIFACT, [seal], now=NOW)
        assert result["status"] == "blocked"
        assert result["invalid"]
    with pytest.raises(ValueError, match="issuer is not pinned"):
        attest_check(policy, challenge, ARTIFACT, "security", True, rogue, now=NOW)


def test_cli_fails_closed_on_missing_and_ambiguous_input(request_data, tmp_path):
    _, policy, _ = request_data
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(ARTIFACT)
    command = [sys.executable, "-m", "crovia_seal.evidence_gate"]
    common = ["--policy", str(policy_path), "--artifact", str(artifact_path)]
    challenge = subprocess.run(command + ["challenge"] + common, check=True, capture_output=True)
    challenge_path = tmp_path / "challenge.json"
    challenge_path.write_bytes(challenge.stdout)
    verify = command + ["verify"] + common + ["--challenge", str(challenge_path)]
    missing = subprocess.run(verify, capture_output=True)
    assert missing.returncode == 1
    assert json.loads(missing.stdout)["missing"] == ["security", "unit"]
    challenge_path.write_bytes(challenge.stdout.strip()[:-1] + b', "nonce": "another"}')
    invalid = subprocess.run(verify, capture_output=True)
    assert invalid.returncode == 2
    assert "duplicate JSON key" in json.loads(invalid.stdout)["reason"]
