"""Core verification logic for Crovia seals."""
import json
import hashlib
import urllib.request
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

SEAL_API = "https://seal.croviatrust.com/v1/seal/"
TRUST_ROOT_URL = "https://seal.croviatrust.com/trust-root.json"
MESSAGE_PREFIX = "CROVIA-SEAL-v1"


def csc1(obj):
    """CSC-1 canonical JSON serialization (sorted keys, no whitespace)."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(csc1(v) for v in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        return "{" + ",".join(json.dumps(k) + ":" + csc1(obj[k]) for k in keys) + "}"
    raise TypeError(f"Unsupported type: {type(obj)}")


def fetch_seal(seal_id: str) -> dict:
    """Fetch a seal from the Crovia API."""
    req = urllib.request.Request(
        SEAL_API + seal_id,
        headers={"User-Agent": "crovia-seal-python/0.1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def verify_seal(seal_id: str, text: str = None) -> dict:
    """
    Verify a Crovia seal.

    Args:
        seal_id: The seal ID (sl_...)
        text: Optional text to verify against the output hash

    Returns:
        dict with keys: valid, seal, signature_ok, hash_ok, errors
    """
    result = {"valid": False, "seal": None, "signature_ok": False, "hash_ok": None, "errors": []}

    # Fetch seal
    try:
        seal = fetch_seal(seal_id)
        result["seal"] = seal
    except Exception as e:
        result["errors"].append(f"Seal fetch failed: {e}")
        return result

    # Verify Ed25519 signature
    try:
        pub_hex = seal.get("issuer", {}).get("pubkey", "")
        sig_hex = seal.get("signature", "")
        payload = {k: v for k, v in seal.items() if k != "signature"}
        canon = csc1(payload)
        message = f"{MESSAGE_PREFIX}\n{canon}".encode("utf-8")

        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)

        vk = VerifyKey(pub_bytes)
        vk.verify(message, sig_bytes)
        result["signature_ok"] = True
    except BadSignatureError:
        result["errors"].append("Ed25519 signature INVALID")
        return result
    except Exception as e:
        result["errors"].append(f"Signature verification error: {e}")
        return result

    # Hash check (if text provided)
    if text is not None:
        expected = seal.get("subject", {}).get("output_hash", "")
        actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
        result["hash_ok"] = actual == expected
        if not result["hash_ok"]:
            result["errors"].append(f"Hash mismatch: expected {expected[:16]}…, got {actual[:16]}…")

    result["valid"] = result["signature_ok"] and (result["hash_ok"] is not False)
    return result
