"""
Live registration test — signs a receipt with the Python SDK and posts
it to the real production anchor service.

Run:  python examples/register_live.py
"""
import sys
import time

from crovia_seal import generate_key, register, seal, verify


def main() -> int:
    key = generate_key()
    print(f"[test] generated key, signer = {key.public_hex[:20]}…")

    payload = {
        "test": "live-register-py",
        "timestamp_local": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "random": int.from_bytes(__import__("os").urandom(4), "big"),
    }

    r = seal(payload, key=key, payload_type="test/live-py")
    print(f"[test] sealed: {r['id']}")

    v = verify(r, payload)
    print(f"[test] local verify: {'VALID' if v.valid else 'INVALID'}")
    if not v.valid:
        print("[test] cannot register an invalid local seal")
        return 1

    print("[test] posting to https://croviatrust.com/api/anchor …")
    ack = register(r)
    print(f"[test] register result: accepted={ack.accepted} status={ack.status} "
          f"anchor_id={ack.anchor_id} duplicate={ack.duplicate}")

    if not ack.accepted:
        print(f"[test] registration FAILED: {ack.error}")
        return 1

    # Idempotency.
    ack2 = register(r)
    print(f"[test] re-register (idempotent): accepted={ack2.accepted} "
          f"anchor_id={ack2.anchor_id} duplicate={ack2.duplicate}")

    # Tampered receipt must be rejected.
    tampered = dict(r)
    sig = r["sig"]
    tampered["sig"] = ("1" if sig[0] == "0" else "0") + sig[1:]
    ack3 = register(tampered)
    if ack3.accepted:
        print("[test] register tampered: ACCEPTED ✗ BUG")
        return 1
    print(f"[test] register tampered (must reject): REJECTED ✓ ({ack3.error})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
