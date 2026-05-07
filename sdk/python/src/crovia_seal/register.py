"""
register() — optional opt-in: post a receipt to the Crovia substrate.

`seal()` and `verify()` work fully offline. `register()` is what causes
a receipt to participate in the public continuity graph.

The `requests` library is imported lazily so the core SDK stays
dependency-light if registration isn't used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

DEFAULT_ENDPOINT = "https://croviatrust.com"
DEFAULT_TIMEOUT_SEC = 10.0
USER_AGENT = "crovia-seal-py/0.1.0"


@dataclass
class RegisterResult:
    accepted: bool
    status: int
    anchor_id: Optional[str] = None
    error: Optional[str] = None
    duplicate: bool = False


def register(
    receipt: Dict[str, Any],
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> RegisterResult:
    """Register a receipt with the Crovia substrate.

    Returns a RegisterResult describing whether the substrate accepted the
    receipt. Network errors are returned as fields, not raised.
    """
    try:
        import requests  # noqa: PLC0415  — lazy import (optional dep)
    except ImportError:
        return RegisterResult(
            accepted=False,
            status=0,
            error="missing optional dependency 'requests'; install crovia-seal[register]",
        )

    url = endpoint.rstrip("/") + "/api/anchor"
    try:
        r = requests.post(
            url,
            json={"receipt": receipt},
            timeout=timeout_sec,
            headers={
                "user-agent": USER_AGENT,
                "content-type": "application/json",
            },
        )
    except requests.RequestException as e:
        return RegisterResult(accepted=False, status=0, error=str(e))

    body: Optional[Dict[str, Any]] = None
    try:
        body = r.json()
    except ValueError:
        body = None

    if r.ok:
        return RegisterResult(
            accepted=True,
            status=r.status_code,
            anchor_id=(body or {}).get("anchor_id"),
            duplicate=bool((body or {}).get("duplicate", False)),
        )
    return RegisterResult(
        accepted=False,
        status=r.status_code,
        error=(body or {}).get("error", f"HTTP {r.status_code}"),
    )
