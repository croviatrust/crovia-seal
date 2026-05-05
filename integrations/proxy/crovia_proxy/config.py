"""
Configuration for the Crovia Proxy.

Every knob is env-driven so operators can deploy the proxy as a sidecar in
container orchestrators without touching Python code. The minimal setup is:

    CROVIA_UPSTREAM_URL=https://api.openai.com
    CROVIA_ISSUER_ID=urn:crovia:seal-issuer:example-org
    CROVIA_ISSUER_PRIVATE_HEX=<64 hex chars>

If `CROVIA_ISSUER_PRIVATE_HEX` is unset, the proxy generates an ephemeral key
at startup and logs the public hex + persists to `~/.crovia/proxy.key` so
subsequent restarts are stable.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_KEY_PATH = Path(os.path.expanduser("~/.crovia/proxy.key"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CROVIA_",
        env_file=os.environ.get("CROVIA_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Upstream ---
    upstream_url: str = Field(
        default="https://api.openai.com",
        description="Base URL of the OpenAI-compatible upstream (OpenAI, Ollama, vLLM, Together, etc.)",
    )
    upstream_timeout_seconds: float = 120.0

    # --- Identity ---
    issuer_id: str = Field(
        default="urn:crovia:seal-issuer:crovia-proxy-local",
        description="URN identifying the issuer that signs emitted seals.",
    )
    issuer_private_hex: Optional[str] = Field(
        default=None,
        description="Ed25519 private key (32-byte hex). If unset, a key is generated and persisted.",
    )
    issuer_key_file: Path = Field(
        default=DEFAULT_KEY_PATH,
        description="Path used to persist a generated key when issuer_private_hex is not provided.",
    )

    # --- Behavior ---
    inject_cim: bool = Field(
        default=True,
        description="Whether to embed a CIM zero-width mark into the response text.",
    )
    emit_response_header: bool = Field(
        default=True,
        description="Emit X-Crovia-Seal-Id and X-Crovia-Seal (base64) response headers.",
    )
    chain_seals: bool = Field(
        default=True,
        description="Chain every new seal to the previous one so the proxy produces an auditable sequence.",
    )
    log_file: Optional[Path] = Field(
        default=None,
        description="If set, append every emitted seal to this JSONL file (one JSON object per line).",
    )
    beacon_anchor: bool = Field(
        default=False,
        description=("Enable Crovia Beacon Anchor: every seal embeds a recent drand randomness "
                     "beacon round, proving the seal could not have been emitted before the "
                     "beacon's timestamp. Requires outbound HTTPS to the configured relay."),
    )
    beacon_relay: str = Field(
        default="https://api.drand.sh",
        description="URL of the drand relay used to fetch beacon rounds.",
    )
    beacon_chain_hash: str = Field(
        default="52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        description="drand chain hash (defaults to Quicknet, 3s period, unchained BLS).",
    )
    beacon_cache_seconds: float = Field(
        default=2.5,
        description="Refetch the beacon at most every N seconds (drand round is 3s so 2.5s is ideal).",
    )

    # --- Server ---
    host: str = "127.0.0.1"
    port: int = 7878

    def resolve_private_hex(self) -> str:
        """Return a private key hex, generating+persisting one if needed."""
        if self.issuer_private_hex:
            return self.issuer_private_hex.strip()
        p = self.issuer_key_file
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
        p.parent.mkdir(parents=True, exist_ok=True)
        hex_key = secrets.token_hex(32)
        p.write_text(hex_key + "\n", encoding="utf-8")
        try:
            # Best-effort restrictive permissions on POSIX; no-op on Windows.
            os.chmod(p, 0o600)
        except OSError:
            pass
        return hex_key
