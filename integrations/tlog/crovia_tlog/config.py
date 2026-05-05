"""Crovia TLog configuration (env-driven, 12-factor friendly)."""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_DIR = Path(os.path.expanduser("~/.crovia/tlog"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CROVIA_TLOG_",
        env_file=os.environ.get("CROVIA_TLOG_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    log_id: str = Field(
        default="urn:crovia:tlog:local",
        description="Stable identifier of this log instance. Clients pin this value.",
    )
    db_path: Path = Field(
        default=DEFAULT_DIR / "tlog.db",
        description="Path to the SQLite database holding the append-only leaf sequence.",
    )
    log_private_hex: Optional[str] = Field(
        default=None,
        description="Ed25519 private key used to sign STHs. Auto-generated if unset.",
    )
    log_key_file: Path = Field(
        default=DEFAULT_DIR / "log.key",
        description="File where an auto-generated private key is persisted.",
    )
    require_valid_seal: bool = Field(
        default=True,
        description="If true, POST /leaves verifies the submitted Seal signature before accepting.",
    )
    host: str = "127.0.0.1"
    port: int = 7979

    def resolve_private_hex(self) -> str:
        if self.log_private_hex:
            return self.log_private_hex.strip()
        p = self.log_key_file
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
        p.parent.mkdir(parents=True, exist_ok=True)
        hex_key = secrets.token_hex(32)
        p.write_text(hex_key + "\n", encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return hex_key
