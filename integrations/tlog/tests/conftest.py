from __future__ import annotations

import secrets
from pathlib import Path
from typing import Iterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from crovia_tlog.config import Settings
from crovia_tlog.server import create_app


@pytest.fixture
def settings_factory(tmp_path: Path):
    def make(**overrides) -> Settings:
        defaults = {
            "log_id": "urn:crovia:tlog:test",
            "db_path": tmp_path / "tlog.db",
            "log_key_file": tmp_path / "log.key",
            "log_private_hex": secrets.token_hex(32),
        }
        defaults.update(overrides)
        return Settings(**defaults)
    return make


@pytest_asyncio.fixture
async def client_and_settings(settings_factory) -> Iterator[tuple[AsyncClient, Settings]]:
    settings = settings_factory()
    app = create_app(settings)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c, settings


@pytest.fixture
def sample_seal():
    """Emit a real, verifiable Seal using the core Python lib."""
    from crovia_seal import emit_seal, generate_issuer_key
    key = generate_issuer_key("urn:crovia:seal-issuer:tlog-tests")
    return emit_seal(
        issuer_key=key,
        input_bytes=b"prompt",
        output_bytes=b"response",
        modality="text",
        generator_id="test/model",
        generator_version="v1",
    )
