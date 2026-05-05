"""
Shared test fixtures.

We spin up the FastAPI app with an ephemeral issuer key and a tmp log file
per test so cases are isolated and reproducible.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Iterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from crovia_proxy.config import Settings
from crovia_proxy.server import create_app


@pytest.fixture
def settings_factory(tmp_path: Path):
    """Return a callable producing fresh Settings for each test."""
    def make(**overrides) -> Settings:
        defaults = {
            "upstream_url": "http://mock-upstream",
            "issuer_id": "urn:crovia:seal-issuer:test",
            "issuer_private_hex": secrets.token_hex(32),
            "issuer_key_file": tmp_path / "issuer.key",
            "log_file": tmp_path / "audit.jsonl",
        }
        defaults.update(overrides)   # explicit overrides win
        return Settings(**defaults)
    return make


@pytest_asyncio.fixture
async def client_and_settings(settings_factory) -> Iterator[tuple[AsyncClient, Settings]]:
    settings = settings_factory()
    app = create_app(settings)
    # Drive the FastAPI lifespan context manually so that startup hooks
    # (e.g. http_client) run under ASGITransport which does not trigger
    # lifespan events on its own.
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as c:
            yield c, settings
