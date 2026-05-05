"""
Integration tests for the FastAPI proxy.

Upstream is mocked with `respx` so no real OpenAI traffic is ever sent.
"""
from __future__ import annotations

import base64
import json

import pytest
import respx
from httpx import Response

from crovia_seal import verify_seal, extract_cim


@pytest.mark.asyncio
async def test_health_endpoint(client_and_settings):
    client, settings = client_and_settings
    r = await client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["issuer_id"] == settings.issuer_id
    assert len(data["issuer_pubkey_hex"]) == 64


@pytest.mark.asyncio
async def test_issuer_manifest(client_and_settings):
    client, _ = client_and_settings
    r = await client.get("/.well-known/crovia-issuer.json")
    assert r.status_code == 200
    body = r.json()
    assert body["pubkey"]["alg"] == "Ed25519"
    assert len(body["pubkey"]["key_hex"]) == 64


@pytest.mark.asyncio
@respx.mock
async def test_non_streaming_chat_completion_gets_sealed(client_and_settings):
    client, settings = client_and_settings

    fake_openai = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Hello from the model."},
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
    }
    respx.post("http://mock-upstream/v1/chat/completions").mock(
        return_value=Response(200, json=fake_openai)
    )

    body = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Say hello."}],
        "stream": False,
    }
    r = await client.post("/v1/chat/completions", json=body)
    assert r.status_code == 200

    # Seal present in JSON envelope AND in response headers.
    payload = r.json()
    assert "crovia" in payload
    seal = payload["crovia"]["seal"]
    assert seal["seal_id"].startswith("cs_")
    vr = verify_seal(seal)
    assert vr.ok, vr.errors

    assert r.headers["X-Crovia-Seal-Id"] == seal["seal_id"]
    header_b64 = r.headers["X-Crovia-Seal"]
    decoded = json.loads(base64.b64decode(header_b64))
    assert decoded["seal_id"] == seal["seal_id"]

    # Response message content carries a CIM.
    content = payload["choices"][0]["message"]["content"]
    extracted = extract_cim(content, issuance_year=int(seal["seal_id"].split("_")[1]))
    assert extracted is not None
    assert extracted.seal_id == seal["seal_id"]


@pytest.mark.asyncio
@respx.mock
async def test_upstream_error_is_passed_through_verbatim(client_and_settings):
    client, _ = client_and_settings
    respx.post("http://mock-upstream/v1/chat/completions").mock(
        return_value=Response(429, json={"error": {"message": "rate limit", "type": "rate_limit"}})
    )
    r = await client.post("/v1/chat/completions", json={
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "x"}],
    })
    assert r.status_code == 429
    assert r.json()["error"]["type"] == "rate_limit"
    assert "X-Crovia-Seal-Id" not in r.headers  # no seal on error


@pytest.mark.asyncio
@respx.mock
async def test_invalid_request_body_is_rejected(client_and_settings):
    client, _ = client_and_settings
    r = await client.post(
        "/v1/chat/completions",
        content=b"this is not json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "crovia_proxy"


@pytest.mark.asyncio
@respx.mock
async def test_streaming_chat_completion_emits_final_crovia_event(client_and_settings):
    client, _ = client_and_settings

    def sse(chunks: list[dict]) -> bytes:
        parts = []
        for ch in chunks:
            parts.append(b"data: " + json.dumps(ch).encode("utf-8") + b"\n\n")
        parts.append(b"data: [DONE]\n\n")
        return b"".join(parts)

    upstream_body = sse([
        {"choices": [{"index": 0, "delta": {"role": "assistant"}}], "model": "gpt-4o"},
        {"choices": [{"index": 0, "delta": {"content": "Hello "}}], "model": "gpt-4o"},
        {"choices": [{"index": 0, "delta": {"content": "world"}}], "model": "gpt-4o"},
        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "model": "gpt-4o"},
    ])

    respx.post("http://mock-upstream/v1/chat/completions").mock(
        return_value=Response(200, content=upstream_body, headers={"content-type": "text/event-stream"})
    )

    req = {
        "model": "gpt-4o",
        "stream": True,
        "messages": [{"role": "user", "content": "Hi."}],
    }
    r = await client.post("/v1/chat/completions", json=req)
    assert r.status_code == 200

    text = r.text
    # Original deltas preserved
    assert "Hello " in text and "world" in text
    # Our synthetic crovia event is emitted EXACTLY once, before [DONE].
    assert text.count("[DONE]") == 1
    assert '"crovia"' in text

    # Extract the crovia event and validate the seal.
    # The event is the data: line that contains "crovia":
    crovia_lines = [l for l in text.splitlines() if l.startswith("data: ") and '"crovia"' in l]
    assert len(crovia_lines) == 1
    event = json.loads(crovia_lines[0][len("data: "):])
    seal = event["crovia"]["seal"]
    vr = verify_seal(seal)
    assert vr.ok, vr.errors


@pytest.mark.asyncio
@respx.mock
async def test_empty_output_choices_skip_sealing(client_and_settings):
    client, _ = client_and_settings
    fake = {
        "id": "x", "object": "chat.completion", "created": 0, "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "finish_reason": "function_call",
            "message": {"role": "assistant", "content": None,
                        "function_call": {"name": "f", "arguments": "{}"}},
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 0, "total_tokens": 1},
    }
    respx.post("http://mock-upstream/v1/chat/completions").mock(return_value=Response(200, json=fake))
    r = await client.post("/v1/chat/completions", json={
        "model": "gpt-4o", "messages": [{"role": "user", "content": "call f"}],
    })
    assert r.status_code == 200
    data = r.json()
    assert "crovia" not in data       # no text -> no seal
    assert "X-Crovia-Seal-Id" not in r.headers

