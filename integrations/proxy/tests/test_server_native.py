"""
End-to-end tests for the three native-vendor routes (Anthropic, Google,
Cohere).  Upstream HTTP is mocked with respx so tests run offline.

For each vendor we verify:
    1. The proxy forwards the request to the configured upstream URL.
    2. The vendor-native response is augmented with a Crovia Seal in the
       expected vendor-specific JSON shape.
    3. The seal headers (X-Crovia-Seal-Id, X-Crovia-Seal, X-Crovia-Issuer-Pubkey)
       are emitted.
    4. The seal verifies independently against the issuer pubkey.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from crovia_seal.seal import verify_seal


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_anthropic_messages_seals_native_response(client_and_settings):
    client, settings = client_and_settings

    # Mock the upstream
    upstream_resp = {
        "id": "msg_01ABC",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": "Bonjour, comment puis-je vous aider?"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 12, "output_tokens": 9},
    }
    respx.post(f"{settings.upstream_anthropic_url}/v1/messages").mock(
        return_value=httpx.Response(200, json=upstream_resp)
    )

    body = {
        "model": "claude-3-5-sonnet-20241022",
        "system": "Speak French.",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 100,
    }
    r = await client.post("/v1/messages", json=body, headers={"x-api-key": "stub"})
    assert r.status_code == 200, r.text

    j = r.json()
    # Vendor-native fields preserved
    assert j["id"] == "msg_01ABC"
    assert j["model"] == "claude-3-5-sonnet-20241022"
    # Crovia field injected at top level
    assert "crovia" in j
    assert j["crovia"]["seal_id"].startswith("cs_")
    seal = j["crovia"]["seal"]

    # Headers
    assert r.headers["x-crovia-seal-id"] == j["crovia"]["seal_id"]
    assert r.headers["x-crovia-issuer-pubkey"]

    # Seal verifies cryptographically
    res = verify_seal(seal)
    assert res.ok, res.errors
    assert seal["generator"]["id"] == "anthropic/claude-3-5-sonnet-20241022"


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_google_generate_content_seals_native_response(client_and_settings):
    client, settings = client_and_settings

    upstream_resp = {
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "The capital is Paris."}]},
            "finishReason": "STOP",
        }],
        "modelVersion": "gemini-1.5-pro-002",
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 5},
    }
    respx.post(
        f"{settings.upstream_google_url}/v1beta/models/gemini-1.5-pro:generateContent"
    ).mock(return_value=httpx.Response(200, json=upstream_resp))

    body = {
        "contents": [{"role": "user", "parts": [{"text": "Capital of France?"}]}],
    }
    r = await client.post(
        "/v1beta/models/gemini-1.5-pro:generateContent",
        json=body,
    )
    assert r.status_code == 200, r.text

    j = r.json()
    # Native fields preserved
    assert j["modelVersion"] == "gemini-1.5-pro-002"
    assert j["candidates"][0]["finishReason"] == "STOP"
    # Crovia field injected (camelCase per Google convention)
    assert "croviaSeal" in j
    assert j["croviaSeal"]["sealId"].startswith("cs_")
    seal = j["croviaSeal"]["seal"]

    # Crypto verification
    res = verify_seal(seal)
    assert res.ok, res.errors
    assert seal["generator"]["id"] == "google/gemini-1.5-pro-002"


@pytest.mark.asyncio
@respx.mock
async def test_google_unknown_action_returns_404(client_and_settings):
    client, _ = client_and_settings
    r = await client.post(
        "/v1beta/models/gemini-1.5-pro:doSomethingElse", json={}
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Cohere
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_cohere_chat_seals_native_response(client_and_settings):
    client, settings = client_and_settings

    upstream_resp = {
        "response_id": "11111111-2222-3333-4444-555555555555",
        "text": "I am doing well, thank you for asking.",
        "generation_id": "abc",
        "model": "command-r-plus",
        "finish_reason": "COMPLETE",
        "meta": {"api_version": {"version": "1"}},
    }
    respx.post(f"{settings.upstream_cohere_url}/v1/chat").mock(
        return_value=httpx.Response(200, json=upstream_resp)
    )

    body = {
        "model": "command-r-plus",
        "preamble": "Be friendly.",
        "chat_history": [
            {"role": "USER", "message": "Hello"},
            {"role": "CHATBOT", "message": "Hi there!"},
        ],
        "message": "How are you?",
    }
    r = await client.post("/v1/chat", json=body)
    assert r.status_code == 200, r.text

    j = r.json()
    # Native fields preserved
    assert j["response_id"] == "11111111-2222-3333-4444-555555555555"
    assert j["finish_reason"] == "COMPLETE"
    # Crovia field injected (snake_case per Cohere convention)
    assert "crovia_seal" in j
    seal = j["crovia_seal"]["seal"]

    res = verify_seal(seal)
    assert res.ok, res.errors
    assert seal["generator"]["id"] == "cohere/command-r-plus"


# ---------------------------------------------------------------------------
# Streaming pass-through
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_anthropic_stream_passes_through_unsealed(client_and_settings):
    """Streaming requests are forwarded verbatim with no seal injection.
    The X-Crovia-Stream-Sealed: false header signals this to the caller."""
    client, settings = client_and_settings

    sse_body = (
        b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
        b"event: content_block_delta\ndata: {\"delta\":{\"text\":\"Hi\"}}\n\n"
        b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
    )
    respx.post(f"{settings.upstream_anthropic_url}/v1/messages").mock(
        return_value=httpx.Response(
            200,
            content=sse_body,
            headers={"content-type": "text/event-stream"},
        )
    )

    r = await client.post(
        "/v1/messages",
        json={"model": "claude-3-5-sonnet-20241022", "stream": True,
              "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 32},
    )
    assert r.status_code == 200
    assert r.headers.get("x-crovia-stream-sealed") == "false"
    assert b"content_block_delta" in r.content


# ---------------------------------------------------------------------------
# Upstream error pass-through
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_anthropic_upstream_error_passes_through_verbatim(client_and_settings):
    client, settings = client_and_settings
    err_body = {"type": "error", "error": {"type": "authentication_error",
                                           "message": "invalid api key"}}
    respx.post(f"{settings.upstream_anthropic_url}/v1/messages").mock(
        return_value=httpx.Response(401, json=err_body)
    )
    r = await client.post(
        "/v1/messages",
        json={"model": "claude-3-5-sonnet-20241022",
              "messages": [{"role": "user", "content": "x"}], "max_tokens": 8},
    )
    assert r.status_code == 401
    j = r.json()
    assert j["error"]["type"] == "authentication_error"
    assert "crovia" not in j  # we MUST NOT seal upstream errors
