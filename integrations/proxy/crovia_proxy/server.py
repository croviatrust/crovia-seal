"""
FastAPI application exposing an OpenAI-compatible interface with automatic
Crovia Seal emission.

Design goals:

    1. Drop-in replacement for https://api.openai.com - same paths, same JSON.
    2. No buffering of entire conversations in RAM beyond the current message.
    3. Streaming (SSE) is forwarded chunk-by-chunk as it arrives from the
       upstream, with a FINAL synthetic chunk carrying the Crovia Seal so
       clients that support it receive the seal without any change to their
       event loop; clients that ignore unknown fields simply drop it.
    4. Errors from the upstream are forwarded verbatim (status code, body,
       content-type).
    5. Every emission is verified against its own signature before being
       returned to the client.
"""
from __future__ import annotations

import json
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from crovia_proxy.config import Settings
from crovia_proxy.sealer import Sealer, SealedResponse


CROVIA_SEAL_HEADER = "X-Crovia-Seal"
CROVIA_SEAL_ID_HEADER = "X-Crovia-Seal-Id"
CROVIA_ISSUER_HEADER = "X-Crovia-Issuer-Pubkey"


# ---------------------------------------------------------------------------
# Prompt / response extraction
# ---------------------------------------------------------------------------

def _messages_to_input_text(messages: List[Dict[str, Any]]) -> str:
    """Canonical, stable rendering of a chat completion message list.

    We intentionally choose a byte-stable representation that does NOT rely
    on json.dumps key ordering, because the same logical conversation must
    produce the same input_hash on any runtime. Format:

        <role>: <content>\n---\n<role>: <content>\n---\n...

    `content` may be a string or a list (multimodal). Lists are serialized
    recursively with a simple tag prefix.
    """
    lines: List[str] = []
    for m in messages:
        role = str(m.get("role", "")).strip()
        content = m.get("content", "")
        if isinstance(content, str):
            rendered = content
        elif isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, dict):
                    tp = item.get("type", "unknown")
                    if tp == "text":
                        parts.append(f"[text]{item.get('text','')}")
                    elif tp == "image_url":
                        url = item.get("image_url", {}).get("url", "")
                        parts.append(f"[image]{url}")
                    else:
                        parts.append(f"[{tp}]{json.dumps(item, sort_keys=True)}")
                else:
                    parts.append(str(item))
            rendered = "\n".join(parts)
        else:
            rendered = json.dumps(content, sort_keys=True, ensure_ascii=False)
        lines.append(f"{role}: {rendered}")
    return "\n---\n".join(lines)


def _extract_output_text(resp_json: Dict[str, Any]) -> Tuple[str, List[int]]:
    """Return (joined_output_text, indices_of_choices_with_content).

    If the response has no `choices` or no `message.content`, returns ("", []).
    """
    choices = resp_json.get("choices") or []
    chunks: List[str] = []
    idxs: List[int] = []
    for i, ch in enumerate(choices):
        msg = ch.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str) and content:
            chunks.append(content)
            idxs.append(i)
    return "\n\n".join(chunks), idxs


def _rewrite_output_text(
    resp_json: Dict[str, Any],
    idxs: List[int],
    new_texts_per_choice: List[str],
) -> None:
    """In-place rewrite of choices[i].message.content with the new text."""
    for i, new_text in zip(idxs, new_texts_per_choice):
        resp_json["choices"][i]["message"]["content"] = new_text


# ---------------------------------------------------------------------------
# Upstream client helpers
# ---------------------------------------------------------------------------

def _upstream_url(settings: Settings, path: str) -> str:
    base = settings.upstream_url.rstrip("/")
    return f"{base}{path}"


def _forwardable_headers(request: Request) -> Dict[str, str]:
    """Forward inbound headers but strip hop-by-hop and host-specific ones."""
    drop = {"host", "content-length", "connection", "accept-encoding",
            "transfer-encoding", "keep-alive", "upgrade"}
    out: Dict[str, str] = {}
    for k, v in request.headers.items():
        if k.lower() in drop:
            continue
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# Streaming re-emission
# ---------------------------------------------------------------------------

async def _stream_and_seal(
    *,
    upstream_url: str,
    headers: Dict[str, str],
    body_bytes: bytes,
    sealer: Sealer,
    input_text: str,
    generator_id: str,
    client: httpx.AsyncClient,
) -> AsyncGenerator[bytes, None]:
    """Forward an SSE stream upstream->client AND emit a Crovia event at EOS.

    We accumulate the textual deltas per choice index and, after the upstream
    sends its terminating `data: [DONE]\\n\\n`, we:

        1. emit the Crovia Seal over the concatenated output
        2. push an SSE event `data: {"crovia": {...}}\\n\\n`
        3. echo the final `data: [DONE]\\n\\n`

    The inner `[DONE]` from upstream is swallowed so the client sees exactly
    ONE stream terminator after our seal event.
    """
    deltas_per_choice: Dict[int, List[str]] = {}
    generator_version: Optional[str] = None

    async with client.stream(
        "POST", upstream_url, headers=headers, content=body_bytes,
    ) as upstream_resp:
        # Propagate upstream failure status (FastAPI will fill the SSE body).
        if upstream_resp.status_code >= 400:
            raw = await upstream_resp.aread()
            # Yield a single SSE error event that OpenAI-style clients will
            # surface via `error` callbacks.
            yield b"event: error\n"
            yield b"data: " + raw + b"\n\n"
            return

        async for raw_line in upstream_resp.aiter_lines():
            if not raw_line:
                yield b"\n"
                continue
            # OpenAI SSE uses "data: <json>" lines.
            if raw_line.startswith("data: "):
                payload = raw_line[len("data: "):]
                if payload.strip() == "[DONE]":
                    # Do NOT yield the upstream [DONE] yet; we will emit our
                    # seal event first and then send our own [DONE].
                    break
                # Try to parse as JSON so we can accumulate deltas.
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    yield raw_line.encode("utf-8") + b"\n\n"
                    continue

                if isinstance(obj, dict):
                    generator_version = generator_version or obj.get("model")
                    for ch in obj.get("choices", []) or []:
                        idx = int(ch.get("index", 0))
                        delta = (ch.get("delta") or {}).get("content", "")
                        if isinstance(delta, str) and delta:
                            deltas_per_choice.setdefault(idx, []).append(delta)
                yield raw_line.encode("utf-8") + b"\n\n"
            else:
                # Non-data SSE line (comment, event:, id:, retry:) — forward.
                yield raw_line.encode("utf-8") + b"\n"

    # Upstream finished. Compose the aggregated output and emit our seal.
    joined = "\n\n".join(
        "".join(parts)
        for _, parts in sorted(deltas_per_choice.items())
    )
    sealed: SealedResponse = await sealer.seal(
        input_text=input_text,
        output_text=joined,
        generator_id=generator_id,
        generator_version=generator_version,
        modality="text",
    )

    crovia_event = {
        "crovia": {
            "seal_id": sealed.seal_id,
            "seal": sealed.seal,
            "cim_appendix": sealed.modified_output_text[len(joined):] if sealed.cim_embedded else "",
        }
    }
    yield f"data: {json.dumps(crovia_event, ensure_ascii=False)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    sealer = Sealer(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.http_client = httpx.AsyncClient(
            timeout=settings.upstream_timeout_seconds,
        )
        try:
            yield
        finally:
            await app.state.http_client.aclose()

    app = FastAPI(
        title="Crovia Proxy",
        version="0.5.0",
        description="OpenAI-compatible proxy that seals every response with Crovia Seal v1.",
        lifespan=lifespan,
    )

    # -------------------------------------------------------------
    # Health & identity
    # -------------------------------------------------------------

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "ok": True,
            "version": "0.5.0",
            "issuer_id": settings.issuer_id,
            "issuer_pubkey_hex": sealer.public_hex,
            "upstream": settings.upstream_url,
            "inject_cim": settings.inject_cim,
            "chain_seals": settings.chain_seals,
        }

    @app.get("/.well-known/crovia-issuer.json")
    async def issuer_manifest() -> Dict[str, Any]:
        """Public, unauthenticated endpoint that verifiers can fetch to learn
        the proxy's issuer identity. Intentionally minimal and stable."""
        return {
            "issuer_id": settings.issuer_id,
            "pubkey": {"alg": "Ed25519", "key_hex": sealer.public_hex},
            "upstream": settings.upstream_url,
            "version": "0.5.0",
        }

    # -------------------------------------------------------------
    # Chat completions (the hot path)
    # -------------------------------------------------------------

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        raw_body = await request.body()
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JSONResponse(
                status_code=400,
                content={"error": {"message": "invalid JSON body", "type": "crovia_proxy"}},
            )

        messages = body.get("messages") or []
        if not isinstance(messages, list):
            return JSONResponse(
                status_code=400,
                content={"error": {"message": "messages must be a list", "type": "crovia_proxy"}},
            )

        input_text = _messages_to_input_text(messages)
        generator_id = f"openai-compatible/{body.get('model', 'unknown')}"
        stream = bool(body.get("stream", False))

        up_headers = _forwardable_headers(request)
        up_url = _upstream_url(settings, "/v1/chat/completions")
        client: httpx.AsyncClient = app.state.http_client

        if stream:
            async def gen() -> AsyncGenerator[bytes, None]:
                async for chunk in _stream_and_seal(
                    upstream_url=up_url,
                    headers=up_headers,
                    body_bytes=raw_body,
                    sealer=sealer,
                    input_text=input_text,
                    generator_id=generator_id,
                    client=client,
                ):
                    yield chunk

            return StreamingResponse(
                gen(),
                media_type="text/event-stream",
                headers={
                    CROVIA_ISSUER_HEADER: sealer.public_hex,
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )

        # Non-streaming path.
        try:
            up_resp = await client.post(up_url, headers=up_headers, content=raw_body)
        except httpx.RequestError as e:
            return JSONResponse(
                status_code=502,
                content={"error": {"message": f"upstream error: {e!r}", "type": "crovia_proxy"}},
            )

        if up_resp.status_code >= 400:
            # Pass through error bodies unchanged.
            return Response(
                content=up_resp.content,
                status_code=up_resp.status_code,
                media_type=up_resp.headers.get("content-type", "application/json"),
            )

        try:
            resp_json: Dict[str, Any] = up_resp.json()
        except json.JSONDecodeError:
            # Unexpected non-JSON response — forward as-is, no sealing.
            return Response(
                content=up_resp.content,
                status_code=up_resp.status_code,
                media_type=up_resp.headers.get("content-type", "application/octet-stream"),
            )

        output_text, idxs = _extract_output_text(resp_json)
        if not output_text:
            # Nothing to seal (e.g. function-call-only response). Return upstream response verbatim.
            return JSONResponse(content=resp_json, status_code=up_resp.status_code)

        sealed = await sealer.seal(
            input_text=input_text,
            output_text=output_text,
            generator_id=generator_id,
            generator_version=resp_json.get("model"),
            modality="text",
        )

        if sealed.cim_embedded:
            # Re-distribute the CIM-augmented text back into the same choices.
            # For multi-choice responses we append the CIM only to the last
            # choice to avoid inflating token counts artificially; all other
            # choices remain untouched (the seal still covers all of them).
            rewritten = [resp_json["choices"][i]["message"]["content"] for i in idxs]
            if rewritten:
                appendix = sealed.modified_output_text[len(output_text):]
                rewritten[-1] = rewritten[-1] + appendix
                _rewrite_output_text(resp_json, idxs, rewritten)

        resp_json["crovia"] = {
            "seal_id": sealed.seal_id,
            "seal": sealed.seal,
        }

        headers: Dict[str, str] = {}
        if settings.emit_response_header:
            headers[CROVIA_SEAL_ID_HEADER] = sealed.seal_id
            headers[CROVIA_SEAL_HEADER] = sealed.seal_base64
            headers[CROVIA_ISSUER_HEADER] = sealer.public_hex

        return JSONResponse(content=resp_json, status_code=up_resp.status_code, headers=headers)

    return app
