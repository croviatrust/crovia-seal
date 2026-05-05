"""
Vendor-specific adapters for the Crovia Proxy.

Each adapter knows how to:
    1. Translate a vendor-native request body into a stable canonical input
       string (so the same conversation produces the same input_hash).
    2. Extract the assistant's output text from a vendor-native response.
    3. Inject a Crovia Seal back into the response in the vendor's native
       JSON shape, so downstream clients that already speak that vendor's
       protocol can keep working unchanged AND optionally read the seal.

The OpenAI-compatible path (`/v1/chat/completions`) is handled directly by
`server.py` for historical reasons; this module covers the three remaining
top-tier providers:

    /v1/messages                                       -> Anthropic Messages API
    /v1beta/models/{model}:generateContent             -> Google Gemini
    /v1beta/models/{model}:streamGenerateContent       -> Google Gemini (stream)
    /v1/chat                                           -> Cohere Chat API

The adapter contract intentionally sticks to **non-streaming** translation
(the streaming path varies wildly across vendors and is added per-vendor as
needed).  Non-streaming covers >95% of programmatic verification use cases.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from crovia_proxy.sealer import SealedResponse


# ---------------------------------------------------------------------------
# Common utilities
# ---------------------------------------------------------------------------

def _render_content_blocks(content: Any) -> str:
    """Render a polymorphic `content` field (string OR list of typed parts)
    into a stable text form.  Same convention as the OpenAI adapter so that
    cross-vendor input_hash equivalence is preserved when the same logical
    text is sent."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out: List[str] = []
        for item in content:
            if isinstance(item, dict):
                tp = item.get("type", "unknown")
                if tp == "text":
                    out.append(f"[text]{item.get('text', '')}")
                elif tp in ("image", "image_url"):
                    if "source" in item and isinstance(item["source"], dict):
                        # Anthropic shape: {type: "image", source: {...}}
                        src = item["source"]
                        media_type = src.get("media_type") or src.get("type", "")
                        out.append(f"[image:{media_type}]{src.get('data', '')[:64]}")
                    else:
                        url = item.get("image_url", {}).get("url", "") if isinstance(item.get("image_url"), dict) else ""
                        out.append(f"[image]{url}")
                elif tp == "tool_use":
                    out.append(f"[tool_use:{item.get('name','')}]{json.dumps(item.get('input', {}), sort_keys=True)}")
                elif tp == "tool_result":
                    out.append(f"[tool_result:{item.get('tool_use_id','')}]{_render_content_blocks(item.get('content',''))}")
                else:
                    out.append(f"[{tp}]{json.dumps(item, sort_keys=True)}")
            else:
                out.append(str(item))
        return "\n".join(out)
    # null, bool, number → JSON canonical
    return json.dumps(content, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Anthropic Messages API
# ---------------------------------------------------------------------------
# https://docs.anthropic.com/en/api/messages
#
# Request (POST /v1/messages):
#   {
#     "model": "claude-3-5-sonnet-20241022",
#     "system": "...",                          (optional)
#     "messages": [{"role": "user"|"assistant", "content": "..." | [parts]}],
#     "max_tokens": 1024
#   }
#
# Response:
#   {
#     "id": "msg_...",
#     "type": "message",
#     "role": "assistant",
#     "model": "claude-3-5-sonnet-20241022",
#     "content": [{"type": "text", "text": "..."}, ...],
#     "stop_reason": "end_turn",
#     "usage": {...}
#   }


class AnthropicAdapter:
    name = "anthropic"
    upstream_path = "/v1/messages"
    default_upstream_url = "https://api.anthropic.com"

    @staticmethod
    def extract_input_text(body: Dict[str, Any]) -> str:
        lines: List[str] = []
        sysmsg = body.get("system")
        if sysmsg:
            # Anthropic 2024+ allows system to be a string OR a list of {type:text, text:...}
            lines.append(f"system: {_render_content_blocks(sysmsg)}")
        for m in body.get("messages") or []:
            role = str(m.get("role", "")).strip()
            rendered = _render_content_blocks(m.get("content", ""))
            lines.append(f"{role}: {rendered}")
        return "\n---\n".join(lines)

    @staticmethod
    def extract_output_text(resp_json: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        chunks: List[str] = []
        for blk in resp_json.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "text":
                txt = blk.get("text", "")
                if isinstance(txt, str) and txt:
                    chunks.append(txt)
        joined = "\n\n".join(chunks)
        meta = {
            "generator_id": "anthropic/" + str(resp_json.get("model", "unknown")),
            "generator_version": resp_json.get("model"),
        }
        return joined, meta

    @staticmethod
    def inject_seal(resp_json: Dict[str, Any], sealed: SealedResponse,
                    joined_output: str) -> Dict[str, Any]:
        # Append CIM appendix to the LAST text block (preserves token semantics).
        if sealed.cim_embedded:
            appendix = sealed.modified_output_text[len(joined_output):]
            for blk in reversed(resp_json.get("content") or []):
                if isinstance(blk, dict) and blk.get("type") == "text":
                    blk["text"] = blk.get("text", "") + appendix
                    break
        # Anthropic responses are open-shaped objects; we add a top-level "crovia"
        # field just like OpenAI.  Anthropic's strict-typed clients will ignore
        # unknown fields.
        resp_json["crovia"] = {
            "seal_id": sealed.seal_id,
            "seal": sealed.seal,
        }
        return resp_json


# ---------------------------------------------------------------------------
# Google Gemini generateContent
# ---------------------------------------------------------------------------
# https://ai.google.dev/api/generate-content
#
# Request (POST /v1beta/models/{model}:generateContent):
#   {
#     "contents": [{"role": "user"|"model", "parts": [{"text": "..."} | {"inlineData": {...}}]}],
#     "systemInstruction": {"parts": [{"text": "..."}]},   (optional)
#     "generationConfig": {...}
#   }
#
# Response:
#   {
#     "candidates": [{"content": {"role": "model", "parts": [{"text": "..."}]},
#                     "finishReason": "STOP", ...}],
#     "modelVersion": "gemini-1.5-pro-002",
#     "usageMetadata": {...}
#   }


class GoogleAdapter:
    name = "google"
    upstream_path = "/v1beta/models"  # actual path includes :generateContent suffix
    default_upstream_url = "https://generativelanguage.googleapis.com"

    @staticmethod
    def _render_parts(parts: List[Dict[str, Any]]) -> str:
        out: List[str] = []
        for p in parts or []:
            if "text" in p:
                out.append(f"[text]{p['text']}")
            elif "inlineData" in p:
                d = p["inlineData"]
                mt = d.get("mimeType", "")
                out.append(f"[inline:{mt}]{(d.get('data') or '')[:64]}")
            elif "fileData" in p:
                fd = p["fileData"]
                out.append(f"[file:{fd.get('mimeType','')}]{fd.get('fileUri','')}")
            elif "functionCall" in p:
                fc = p["functionCall"]
                out.append(f"[fn_call:{fc.get('name','')}]{json.dumps(fc.get('args',{}), sort_keys=True)}")
            elif "functionResponse" in p:
                fr = p["functionResponse"]
                out.append(f"[fn_resp:{fr.get('name','')}]{json.dumps(fr.get('response',{}), sort_keys=True)}")
            else:
                out.append(json.dumps(p, sort_keys=True, ensure_ascii=False))
        return "\n".join(out)

    @staticmethod
    def extract_input_text(body: Dict[str, Any]) -> str:
        lines: List[str] = []
        sys_inst = body.get("systemInstruction") or body.get("system_instruction")
        if isinstance(sys_inst, dict):
            lines.append(f"system: {GoogleAdapter._render_parts(sys_inst.get('parts') or [])}")
        for c in body.get("contents") or []:
            role = str(c.get("role", "")).strip()
            rendered = GoogleAdapter._render_parts(c.get("parts") or [])
            lines.append(f"{role}: {rendered}")
        return "\n---\n".join(lines)

    @staticmethod
    def extract_output_text(resp_json: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        chunks: List[str] = []
        for cand in resp_json.get("candidates") or []:
            content = cand.get("content") or {}
            for p in content.get("parts") or []:
                if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"]:
                    chunks.append(p["text"])
        joined = "\n\n".join(chunks)
        version = resp_json.get("modelVersion") or resp_json.get("model")
        meta = {
            "generator_id": "google/" + str(version or "gemini-unknown"),
            "generator_version": version,
        }
        return joined, meta

    @staticmethod
    def inject_seal(resp_json: Dict[str, Any], sealed: SealedResponse,
                    joined_output: str) -> Dict[str, Any]:
        if sealed.cim_embedded:
            appendix = sealed.modified_output_text[len(joined_output):]
            cands = resp_json.get("candidates") or []
            for cand in reversed(cands):
                parts = (cand.get("content") or {}).get("parts") or []
                for p in reversed(parts):
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        p["text"] = p["text"] + appendix
                        break
                else:
                    continue
                break
        # Top-level extension field per Google JSON convention (camelCase).
        resp_json["croviaSeal"] = {
            "sealId": sealed.seal_id,
            "seal": sealed.seal,
        }
        return resp_json


# ---------------------------------------------------------------------------
# Cohere Chat (v1)
# ---------------------------------------------------------------------------
# https://docs.cohere.com/reference/chat
#
# Request (POST /v1/chat):
#   {
#     "model": "command-r-plus",
#     "message": "...",                   (current user message)
#     "chat_history": [{"role":"USER"|"CHATBOT","message":"..."}],
#     "preamble": "..." (system),
#     "documents": [...],
#     "temperature": 0.7
#   }
#
# Response:
#   {
#     "response_id": "...",
#     "text": "...",
#     "generation_id": "...",
#     "meta": {"api_version":{"version":"1"},...},
#     "finish_reason": "COMPLETE"
#   }


class CohereAdapter:
    name = "cohere"
    upstream_path = "/v1/chat"
    default_upstream_url = "https://api.cohere.com"

    @staticmethod
    def extract_input_text(body: Dict[str, Any]) -> str:
        lines: List[str] = []
        preamble = body.get("preamble")
        if preamble:
            lines.append(f"system: {preamble}")
        for h in body.get("chat_history") or []:
            role = str(h.get("role", "")).strip().lower()
            msg = h.get("message", "")
            lines.append(f"{role}: {msg}")
        cur = body.get("message")
        if cur:
            lines.append(f"user: {cur}")
        return "\n---\n".join(lines)

    @staticmethod
    def extract_output_text(resp_json: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        text = resp_json.get("text", "") or ""
        # Cohere puts model id back in `meta` only on some endpoints; we accept
        # `model` echoed back when present.
        version = resp_json.get("model") or (resp_json.get("meta") or {}).get("model")
        meta = {
            "generator_id": "cohere/" + str(version or "command-r-unknown"),
            "generator_version": version,
        }
        return text, meta

    @staticmethod
    def inject_seal(resp_json: Dict[str, Any], sealed: SealedResponse,
                    joined_output: str) -> Dict[str, Any]:
        if sealed.cim_embedded:
            appendix = sealed.modified_output_text[len(joined_output):]
            resp_json["text"] = (resp_json.get("text") or "") + appendix
        # Cohere convention: top-level ad-hoc field.
        resp_json["crovia_seal"] = {
            "seal_id": sealed.seal_id,
            "seal": sealed.seal,
        }
        return resp_json


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ADAPTERS: Dict[str, Any] = {
    AnthropicAdapter.name: AnthropicAdapter,
    GoogleAdapter.name:    GoogleAdapter,
    CohereAdapter.name:    CohereAdapter,
}


def get_adapter(name: str):
    """Return the adapter class for `name`.  Raises KeyError if unknown."""
    return ADAPTERS[name]


def list_adapter_names() -> List[str]:
    return list(ADAPTERS.keys())
