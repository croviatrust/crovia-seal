"""
Unit tests for vendor adapters: Anthropic, Google Gemini, Cohere.

We test pure adapter logic (input extraction, output extraction, seal
injection) without spinning up an upstream — vendor APIs are mocked at the
HTTP layer in `test_server_native.py`.
"""
from __future__ import annotations

import pytest

from crovia_proxy.vendors import (
    AnthropicAdapter,
    GoogleAdapter,
    CohereAdapter,
    list_adapter_names,
    get_adapter,
)


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------

def test_registry_lists_all_three():
    names = list_adapter_names()
    assert set(names) == {"anthropic", "google", "cohere"}


def test_get_adapter_returns_concrete_classes():
    assert get_adapter("anthropic") is AnthropicAdapter
    assert get_adapter("google") is GoogleAdapter
    assert get_adapter("cohere") is CohereAdapter


def test_get_adapter_unknown_raises():
    with pytest.raises(KeyError):
        get_adapter("openai")  # served directly, not via adapter


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class TestAnthropic:
    def test_extract_input_text_string_content(self):
        body = {
            "system": "Be brief.",
            "messages": [
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": "Hello!"},
            ],
        }
        out = AnthropicAdapter.extract_input_text(body)
        assert out == "system: Be brief.\n---\nuser: Hi\n---\nassistant: Hello!"

    def test_extract_input_text_block_content(self):
        body = {
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Look at this:"},
                    {"type": "image", "source": {
                        "type": "base64", "media_type": "image/png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAA" * 5,
                    }},
                ]},
            ],
        }
        out = AnthropicAdapter.extract_input_text(body)
        assert out.startswith("user: [text]Look at this:\n[image:image/png]")

    def test_extract_output_text_single_block(self):
        resp = {
            "content": [{"type": "text", "text": "The capital is Paris."}],
            "model": "claude-3-5-sonnet-20241022",
        }
        out, meta = AnthropicAdapter.extract_output_text(resp)
        assert out == "The capital is Paris."
        assert meta["generator_id"] == "anthropic/claude-3-5-sonnet-20241022"
        assert meta["generator_version"] == "claude-3-5-sonnet-20241022"

    def test_extract_output_text_multi_block_concatenates(self):
        resp = {
            "content": [
                {"type": "text", "text": "First."},
                {"type": "tool_use", "name": "lookup", "input": {}},
                {"type": "text", "text": "Second."},
            ],
            "model": "claude-3-5-sonnet-20241022",
        }
        out, _ = AnthropicAdapter.extract_output_text(resp)
        assert out == "First.\n\nSecond."

    def test_inject_seal_appends_cim_to_last_text_block(self):
        from crovia_proxy.sealer import SealedResponse
        sealed = SealedResponse(
            seal_id="cs_2026_TEST",
            seal={"seal_id": "cs_2026_TEST"},
            seal_base64="b64",
            modified_output_text="Hello world." + "\u200b\u200c",
            cim_embedded=True,
        )
        resp = {"content": [{"type": "text", "text": "Hello world."}],
                "model": "claude-3-5-sonnet-20241022"}
        out = AnthropicAdapter.inject_seal(resp, sealed, "Hello world.")
        assert out["content"][0]["text"] == "Hello world.\u200b\u200c"
        assert out["crovia"]["seal_id"] == "cs_2026_TEST"


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------

class TestGoogle:
    def test_extract_input_text_with_system_instruction(self):
        body = {
            "systemInstruction": {"parts": [{"text": "Reply with one word."}]},
            "contents": [
                {"role": "user", "parts": [{"text": "Capital of France?"}]},
            ],
        }
        out = GoogleAdapter.extract_input_text(body)
        assert out == "system: [text]Reply with one word.\n---\nuser: [text]Capital of France?"

    def test_extract_input_text_handles_multipart_user_message(self):
        body = {
            "contents": [
                {"role": "user", "parts": [
                    {"text": "Describe:"},
                    {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                ]},
            ],
        }
        out = GoogleAdapter.extract_input_text(body)
        assert "[text]Describe:" in out
        assert "[inline:image/png]" in out

    def test_extract_output_text_picks_first_candidate(self):
        resp = {
            "candidates": [
                {"content": {"role": "model", "parts": [{"text": "Paris."}]}},
            ],
            "modelVersion": "gemini-1.5-pro-002",
        }
        out, meta = GoogleAdapter.extract_output_text(resp)
        assert out == "Paris."
        assert meta["generator_id"] == "google/gemini-1.5-pro-002"

    def test_inject_seal_uses_camelcase_field(self):
        from crovia_proxy.sealer import SealedResponse
        sealed = SealedResponse(
            seal_id="cs_2026_GG",
            seal={"seal_id": "cs_2026_GG"},
            seal_base64="b64",
            modified_output_text="Paris.",
            cim_embedded=False,
        )
        resp = {"candidates": [{"content": {"parts": [{"text": "Paris."}]}}]}
        out = GoogleAdapter.inject_seal(resp, sealed, "Paris.")
        # Google convention: camelCase ("croviaSeal", "sealId")
        assert out["croviaSeal"]["sealId"] == "cs_2026_GG"


# ---------------------------------------------------------------------------
# Cohere
# ---------------------------------------------------------------------------

class TestCohere:
    def test_extract_input_text_full_history_plus_current(self):
        body = {
            "preamble": "Speak French.",
            "chat_history": [
                {"role": "USER", "message": "Hi"},
                {"role": "CHATBOT", "message": "Bonjour"},
            ],
            "message": "Comment ça va?",
        }
        out = CohereAdapter.extract_input_text(body)
        # roles get lowercased; current message added as a final user line
        assert out == ("system: Speak French.\n---\n"
                       "user: Hi\n---\n"
                       "chatbot: Bonjour\n---\n"
                       "user: Comment ça va?")

    def test_extract_output_text_reads_top_level_text(self):
        resp = {"text": "Bien, merci!", "model": "command-r-plus", "response_id": "abc"}
        out, meta = CohereAdapter.extract_output_text(resp)
        assert out == "Bien, merci!"
        assert meta["generator_id"] == "cohere/command-r-plus"

    def test_extract_output_text_falls_back_when_model_missing(self):
        resp = {"text": "ok"}  # no model echoed
        out, meta = CohereAdapter.extract_output_text(resp)
        assert out == "ok"
        assert meta["generator_id"] == "cohere/command-r-unknown"

    def test_inject_seal_uses_snake_case_field(self):
        from crovia_proxy.sealer import SealedResponse
        sealed = SealedResponse(
            seal_id="cs_2026_CC",
            seal={"seal_id": "cs_2026_CC"},
            seal_base64="b64",
            modified_output_text="ok",
            cim_embedded=False,
        )
        resp = {"text": "ok", "model": "command-r-plus"}
        out = CohereAdapter.inject_seal(resp, sealed, "ok")
        assert out["crovia_seal"]["seal_id"] == "cs_2026_CC"
