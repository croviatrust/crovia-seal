# Crovia Proxy

**Multi-vendor proxy that seals every AI response with a Crovia Seal v1 provenance receipt.**

Drop-in: change one line in any OpenAI / Anthropic / Google Gemini / Cohere SDK setup and every AI response that passes through gains a cryptographic receipt, a tamper-evident chain, and a zero-width CIM mark embedded in the text itself.

---

## What it does

1. Accepts a request in any of the four supported native shapes:
   - **OpenAI**: `POST /v1/chat/completions` (streaming + non-streaming)
   - **Anthropic**: `POST /v1/messages` (Messages API)
   - **Google Gemini**: `POST /v1beta/models/{model}:generateContent`
   - **Cohere**: `POST /v1/chat`
2. Forwards it verbatim to the appropriate upstream (configurable per vendor).
3. After the response arrives, it:
   - computes a Crovia Seal over the `(input_text, output_text)` pair, signed Ed25519 with the proxy's issuer key;
   - chains the seal to the previous one (append-only hash chain);
   - embeds a **Crovia Invisible Mark (CIM)** inside the response text so the seal id survives copy-paste;
   - injects the seal into the response in each vendor's idiomatic JSON shape:
     - OpenAI / Anthropic: top-level `crovia` field (`snake_case` inner keys)
     - Google Gemini: top-level `croviaSeal` field (`camelCase` inner keys, per Google convention)
     - Cohere: top-level `crovia_seal` field (per Cohere convention)
   - emits the same `X-Crovia-Seal-Id` / `X-Crovia-Seal` / `X-Crovia-Issuer-Pubkey` headers across all four routes.

Streaming requests on the native vendor routes are forwarded **verbatim, unsealed**, with an `X-Crovia-Stream-Sealed: false` response header so callers know.  Sealed evidence requires non-streaming responses (the OpenAI route additionally seals streams via a synthetic final SSE event).

No data is ever sent to any Crovia server. The proxy is 100% local; only the upstream traffic (to OpenAI / Anthropic / Google / Cohere) is the usual one.

---

## Install

```bash
pip install -e reference/python          # the core crovia_seal library
pip install -e integrations/proxy        # this proxy
```

## Run

```bash
# Minimal: proxies to OpenAI
export OPENAI_API_KEY=sk-...            # your normal API key, forwarded
crovia-proxy --upstream https://api.openai.com --port 7878

# Using a local model via Ollama
crovia-proxy --upstream http://localhost:11434 --port 7878

# Using a local vLLM server
crovia-proxy --upstream http://localhost:8000 --port 7878
```

The proxy generates a persistent issuer key on first start under `~/.crovia/proxy.key` (or `%USERPROFILE%\.crovia\proxy.key` on Windows). Pin your public key hex from `/health` or `/.well-known/crovia-issuer.json`.

## Use with the OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:7878/v1", api_key="sk-...")
resp = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Write a haiku about proofs."}],
)
print(resp.choices[0].message.content)

# The extra field "crovia" carries the full Seal:
import json
print(json.dumps(resp.model_extra["crovia"]["seal"], indent=2))
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CROVIA_UPSTREAM_URL` | `https://api.openai.com` | OpenAI-compatible upstream (`/v1/chat/completions`) |
| `CROVIA_UPSTREAM_ANTHROPIC_URL` | `https://api.anthropic.com` | Anthropic upstream (`/v1/messages`) |
| `CROVIA_UPSTREAM_GOOGLE_URL` | `https://generativelanguage.googleapis.com` | Google Gemini upstream |
| `CROVIA_UPSTREAM_COHERE_URL` | `https://api.cohere.com` | Cohere upstream (`/v1/chat`) |
| `CROVIA_ISSUER_ID` | `urn:crovia:seal-issuer:crovia-proxy-local` | URN of the signer |
| `CROVIA_ISSUER_PRIVATE_HEX` | *(unset)* | 32-byte Ed25519 private hex; generated+persisted if missing |
| `CROVIA_INJECT_CIM` | `true` | embed CIM in response text |
| `CROVIA_CHAIN_SEALS` | `true` | chain seals via `prev_seal_hash` |
| `CROVIA_LOG_FILE` | *(unset)* | optional append-only JSONL audit log |
| `CROVIA_HOST` | `127.0.0.1` | bind host |
| `CROVIA_PORT` | `7878` | bind port |

## Endpoints

Sealed paths (non-streaming responses are signed; streaming is pass-through):

| Method | Path | Vendor | Seal field |
|---|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible | `response.crovia.seal` |
| `POST` | `/v1/messages` | Anthropic | `response.crovia.seal` |
| `POST` | `/v1beta/models/{model}:generateContent` | Google Gemini | `response.croviaSeal.seal` |
| `POST` | `/v1/chat` | Cohere | `response.crovia_seal.seal` |

Discovery / health:

- `GET /health` — liveness + identity.
- `GET /.well-known/crovia-issuer.json` — public issuer manifest for verifiers.

## SDK examples for the native routes

### Anthropic

```python
import anthropic
client = anthropic.Anthropic(
    base_url="http://localhost:7878",
    api_key="sk-ant-...",
)
resp = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=128,
    messages=[{"role": "user", "content": "Write a haiku about proofs."}],
)
print(resp.content[0].text)
# Seal lives in the raw JSON: resp.model_dump()["crovia"]["seal"]
```

### Google Gemini (REST)

```python
import httpx
r = httpx.post(
    "http://localhost:7878/v1beta/models/gemini-1.5-pro:generateContent",
    headers={"x-goog-api-key": "AIza..."},
    json={"contents": [{"role": "user",
                        "parts": [{"text": "Capital of France?"}]}]},
)
body = r.json()
print(body["candidates"][0]["content"]["parts"][0]["text"])
print(body["croviaSeal"]["seal"])
```

### Cohere

```python
import cohere
client = cohere.Client(
    base_url="http://localhost:7878",
    api_key="...",
)
resp = client.chat(
    model="command-r-plus",
    message="Capital of France?",
)
print(resp.text)
# raw seal in the underlying JSON: resp.model_dump()["crovia_seal"]["seal"]
```

## Test

```bash
pytest integrations/proxy/tests -v
```

## Security notes

- The proxy's issuer key is a local file. Rotate by removing `~/.crovia/proxy.key` (or setting `CROVIA_ISSUER_PRIVATE_HEX` to a new hex).
- The proxy does NOT strip headers from the upstream response except for hop-by-hop headers; API keys sent by the client are forwarded verbatim to the upstream.
- Verify seals server-side using the public key at `/.well-known/crovia-issuer.json` or any copy pinned in your code.
