# Crovia Proxy

**OpenAI-compatible proxy that seals every response with a Crovia Seal v1 provenance receipt.**

Drop-in: change one line in any OpenAI SDK setup and every AI response that passes through gains a cryptographic receipt, a tamper-evident chain, and a zero-width CIM mark embedded in the text itself.

---

## What it does

1. Accepts an OpenAI-style `/v1/chat/completions` request (both streaming and non-streaming).
2. Forwards it to the real upstream (OpenAI, Ollama, vLLM, Together, Groq, any OpenAI-compatible endpoint).
3. After the response arrives, it:
   - computes a Crovia Seal over the `(input_text, output_text)` pair, signed Ed25519 with the proxy's issuer key;
   - chains the seal to the previous one (append-only hash chain);
   - embeds a **Crovia Invisible Mark (CIM)** inside the response text so the seal id survives copy-paste;
   - returns the response with:
     - the full seal JSON inside `response.crovia.seal`
     - `X-Crovia-Seal-Id` and `X-Crovia-Seal` HTTP headers
     - a final SSE event `data: {"crovia": {...}}` for streaming

No data is ever sent to any Crovia server. The proxy is 100% local; only the upstream traffic (to OpenAI etc.) is the usual one.

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
| `CROVIA_UPSTREAM_URL` | `https://api.openai.com` | where to forward requests |
| `CROVIA_ISSUER_ID` | `urn:crovia:seal-issuer:crovia-proxy-local` | URN of the signer |
| `CROVIA_ISSUER_PRIVATE_HEX` | *(unset)* | 32-byte Ed25519 private hex; generated+persisted if missing |
| `CROVIA_INJECT_CIM` | `true` | embed CIM in response text |
| `CROVIA_CHAIN_SEALS` | `true` | chain seals via `prev_seal_hash` |
| `CROVIA_LOG_FILE` | *(unset)* | optional append-only JSONL audit log |
| `CROVIA_HOST` | `127.0.0.1` | bind host |
| `CROVIA_PORT` | `7878` | bind port |

## Endpoints

- `POST /v1/chat/completions` — the sealed hot path (streaming + non-streaming).
- `GET /health` — liveness + identity.
- `GET /.well-known/crovia-issuer.json` — public issuer manifest for verifiers.

## Test

```bash
pytest integrations/proxy/tests -v
```

## Security notes

- The proxy's issuer key is a local file. Rotate by removing `~/.crovia/proxy.key` (or setting `CROVIA_ISSUER_PRIVATE_HEX` to a new hex).
- The proxy does NOT strip headers from the upstream response except for hop-by-hop headers; API keys sent by the client are forwarded verbatim to the upstream.
- Verify seals server-side using the public key at `/.well-known/crovia-issuer.json` or any copy pinned in your code.
