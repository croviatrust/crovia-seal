"""CLI entry point: `crovia-proxy` or `python -m crovia_proxy`."""
from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from crovia_proxy.config import Settings
from crovia_proxy.server import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="crovia-proxy",
        description="OpenAI-compatible proxy that seals every response with Crovia Seal v1.",
    )
    parser.add_argument("--host", default=None, help="bind host (default: env CROVIA_HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="bind port (default: env CROVIA_PORT or 7878)")
    parser.add_argument("--upstream", default=None, help="override CROVIA_UPSTREAM_URL")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    if args.upstream:
        os.environ["CROVIA_UPSTREAM_URL"] = args.upstream

    settings = Settings()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port

    app = create_app(settings)

    print(
        f"[crovia-proxy] issuer_id   = {settings.issuer_id}",
        f"[crovia-proxy] pubkey_hex  = {app.state.__dict__.get('pubkey','<pending>')}",
        f"[crovia-proxy] upstream    = {settings.upstream_url}",
        f"[crovia-proxy] listening   = http://{settings.host}:{settings.port}",
        sep="\n",
        file=sys.stderr,
    )

    uvicorn.run(app, host=settings.host, port=settings.port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
