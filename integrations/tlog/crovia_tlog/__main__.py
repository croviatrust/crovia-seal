"""CLI: `crovia-tlog` or `python -m crovia_tlog`."""
from __future__ import annotations

import argparse
import sys

import uvicorn

from crovia_tlog.config import Settings
from crovia_tlog.server import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="crovia-tlog", description="Run the Crovia Transparency Log HTTP server.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    settings = Settings()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port

    app = create_app(settings)
    print(
        f"[crovia-tlog] log_id    = {settings.log_id}",
        f"[crovia-tlog] db        = {settings.db_path}",
        f"[crovia-tlog] listening = http://{settings.host}:{settings.port}",
        sep="\n",
        file=sys.stderr,
    )
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
