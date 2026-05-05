"""Crovia Proxy - OpenAI-compatible proxy with automatic Crovia Seal emission.

Public API:
    create_app(settings=None)   -> FastAPI application factory
    Settings                    -> pydantic settings, loaded from env
    Sealer                      -> stateless sealing service
"""
from crovia_proxy.config import Settings
from crovia_proxy.sealer import Sealer, SealedResponse
from crovia_proxy.server import create_app

__version__ = "0.5.0"
__all__ = ["Settings", "Sealer", "SealedResponse", "create_app", "__version__"]
