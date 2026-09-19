"""Protocol profile classification for the public Crovia Seal service.

This module deliberately performs classification only. Cryptographic acceptance
must be delegated to the verifier for the selected profile. Keeping detection
separate prevents a legacy object from being interpreted as a draft object.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Mapping


DRAFT_01_VERSION = "crovia.seal.v1"
LEGACY_VERSION = "crovia-seal-v1"


class Profile(str, Enum):
    DRAFT_01 = "draft-crovia-seal-01"
    LEGACY_V1 = "crovia-legacy-v1"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"


_DRAFT_MARKERS = frozenset({"timestamp", "chain"})
_LEGACY_MARKERS = frozenset({"issued_at", "issuer_app"})


def classify_profile(value: Any) -> Profile:
    """Classify a decoded JSON value without accepting malformed ambiguity.

    An object is draft-01 only when it uses the draft version identifier and
    has the structural markers required by that profile. Legacy objects remain
    identifiable for historical verification. Mixed or colliding shapes are
    rejected as ambiguous.
    """
    if not isinstance(value, Mapping):
        return Profile.UNSUPPORTED

    version = value.get("seal_version")
    has_draft_markers = bool(_DRAFT_MARKERS.intersection(value))
    has_legacy_markers = bool(_LEGACY_MARKERS.intersection(value))

    if has_draft_markers and has_legacy_markers:
        return Profile.AMBIGUOUS

    if version == DRAFT_01_VERSION:
        issuer = value.get("issuer")
        signature = value.get("signature")
        draft_shape = (
            has_draft_markers
            and isinstance(issuer, Mapping)
            and isinstance(issuer.get("pubkey"), Mapping)
            and isinstance(signature, Mapping)
        )
        return Profile.DRAFT_01 if draft_shape else Profile.AMBIGUOUS

    if version == LEGACY_VERSION:
        issuer = value.get("issuer")
        legacy_shape = (
            "issued_at" in value
            and isinstance(issuer, Mapping)
            and isinstance(issuer.get("pubkey"), str)
            and isinstance(value.get("signature"), str)
        )
        return Profile.LEGACY_V1 if legacy_shape else Profile.AMBIGUOUS

    return Profile.UNSUPPORTED
