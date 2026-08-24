"""Stable opaque correlation identifiers for Guard Cloud Review v2."""

from __future__ import annotations

import uuid

_CORRELATION_DOMAIN = uuid.UUID("e927e1cf-e257-4af5-ae66-a8b6edcc18f5")


def cloud_review_v2_correlation_id(local_request_id: str) -> str:
    """Derive one non-secret correlation ID for every version of a local request."""

    if not local_request_id.strip():
        raise ValueError("local_request_id is required")
    return f"gcrv2_{uuid.uuid5(_CORRELATION_DOMAIN, local_request_id)}"


__all__ = ["cloud_review_v2_correlation_id"]
