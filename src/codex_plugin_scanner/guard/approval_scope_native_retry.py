"""Detect native reviews whose one-time approval can never match a retry."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

# Native pre-tool reviews bind a retry to the Rust request digest only for the small set of
# commands that daemon/hook_native_review_approval.py treats as reusable. Every other command
# is queued with a per-request artifact hash, so a later attempt can never match its approval.
_NATIVE_REVIEW_BINDING_PREFIX: Final = "native-review-v4:"


def native_retry_cannot_reuse_approval(request: Mapping[str, object]) -> bool:
    artifact_id = request.get("artifact_id")
    if not isinstance(artifact_id, str) or ":native-pretool:" not in artifact_id:
        return False
    artifact_hash = request.get("artifact_hash")
    return not (isinstance(artifact_hash, str) and artifact_hash.startswith(_NATIVE_REVIEW_BINDING_PREFIX))
