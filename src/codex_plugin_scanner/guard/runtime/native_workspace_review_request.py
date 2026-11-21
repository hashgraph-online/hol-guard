"""Native workspace-review request primitives: the bridge error, canonical
JSON bytes, request-id safety and the private request directory."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

_REQUEST_DIRECTORY = "workspace-review-requests"
_MAX_REQUEST_ID_LENGTH = 128

__all__ = [
    "NativeWorkspaceReviewError",
    "_canonical_json_bytes",
    "_json_field",
    "_private_request_directory",
    "_request_id_is_safe",
    "canonical_workspace_review_decision_bytes",
]


class NativeWorkspaceReviewError(ValueError):
    """Finite error raised by the local native review bridge."""

    def __init__(self, code: str):
        self.code: str = code if code else "native_workspace_review_failed"
        super().__init__(self.code)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid") from error


def canonical_workspace_review_decision_bytes(value: object) -> bytes:
    """Return canonical bytes for the signed decision CLI boundary."""

    try:
        return _canonical_json_bytes(value)
    except NativeWorkspaceReviewError as error:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid") from error


def _request_id_is_safe(request_id: str) -> bool:
    return (
        isinstance(request_id, str)
        and bool(request_id)
        and len(request_id) <= _MAX_REQUEST_ID_LENGTH
        and all(char.isascii() and (char.isalnum() or char in "-_.:") for char in request_id)
    )


def _private_request_directory(guard_home: Path) -> Path:
    state_base = guard_home / "native-runtime"
    request_directory = state_base / _REQUEST_DIRECTORY
    if os.name == "nt":
        # The runtime's private-state writer creates and repairs these.
        return request_directory
    for directory in (state_base, request_directory):
        if directory.is_symlink():
            raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)
        except OSError as error:
            raise NativeWorkspaceReviewError("native_workspace_review_request_unavailable") from error
    return request_directory


def _json_field(request: Mapping[str, object], name: str) -> object:
    value = request.get(name)
    if not name.endswith("_json") or not isinstance(value, str):
        return value
    try:
        parsed: object = json.loads(value)
        return parsed
    except (TypeError, ValueError) as error:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid") from error
