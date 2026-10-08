"""Finite native workspace-review error and store contract."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol


class NativeWorkspaceReviewError(ValueError):
    """Finite error raised by the local native review bridge."""

    def __init__(self, code: str, *, call_stage: str = "verify", commit_certainty: str = "pre_commit"):
        self.code: str = code if code else "native_workspace_review_failed"
        self.call_stage = call_stage
        self.commit_certainty = commit_certainty
        super().__init__(self.code)


class NativeWorkspaceReviewStore(Protocol):
    def get_approval_request(self, request_id: str) -> dict[str, object] | None: ...

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...

    def resolve_native_workspace_review_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        expected_request: Mapping[str, object],
        resolved_at: str,
        native_replayed: bool,
        native_receipt: Mapping[str, object] | None = None,
    ) -> dict[str, object]: ...


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
