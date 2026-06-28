"""Shared typed hook-review request/response API for HOL Guard fast hook review.

These dataclasses are the canonical contract between harness adapters
(Pi, Codex, Claude Code, etc.), the daemon-resident hook worker, the CLI
fallback, and the hook review engine. They never carry raw tool output —
only digests, excerpts, and decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

HookPayloadKind = Literal["inline", "encrypted_payload_ref", "source_file_ref", "unknown"]

ModelOutputAction = Literal[
    "allow_original",
    "replace_with_reviewed_excerpt",
    "block",
    "not_applicable",
]

HookDecision = Literal["allow", "deny"]

HookEventName = Literal["UserPromptSubmit", "PreToolUse", "PostToolUse", "PermissionRequest"] | str


@dataclass(frozen=True, slots=True)
class HookOutputSummary:
    """Bounded summary of post-tool output provided by the adapter.

    Contains only an excerpt, a digest, and counts — never full content.
    """

    text_excerpt: str
    excerpt_truncated: bool
    output_sha256: str | None
    output_chars: int | None
    content_items_seen: int | None = None
    object_keys_seen: int | None = None
    max_depth_seen: int | None = None


@dataclass(frozen=True, slots=True)
class HookSourceFileRef:
    """Adapter-provided reference to a direct source-file read.

    This is an optimization hint, never trusted authority. The engine
    re-reads, re-stats, re-hashes, and re-scans the file before allowing
    original output.
    """

    version: int
    path: str
    output_sha256: str
    output_chars: int
    tool_input_path: str | None = None
    adapter_stat: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HookReviewRequest:
    """A fully-typed hook review request."""

    harness: str
    event_name: HookEventName
    payload: dict[str, object]
    payload_kind: HookPayloadKind
    config_path: str | None
    cwd: Path | None
    home_dir: Path
    guard_home: Path
    source_scope: str
    output_summary: HookOutputSummary | None = None
    source_ref: HookSourceFileRef | None = None
    received_at_monotonic: float = 0.0
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class HookReviewResponse:
    """The engine's decision and model-output directive for the adapter.

    The adapter must only preserve original full output when *all* of
    ``decision == "allow"``, ``model_output_action == "allow_original"``,
    and ``reviewed_output_sha256`` matches the adapter's locally computed
    output hash. Any other combination means the adapter must not return
    raw content.
    """

    decision: HookDecision
    reason: str | None
    model_output_action: ModelOutputAction
    reviewed_output_sha256: str | None = None
    reviewed_excerpt: str | None = None
    notice: Literal["none", "excerpt", "warning"] = "none"
    reason_code: str = "unknown"
    policy_action: str | None = None
    metrics: dict[str, object] = field(default_factory=dict)

    def to_harness_json(self) -> dict[str, object]:
        """Serialize to the harness-facing JSON envelope.

        Omits ``None`` / empty optional fields. ``decision`` and
        ``model_output_action`` are always present. ``reviewed_output_sha256``
        is included only when non-empty. ``reason`` is included only when
        non-empty. ``policy_action`` is included only when set.
        """
        payload: dict[str, object] = {"decision": self.decision}
        if self.reason:
            payload["reason"] = self.reason
        payload["model_output_action"] = self.model_output_action
        if self.reviewed_output_sha256:
            payload["reviewed_output_sha256"] = self.reviewed_output_sha256
        if self.reviewed_excerpt is not None:
            payload["reviewed_excerpt"] = self.reviewed_excerpt
        payload["notice"] = self.notice
        payload["reason_code"] = self.reason_code
        if self.policy_action is not None:
            payload["policy_action"] = self.policy_action
        return payload


__all__ = [
    "HookDecision",
    "HookEventName",
    "HookOutputSummary",
    "HookPayloadKind",
    "HookReviewRequest",
    "HookReviewResponse",
    "HookSourceFileRef",
    "ModelOutputAction",
]
