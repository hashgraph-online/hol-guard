"""Daemon-resident hook worker for fast hook review.

This worker avoids Python startup/import cost and avoids calling the
CLI path for normal daemon hooks. It builds a ``HookReviewRequest``
from the HTTP payload and calls ``HookReviewEngine.review()``.

Security:
- Never lets unreviewed tool output reach the model.
- Never falls back to legacy CLI after a worker exception for a
  request that supplied only ``guard_source_ref`` without full output.
- Never calls ``run_guard_command()``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import load_guard_config
from ..runtime.hook_content_scanner import ContentScanner
from ..runtime.hook_decision_cache import HookDecisionCache
from ..runtime.hook_review_engine import HookReviewEngine
from ..runtime.hook_review_types import (
    HookOutputSummary,
    HookPayloadKind,
    HookReviewRequest,
    HookSourceFileRef,
)

if TYPE_CHECKING:
    from ..store import GuardStore


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised when the worker cannot handle a request (caller falls back to CLI)."""


class HookWorker:
    """Resident hook review worker for the daemon."""

    def __init__(self, *, store: GuardStore):
        self.store = store
        self.guard_home = store.guard_home
        self.scanner = ContentScanner()
        self.cache = HookDecisionCache(store)
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()
        self.engine = HookReviewEngine(
            store=store,
            scanner=self.scanner,
            cache=self.cache,
            config_loader=self._load_config,
            metrics=self.metrics,
        )

    def _load_config(self, guard_home: Path, workspace: Path | None):
        return load_guard_config(guard_home, workspace=workspace)

    def review_http_payload(
        self,
        *,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
    ) -> dict[str, object]:
        """Review a hook HTTP payload and return harness JSON.

        Builds a ``HookReviewRequest`` from the payload, calls the engine,
        and returns ``HookReviewResponse.to_harness_json()``.

        Raises ``HookWorkerUnsupported`` if the request cannot be handled
        by the fast path (caller should fall back to legacy CLI).

        The fast path handles ``PostToolUse`` events:
        + With ``guard_source_ref`` (Pi/OMP): uses the source-read fast
        + path with hash verification and file-system caching.
        + Without ``guard_source_ref`` (claude-code, codex, grok, zcode,
        + etc.): uses the server-side output scanning path. The engine
        + extracts the full tool output from the payload, scans it for
        + secrets, and returns ``allow_original`` if clean.

        All other events (``PreToolUse``, ``UserPromptSubmit``,
        ``PermissionRequest``) must fall through to the legacy CLI path
        so that existing policy, permission, and approval logic is not
        bypassed.
        """
        harness = self._runtime_harness(params) or default_harness
        event_name = self._hook_event_name(payload)

        # Only PostToolUse is eligible for the fast path. Everything else
        # needs the full CLI policy/permission engine.
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(
                f"fast path only supports PostToolUse, got event={event_name}"
            )

        request = self._request_from_payload(
            payload,
            harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
        response = self.engine.review(request)
        return response.to_harness_json()

    def _runtime_harness(self, params: Mapping[str, list[str]]) -> str | None:
        values = params.get("runtime-harness", [])
        if values and isinstance(values[-1], str) and values[-1].strip():
            return values[-1].strip()
        return None

    def _request_from_payload(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
    ) -> HookReviewRequest:
        """Build a typed review request from the HTTP payload."""
        event_name = self._hook_event_name(payload)
        payload_kind = self._payload_kind(payload)
        output_summary = self._parse_output_summary(payload)
        source_ref = self._parse_source_ref(payload)
        source_scope = str(payload.get("source_scope") or "project")
        config_path = payload.get("config_path")
        if not isinstance(config_path, str):
            config_path = None

        return HookReviewRequest(
            harness=harness,
            event_name=event_name,
            payload=payload,
            payload_kind=payload_kind,
            config_path=config_path,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            source_scope=source_scope,
            output_summary=output_summary,
            source_ref=source_ref,
        )

    def _hook_event_name(self, payload: Mapping[str, object]) -> str:
        for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "PreToolUse"

    def _payload_kind(self, payload: Mapping[str, object]) -> HookPayloadKind:
        if "guard_payload_ref" in payload:
            return "encrypted_payload_ref"
        if "guard_source_ref" in payload:
            return "source_file_ref"
        return "inline"

    def _parse_output_summary(self, payload: Mapping[str, object]) -> HookOutputSummary | None:
        summary = payload.get("tool_response_summary")
        if not isinstance(summary, Mapping):
            return None
        text_excerpt = summary.get("text_excerpt") or summary.get("excerpt") or ""
        if not isinstance(text_excerpt, str):
            text_excerpt = str(text_excerpt)
        excerpt_truncated = bool(summary.get("excerpt_truncated", False))
        output_sha256 = summary.get("output_sha256")
        if not isinstance(output_sha256, str):
            output_sha256 = None
        output_chars_raw = summary.get("output_chars")
        output_chars = int(output_chars_raw) if isinstance(output_chars_raw, (int, float)) else None
        content_items_seen_raw = summary.get("content_items_seen")
        content_items_seen = int(content_items_seen_raw) if isinstance(content_items_seen_raw, (int, float)) else None
        object_keys_seen_raw = summary.get("object_keys_seen")
        object_keys_seen = int(object_keys_seen_raw) if isinstance(object_keys_seen_raw, (int, float)) else None
        max_depth_seen_raw = summary.get("max_depth_seen")
        max_depth_seen = int(max_depth_seen_raw) if isinstance(max_depth_seen_raw, (int, float)) else None
        return HookOutputSummary(
            text_excerpt=text_excerpt,
            excerpt_truncated=excerpt_truncated,
            output_sha256=output_sha256,
            output_chars=output_chars,
            content_items_seen=content_items_seen,
            object_keys_seen=object_keys_seen,
            max_depth_seen=max_depth_seen,
        )

    def _parse_source_ref(self, payload: Mapping[str, object]) -> HookSourceFileRef | None:
        ref = payload.get("guard_source_ref")
        if not isinstance(ref, Mapping):
            return None
        version = ref.get("version")
        path = ref.get("path")
        output_sha256 = ref.get("output_sha256")
        output_chars = ref.get("output_chars")
        tool_input_path = ref.get("tool_input_path")
        adapter_stat = ref.get("adapter_stat")

        # Invalid shape: return a ref with version -1 so the engine fails safe.
        if not isinstance(version, int) or not isinstance(path, str) or not isinstance(output_sha256, str):
            return HookSourceFileRef(
                version=-1,
                path="",
                output_sha256="",
                output_chars=0,
            )

        if not isinstance(output_chars, int):
            output_chars = 0
        if not isinstance(tool_input_path, str):
            tool_input_path = None
        stat_dict = dict(adapter_stat) if isinstance(adapter_stat, Mapping) else {}

        return HookSourceFileRef(
            version=version,
            path=path,
            output_sha256=output_sha256,
            output_chars=output_chars,
            tool_input_path=tool_input_path,
            adapter_stat=stat_dict,
        )

    # Server-side output scanning:
    # Harnesses without client-side guard_source_ref (claude-code, codex,
    # grok, zcode, etc.) are handled by the engine's server-side output
    # scanning path. The engine extracts the full tool output from the
    # payload (tool_response, stdout, etc.), scans it for secrets, and
    # returns allow_original if clean. This is more secure than the legacy
    # CLI path because the full output is scanned, not just a bounded excerpt.
    #
    # The source-read fast path (with guard_source_ref) remains available
    # for Pi/OMP, which provides a client-computed hash for file-system
    # caching and exact-match verification.


__all__ = ["HookWorker", "HookWorkerUnsupported"]
