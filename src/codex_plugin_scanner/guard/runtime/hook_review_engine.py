"""Hook review engine: the typed, resident decision core.

This engine ties together:
- ``HookReviewRequest`` / ``HookReviewResponse`` typed API
- ``ContentScanner`` for streaming secret detection
- ``HookDecisionCache`` for exact source-read caching
- ``evaluate_source_file_ref()`` for the source-read fast path
- ``normalize_harness_payload()`` for action envelope normalization
- ``load_guard_config()`` for config loading

Security invariants:
- Never allows raw output on timeout, exception, or cache miss.
- Never calls an LLM in the hot path.
- Never calls Guard Cloud or network for allow/block decisions.
- Never lets unreviewed tool output reach the model.
- Fail-safe: any unexpected exception returns deny/block.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .actions import normalize_harness_payload
from .hook_content_scanner import ContentScanner
from .hook_decision_cache import HookDecisionCache
from .hook_review_types import HookReviewRequest, HookReviewResponse
from .hook_source_read import (
    SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET,
    SOURCE_READ_MAX_SCAN_BYTES,
    evaluate_source_file_ref,
)

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore

HOOK_ENGINE_TOTAL_BUDGET_MS = 9000
HOOK_ENGINE_NORMAL_BUDGET_MS = 1000
HOOK_SOURCE_FAST_PATH_BUDGET_MS = 250
HOOK_SCANNER_DEFAULT_BUDGET_MS = 750
ARBITRARY_STDOUT_FULL_ALLOW_BYTES = 256 * 1024


class HookFailSafe(RuntimeError):  # noqa: N818
    """Raised when the engine must fail safe with a specific reason."""

    def __init__(self, reason_code: str, reason: str, *, excerpt: str | None = None):
        super().__init__(reason)
        self.reason_code = reason_code
        self.reason = reason
        self.excerpt = excerpt

    def to_response(self) -> HookReviewResponse:
        return HookReviewResponse(
            decision="deny" if self.excerpt is None else "allow",
            reason=self.reason,
            model_output_action="block" if self.excerpt is None else "replace_with_reviewed_excerpt",
            reviewed_excerpt=self.excerpt,
            notice="warning" if self.excerpt is None else "excerpt",
            reason_code=self.reason_code,
        )


class HookReviewEngine:
    """The resident hook review engine.

    Call ``review()`` with a ``HookReviewRequest`` and get a
    ``HookReviewResponse``. The engine is deterministic, local-first,
    and never calls an LLM or the network.
    """

    def __init__(
        self,
        *,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        config_loader: Callable[[Path, Path | None], GuardConfig],
        metrics: object | None = None,
        enrichment_queue: object | None = None,
    ):
        self.store = store
        self.scanner = scanner
        self.cache = cache
        self.config_loader = config_loader
        self.metrics = metrics
        self.enrichment_queue = enrichment_queue

    def review(self, request: HookReviewRequest) -> HookReviewResponse:
        """Review a hook request and return a typed response.

        Never raises. Any unexpected exception returns deny/block.
        """
        start = time.monotonic()
        try:
            return self._review_inner(request, start=start)
        except HookFailSafe as error:
            return error.to_response()
        except Exception:
            return HookReviewResponse(
                decision="deny",
                reason="HOL Guard could not complete local hook review safely.",
                model_output_action="block",
                notice="warning",
                reason_code="engine_exception",
            )
        finally:
            self._record_metrics(request, start)

    def _review_inner(self, request: HookReviewRequest, *, start: float) -> HookReviewResponse:
        # Load config.
        config = self.config_loader(request.guard_home, request.cwd)

        # Normalize payload into action envelope.
        envelope = normalize_harness_payload(
            request.harness,
            request.event_name,
            request.payload,
            workspace=request.cwd,
            home_dir=request.home_dir,
        )

        # Source-read fast path for PostToolUse with guard_source_ref.
        if request.event_name == "PostToolUse" and request.source_ref is not None:
            deadline = start + (HOOK_SOURCE_FAST_PATH_BUDGET_MS / 1000.0)
            source_result = evaluate_source_file_ref(
                request=request,
                envelope=envelope,
                scanner=self.scanner,
                cache=self.cache,
                config=config,
                store=self.store,
                deadline_monotonic=deadline,
            )

            if source_result.status == "allow_original":
                return HookReviewResponse(
                    decision="allow",
                    reason=None,
                    model_output_action="allow_original",
                    reviewed_output_sha256=source_result.proof.output_sha256 if source_result.proof else None,
                    notice="none",
                    reason_code=source_result.reason_code,
                    policy_action="allow",
                )

            if source_result.status == "risky":
                # For MVP: deny/block for risky source files (secrets, sensitive paths).
                # Do not allow original output.
                return HookReviewResponse(
                    decision="deny",
                    reason="HOL Guard blocked this output because it contains sensitive content.",
                    model_output_action="block",
                    notice="warning",
                    reason_code=source_result.reason_code,
                )

            # inconclusive: fall through to standard path below.

        # Server-side output scanning for PostToolUse without guard_source_ref.
        # This handles all harnesses that don't generate guard_source_ref
        # client-side (claude-code, codex, grok, zcode, etc.). The engine
        # extracts the full tool output from the payload and scans it.
        if request.event_name == "PostToolUse" and request.source_ref is None:
            return self._review_output_scan(request, envelope, config, start)

        # Standard path for non-source or inconclusive requests.
        return self._review_standard(request, envelope, config, start)

    def _review_output_scan(
        self,
        request: HookReviewRequest,
        envelope: object,
        config: GuardConfig,
        start: float,
    ) -> HookReviewResponse:
        """Scan full tool output for PostToolUse file reads without guard_source_ref.

        This is the server-side fast path for all harnesses that do not
        generate ``guard_source_ref`` client-side (claude-code, codex,
        grok, zcode, etc.). It extracts the full tool output from the
        payload, scans it for secrets, and returns ``allow_original``
        if clean.

        Only ``file_read`` actions are eligible — shell commands, MCP
        tools, and other action types still need the full CLI policy/
        permission/approval engine and fall through to ``_review_standard``.
        """
        from .hook_output_text import extract_payload_output

        action_type = getattr(envelope, "action_type", None)
        if action_type != "file_read":
            return self._review_standard(request, envelope, config, start)

        extracted = extract_payload_output(request.payload)

        if not extracted.text:
            # No output text found in payload — fall back to excerpt path.
            return self._review_standard(request, envelope, config, start)

        if extracted.truncated:
            # Output too large to scan in full — scan the excerpt before returning.
            excerpt = extracted.text[:SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET]
            deadline = start + (HOOK_SCANNER_DEFAULT_BUDGET_MS / 1000.0)
            scan_result = self.scanner.scan_text(
                excerpt,
                local_content=True,
                source_context=True,
                max_bytes=SOURCE_READ_MAX_SCAN_BYTES,
                deadline_monotonic=deadline,
            )
            if scan_result.budget_exhausted or scan_result.matches:
                return HookReviewResponse(
                    decision="deny",
                    reason="HOL Guard blocked this output because it could not be fully scanned within local limits.",
                    model_output_action="block",
                    notice="warning",
                    reason_code="output_too_large",
                )
            return HookReviewResponse(
                decision="allow",
                reason="HOL Guard returned a reviewed excerpt because the output was too large"
                " to scan in full within local limits.",
                model_output_action="replace_with_reviewed_excerpt",
                reviewed_excerpt=excerpt,
                notice="excerpt",
                reason_code="output_too_large",
            )

        # Scan the full output text.
        deadline = start + (HOOK_SCANNER_DEFAULT_BUDGET_MS / 1000.0)
        scan_result = self.scanner.scan_text(
            extracted.text,
            local_content=True,
            source_context=True,
            max_bytes=SOURCE_READ_MAX_SCAN_BYTES,
            deadline_monotonic=deadline,
        )

        if scan_result.budget_exhausted:
            excerpt = extracted.text[:SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET]
            return HookReviewResponse(
                decision="deny",
                reason="HOL Guard could not complete local hook review safely.",
                model_output_action="block",
                notice="warning",
                reason_code="scanner_budget_exhausted",
            )

        if scan_result.matches:
            return HookReviewResponse(
                decision="deny",
                reason="HOL Guard blocked this output because it contains sensitive content.",
                model_output_action="block",
                notice="warning",
                reason_code="output_secret_match",
            )

        # Full output is clean — allow the model to see the original.
        return HookReviewResponse(
            decision="allow",
            reason=None,
            model_output_action="allow_original",
            notice="none",
            reason_code="output_scan_allow",
            policy_action="allow",
        )

    def _review_standard(
        self,
        request: HookReviewRequest,
        envelope: object,
        config: GuardConfig,
        start: float,
    ) -> HookReviewResponse:
        """Handle non-source-ref and inconclusive requests.

        For MVP:
        - PreToolUse, UserPromptSubmit, PermissionRequest: return not_applicable.
        - PostToolUse without source ref or inconclusive source ref:
          return replace_with_reviewed_excerpt (conservative).
        - Any scanner finding: deny/block.
        """
        if request.event_name != "PostToolUse":
            return HookReviewResponse(
                decision="allow",
                reason=None,
                model_output_action="not_applicable",
                notice="none",
                reason_code="non_post_tool_event",
            )

        # For post-tool output without a proven source ref, return a
        # conservative reviewed excerpt. The model should not receive
        # raw unreviewed output.
        #
        # If the output summary is available and small enough, we can
        # scan the excerpt. But we never allow original without proof.
        output_summary = request.output_summary
        if output_summary is not None and output_summary.text_excerpt:
            excerpt = output_summary.text_excerpt
            # Scan the excerpt for secrets.
            deadline = start + (HOOK_SCANNER_DEFAULT_BUDGET_MS / 1000.0)
            scan_result = self.scanner.scan_text(
                excerpt,
                local_content=True,
                source_context=False,
                max_bytes=SOURCE_READ_MAX_SCAN_BYTES,
                deadline_monotonic=deadline,
            )
            if scan_result.budget_exhausted:
                return HookReviewResponse(
                    decision="deny",
                    reason="HOL Guard could not complete local hook review safely.",
                    model_output_action="block",
                    notice="warning",
                    reason_code="scanner_budget_exhausted",
                )
            if scan_result.matches:
                return HookReviewResponse(
                    decision="deny",
                    reason="HOL Guard blocked this output because it contains sensitive content.",
                    model_output_action="block",
                    notice="warning",
                    reason_code="secret_match",
                )
            # Excerpt is safe, but we cannot prove the full output is safe.
            return HookReviewResponse(
                decision="allow",
                reason="HOL Guard returned a reviewed excerpt because this output could not be fully"
                " proven safe within local limits.",
                model_output_action="replace_with_reviewed_excerpt",
                reviewed_excerpt=excerpt,
                notice="excerpt",
                reason_code="reviewed_excerpt",
            )

        # No output summary at all — block conservatively.
        return HookReviewResponse(
            decision="deny",
            reason="HOL Guard could not complete local hook review safely.",
            model_output_action="block",
            notice="warning",
            reason_code="no_output_to_review",
        )

    def _record_metrics(self, request: HookReviewRequest, start: float) -> None:
        """Record metrics without raw content."""
        if self.metrics is None:
            return
        latency_ms = (time.monotonic() - start) * 1000.0
        record = getattr(self.metrics, "record", None)
        if callable(record):
            record(
                harness=request.harness,
                event_name=request.event_name,
                route="engine",
                payload_kind=request.payload_kind,
                output_size=0,
                latency_ms=latency_ms,
                decision="unknown",
                policy_action=None,
                model_output_action="unknown",
                reason_code="unknown",
                cache_status="not_applicable",
                fallback_kind="none",
                scanner_bytes=0,
            )


__all__ = [
    "ARBITRARY_STDOUT_FULL_ALLOW_BYTES",
    "HOOK_ENGINE_NORMAL_BUDGET_MS",
    "HOOK_ENGINE_TOTAL_BUDGET_MS",
    "HOOK_SCANNER_DEFAULT_BUDGET_MS",
    "HookFailSafe",
    "HookReviewEngine",
]
