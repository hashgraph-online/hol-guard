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
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from .actions import normalize_harness_payload
from .hook_content_scanner import ContentScanner, should_unsuppress_local_sample_secrets_for_paths
from .hook_decision_cache import HookDecisionCache
from .hook_review_types import HookReviewRequest, HookReviewResponse
from .hook_source_read import (
    SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET,
    SOURCE_READ_MAX_SCAN_BYTES,
    evaluate_source_file_ref,
)
from .skill_paths import is_safe_pi_inline_resource_uri

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore

HOOK_ENGINE_TOTAL_BUDGET_MS = 9000
HOOK_ENGINE_NORMAL_BUDGET_MS = 1000
HOOK_SOURCE_FAST_PATH_BUDGET_MS = 1000
HOOK_SCANNER_DEFAULT_BUDGET_MS = 750
ARBITRARY_STDOUT_FULL_ALLOW_BYTES = 256 * 1024


def _target_paths(envelope: object) -> tuple[str, ...]:
    target_paths = getattr(envelope, "target_paths", ())
    if isinstance(target_paths, (list, tuple)):
        return tuple(path for path in target_paths if isinstance(path, str) and path.strip())
    return ()


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
        config: GuardConfig | None = None
        response: HookReviewResponse
        try:
            config = self.config_loader(request.guard_home, request.cwd)
            response = self._review_inner(request, config=config, start=start)
        except HookFailSafe as error:
            response = error.to_response()
        except Exception as error:
            self._record_failure("engine", error)
            response = HookReviewResponse(
                decision="deny",
                reason="HOL Guard could not complete local hook review safely.",
                model_output_action="block",
                notice="warning",
                reason_code="engine_exception",
            )
        if config is not None and config.mode == "observe" and request.event_name == "PostToolUse":
            response = self._observe_only_response(request, response)
        self._record_metrics(request, response, start)
        return response

    @staticmethod
    def _observe_only_response(
        request: HookReviewRequest,
        response: HookReviewResponse,
    ) -> HookReviewResponse:
        observed_policy_action = response.policy_action
        if response.decision == "deny" and observed_policy_action is None:
            observed_policy_action = "block"
        output_sha256 = (
            request.source_ref.output_sha256
            if request.source_ref is not None
            else request.output_summary.output_sha256
            if request.output_summary is not None
            else None
        )
        return HookReviewResponse(
            decision="allow",
            reason=None,
            model_output_action="allow_original",
            reviewed_output_sha256=output_sha256,
            notice="none",
            reason_code=(f"observe_{response.reason_code}" if response.decision == "deny" else response.reason_code),
            policy_action="allow",
            observed_policy_action=observed_policy_action,
            observe_mode=True,
        )

    @staticmethod
    def _scan_deadline(
        start: float,
        budget_ms: int = HOOK_SCANNER_DEFAULT_BUDGET_MS,
        deadline_monotonic: float | None = None,
    ) -> float:
        deadline = min(
            start + (HOOK_ENGINE_TOTAL_BUDGET_MS / 1000.0),
            time.monotonic() + (budget_ms / 1000.0),
        )
        return min(deadline, deadline_monotonic) if deadline_monotonic is not None else deadline

    def _review_inner(
        self,
        request: HookReviewRequest,
        *,
        config: GuardConfig,
        start: float,
    ) -> HookReviewResponse:
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
            deadline = self._scan_deadline(
                start,
                HOOK_SOURCE_FAST_PATH_BUDGET_MS,
                request.deadline_monotonic,
            )
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

            source_path = request.source_ref.tool_input_path or request.source_ref.path
            target_paths = _target_paths(envelope)
            if (
                request.harness in {"pi", "omp"}
                and len(target_paths) == 1
                and source_path == target_paths[0]
                and is_safe_pi_inline_resource_uri(source_path)
            ):
                # OMP virtual resources have no filesystem path Guard can
                # independently re-read after the tool has resolved them.
                return self._review_output_scan(request, envelope, config, start)

            # Preserve the provenance boundary for ordinary paths, malformed
            # virtual URIs, and failed source proofs.
            return self._review_standard(request, envelope, config, start)

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
        """Scan full inline tool output for PostToolUse without guard_source_ref.

        This is the server-side fast path for all harnesses that do not
        generate ``guard_source_ref`` client-side (claude-code, codex,
        grok, zcode, etc.). It extracts the full tool output from the
        payload, scans it for secrets, and returns ``allow_original``
        if clean.

        PostToolUse observes output from an action that already ran. Applying
        the pre-execution permission engine again creates duplicate approvals
        and can stop every benign shell or MCP result. Scan any extractable
        inline output here; allow output-free completions and keep oversized
        or risky output on conservative paths.
        """
        from .hook_output_text import PAYLOAD_OUTPUT_KEYS, extract_payload_output

        extracted = extract_payload_output(request.payload)
        output_was_truncated = extracted.truncated or bool(
            request.output_summary is not None and request.output_summary.excerpt_truncated
        )

        if not extracted.text:
            if output_was_truncated:
                return HookReviewResponse(
                    decision="deny",
                    reason=(
                        "HOL Guard blocked this output because it could not be safely excerpted within local limits."
                    ),
                    model_output_action="block",
                    notice="warning",
                    reason_code="output_too_large",
                )
            if not any(key in request.payload for key in PAYLOAD_OUTPUT_KEYS):
                return self._review_standard(request, envelope, config, start)
            # The action already completed and produced nothing for the model.
            # A second permission review cannot protect any output and only
            # creates an unresolvable PostToolUse approval.
            return HookReviewResponse(
                decision="allow",
                reason=None,
                model_output_action="allow_original",
                notice="none",
                reason_code="output_empty_allow",
                policy_action="allow",
            )

        target_paths = _target_paths(envelope)
        scan_local_samples = should_unsuppress_local_sample_secrets_for_paths(target_paths, cwd=request.cwd)

        if output_was_truncated:
            # Output too large to scan in full — scan the excerpt before returning.
            excerpt = extracted.text[:SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET]
            deadline = self._scan_deadline(start, deadline_monotonic=request.deadline_monotonic)
            scan_result = self.scanner.scan_text(
                excerpt,
                local_content=scan_local_samples,
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
        deadline = self._scan_deadline(start, deadline_monotonic=request.deadline_monotonic)
        scan_result = self.scanner.scan_text(
            extracted.text,
            local_content=scan_local_samples,
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
        - PostToolUse reaching this path returns a reviewed excerpt.
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
        target_paths = _target_paths(envelope)
        scan_local_samples = should_unsuppress_local_sample_secrets_for_paths(target_paths, cwd=request.cwd)

        output_summary = request.output_summary
        if output_summary is not None and output_summary.text_excerpt:
            excerpt = output_summary.text_excerpt
            # Scan the excerpt for secrets.
            deadline = self._scan_deadline(start, deadline_monotonic=request.deadline_monotonic)
            scan_result = self.scanner.scan_text(
                excerpt,
                local_content=scan_local_samples,
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

    def _record_metrics(
        self,
        request: HookReviewRequest,
        response: HookReviewResponse,
        start: float,
    ) -> None:
        """Record metrics without raw content."""
        if self.metrics is None:
            return
        latency_ms = (time.monotonic() - start) * 1000.0
        record = getattr(self.metrics, "record", None)
        if callable(record):
            try:
                record(
                    harness=request.harness,
                    event_name=request.event_name,
                    route="engine",
                    payload_kind=request.payload_kind,
                    output_size=0,
                    latency_ms=latency_ms,
                    decision=response.decision,
                    policy_action=response.observed_policy_action or response.policy_action,
                    model_output_action=response.model_output_action,
                    reason_code=response.reason_code,
                    cache_status="not_applicable",
                    fallback_kind="none",
                    scanner_bytes=0,
                )
            except Exception as error:
                self._record_failure("metrics", error)

    def _record_failure(self, stage: str, error: Exception) -> None:
        if self.metrics is None:
            return
        record_failure = getattr(self.metrics, "record_failure", None)
        if callable(record_failure):
            with suppress(Exception):
                record_failure(stage=stage, exception_type=type(error).__name__)


__all__ = [
    "ARBITRARY_STDOUT_FULL_ALLOW_BYTES",
    "HOOK_ENGINE_NORMAL_BUDGET_MS",
    "HOOK_ENGINE_TOTAL_BUDGET_MS",
    "HOOK_SCANNER_DEFAULT_BUDGET_MS",
    "HookFailSafe",
    "HookReviewEngine",
]
