"""Guard hook source-ref fast path."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..daemon.hook_request_parsing import parse_hook_source_file_ref
from ..native_mode import python_oracle_surface_enabled
from .commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from .commands_support_runtime_artifacts import _hook_event_name

if TYPE_CHECKING:
    import argparse

    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..runtime.hook_review_types import HookOutputSummary, HookReviewRequest, HookReviewResponse, HookSourceFileRef
    from ..store import GuardStore


_TestSourceRefOracle = Callable[["HookReviewRequest", "GuardStore", "GuardConfig | None"], "HookReviewResponse"]
_test_source_ref_oracle: _TestSourceRefOracle | None = None


def _try_source_ref_fast_path(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    """Run a source-ref oracle only when an explicit test has installed one."""

    if "guard_source_ref" not in payload:
        return None
    import os

    if os.environ.get("HOL_GUARD_HOOK_SOURCE_REF", "1") != "1" or not python_oracle_surface_enabled():
        return None

    from ..runtime.hook_review_types import HookReviewRequest
    from .commands_support_interaction import _emit
    from .commands_support_runtime_resolution import _canonical_harness_name

    oracle = _test_source_ref_oracle
    if oracle is None:
        return None

    source_ref_raw = payload.get("guard_source_ref")
    if not isinstance(source_ref_raw, Mapping):
        return None

    request = HookReviewRequest(
        harness=args.harness,
        event_name=_hook_event_name(payload) or "PreToolUse",
        payload=payload,
        payload_kind="source_file_ref",
        config_path=None,
        cwd=runtime_workspace,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        source_scope=str(payload.get("source_scope") or "project"),
        source_ref=_parse_source_ref(source_ref_raw),
        output_summary=_parse_output_summary(payload.get("tool_response_summary")),
    )
    response = oracle(request, store, config)
    event_name = _hook_event_name(payload) or "PostToolUse"
    record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=context.guard_home,
        harness=_canonical_harness_name(args.harness),
        event=event_name,
        payload=payload,
        succeeded=hook_post_succeeded(event_name, payload),
    )
    _emit("hook", response.to_harness_json(), getattr(args, "json", False))
    return 0


def _parse_source_ref(ref: Mapping[str, object]) -> HookSourceFileRef:
    return parse_hook_source_file_ref(ref)


def _parse_output_summary(summary_raw: object) -> HookOutputSummary | None:
    from ..runtime.hook_review_types import HookOutputSummary

    if not isinstance(summary_raw, Mapping):
        return None
    text_excerpt = summary_raw.get("text_excerpt") or summary_raw.get("excerpt") or ""
    output_sha256 = summary_raw.get("output_sha256")
    output_chars_raw = summary_raw.get("output_chars")
    return HookOutputSummary(
        text_excerpt=text_excerpt if isinstance(text_excerpt, str) else str(text_excerpt),
        excerpt_truncated=bool(summary_raw.get("excerpt_truncated", False)),
        output_sha256=output_sha256 if isinstance(output_sha256, str) else None,
        output_chars=int(output_chars_raw) if isinstance(output_chars_raw, (int, float)) else None,
    )


__all__ = ["_try_source_ref_fast_path"]
