"""Queue-time Extensions allow hint for paused native PreToolUse reviews.

The native result carries no command model, so the hint re-derives the same
counterfactual the Python hook path uses. It is advisory: a hint is stored only
when the freshly bound native evidence matches the paused decision exactly and
enabling the hinted permissions would really settle it. Anything else stores no
hint, so the dashboard never promises an Extensions change that would not work.
"""

from __future__ import annotations

import contextvars
import logging
import time
from collections.abc import Mapping
from pathlib import Path

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_allow_hint import compute_extension_allow_hint
from ..runtime.extension_control_authority import ExtensionControlAuthorityView
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from ..runtime.native_command_evaluation import NativeCommandEvaluation, review_command_native
from .hook_native_launch_identity import launch_cwd as _launch_cwd
from .hook_request_parsing import pre_tool_command, pre_tool_input

_LOGGER = logging.getLogger(__name__)
# Approval persistence and the hook response still need time after the hint.
_SAFETY_MARGIN_SECONDS = 0.35
_MIN_NATIVE_BUDGET_SECONDS = 0.15
_MAX_NATIVE_BUDGET_SECONDS = 0.5
# Tool-input keys that never carry a path, payload, or other content the
# command-only re-review could miss. Any other key means the original decision
# may hold an independent review floor, so no hint is stored.
_COMMAND_ONLY_INPUT_KEYS = frozenset(
    {
        "command",
        "cmd",
        "shell_command",
        "shellCommand",
        "description",
        "timeout",
        "timeout_ms",
        "timeoutMs",
        "run_in_background",
        "runInBackground",
        "workdir",
        "cwd",
    }
)


def _command_only_payload(payload: Mapping[str, object]) -> bool:
    """True when the shell command is the only content the tool call carries."""

    tool_input = pre_tool_input(payload)
    if tool_input is None:
        return False
    return all(isinstance(key, str) and key in _COMMAND_ONLY_INPUT_KEYS for key in tool_input)


def _remaining_budget(deadline: float | None) -> float:
    if deadline is None:
        return _MAX_NATIVE_BUDGET_SECONDS
    return min(_MAX_NATIVE_BUDGET_SECONDS, deadline - time.monotonic() - _SAFETY_MARGIN_SECONDS)


def _evidence_binding(result: Mapping[str, object]) -> Mapping[str, object] | None:
    evidence = result.get("command_extensions")
    binding = evidence.get("binding") if isinstance(evidence, Mapping) else None
    return binding if isinstance(binding, Mapping) else None


def _definite_review_binding(native_result: Mapping[str, object]) -> Mapping[str, object] | None:
    """Return the evidence binding when Rust paused on definite, uncertainty-free extension evidence."""

    if native_result.get("minimum_action") != "review":
        return None
    evidence = native_result.get("command_extensions")
    if not isinstance(evidence, Mapping) or evidence.get("evaluation_error"):
        return None
    binding = _evidence_binding(native_result)
    if binding is None or binding.get("uncertainty_count") != 0:
        return None
    if not isinstance(binding.get("observations_digest"), str):
        return None
    return binding


def native_review_extension_allow_hint(
    store: object,
    *,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Return permission ids whose Allow state would let this paused command run, or None."""

    try:
        # A copied context keeps the advisory re-review from rewriting the
        # hook's recorded decision route.
        return contextvars.copy_context().run(
            _native_review_extension_allow_hint,
            store,
            payload=payload,
            native_result=native_result,
            workspace=workspace,
            home_dir=home_dir,
            deadline=deadline,
        )
    except Exception as error:
        # The hint is optional. A failure here must never affect the review itself.
        _LOGGER.warning("Native review allow hint unavailable (%s)", type(error).__name__)
        return None


def _native_review_extension_allow_hint(
    store: object,
    *,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    deadline: float | None,
) -> dict[str, object] | None:
    binding = _definite_review_binding(native_result)
    command = pre_tool_command(payload)
    reader = getattr(store, "read_extension_control_authority_for_registry", None)
    guard_home = getattr(store, "guard_home", None)
    if (
        binding is None
        or command is None
        or not _command_only_payload(payload)
        or not callable(reader)
        or not isinstance(guard_home, Path)
        or _remaining_budget(deadline) < _MIN_NATIVE_BUDGET_SECONDS
    ):
        return None
    view = reader(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)
    if not isinstance(view, ExtensionControlAuthorityView):
        return None
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    budget = _remaining_budget(deadline)
    if snapshot.authority_failure is not None or budget < _MIN_NATIVE_BUDGET_SECONDS:
        return None
    cwd = _launch_cwd(payload, workspace)
    reviewed = review_command_native(
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
        extension_control_snapshot=snapshot,
        timeout_seconds=budget,
        record_health=False,
    )
    if reviewed is None or (deadline is not None and _remaining_budget(deadline) <= 0):
        return None
    return hint_for_reviewed_command(
        native_result=native_result,
        reviewed=reviewed,
        snapshot=snapshot,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        deadline=None if deadline is None else deadline - _SAFETY_MARGIN_SECONDS,
    )


def hint_for_reviewed_command(
    *,
    native_result: Mapping[str, object],
    reviewed: NativeCommandEvaluation,
    snapshot: ExtensionControlRuntimeSnapshot,
    command: str,
    cwd: Path | None,
    home_dir: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Return the hint when the fresh evidence is exactly what Rust paused on."""

    binding = _definite_review_binding(native_result)
    fresh = _evidence_binding(reviewed.payload)
    # The counterfactual is only sound for the evidence Rust actually paused on.
    if (
        binding is None
        or fresh is None
        or fresh.get("observations_digest") != binding.get("observations_digest")
        or fresh.get("control_effective_digest") != binding.get("control_effective_digest")
        or reviewed.payload.get("minimum_action") != native_result.get("minimum_action")
        or reviewed.payload.get("reason_code") != native_result.get("reason_code")
    ):
        return None
    return compute_extension_allow_hint(
        reviewed.evaluation,
        command_text=command,
        snapshot=snapshot,
        native_evidence=reviewed.payload,
        cwd=cwd,
        home_dir=home_dir,
        deadline=deadline,
    )


__all__ = ["hint_for_reviewed_command", "native_review_extension_allow_hint"]
