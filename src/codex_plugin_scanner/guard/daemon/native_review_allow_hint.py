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
from typing import TYPE_CHECKING

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_allow_hint import (
    compute_extension_allow_hint,
    connector_setup_hint,
    hint_authority_admitted,
)
from ..runtime.extension_control_authority import ExtensionControlAuthorityView
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from ..runtime.native_command_evaluation import NativeCommandEvaluation, review_command_native
from .hook_native_exact_action import launch_cwd as _launch_cwd
from .hook_request_parsing import pre_tool_command, pre_tool_input
from .native_review_connector import connector_display_name

if TYPE_CHECKING:
    from ..local_cli_hook import SetupConnector

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
        "working_directory",
        "workingDirectory",
    }
)


def _command_only_payload(payload: Mapping[str, object]) -> bool:
    """True when the shell command is the only content the tool call carries."""

    tool_input = pre_tool_input(payload)
    if tool_input is None:
        return False
    return all(isinstance(key, str) and key in _COMMAND_ONLY_INPUT_KEYS for key in tool_input)


def _names_launch_directory(raw_payload: Mapping[str, object]) -> bool:
    value = raw_payload.get("cwd")
    return isinstance(value, str) and bool(value.strip())


def _stored_launch_cwd(raw_payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    """The launch directory of a stored approval, whose payload keeps only a redacted ``cwd``.

    The envelope labels directories under the home as ``~/...`` and anything else
    as ``.../name``. A ``~`` label expands against the daemon's own home; a label
    that cannot be traced back to an existing absolute directory yields None, so
    the caller declines a hint it would otherwise derive under the wrong cwd.
    """

    raw = raw_payload.get("cwd")
    if isinstance(raw, str) and (raw.strip() == "~" or raw.strip().startswith("~/")):
        text = raw.strip()
        return _launch_cwd({"cwd": str(Path.home() / text[2:])}, workspace)
    return _launch_cwd(raw_payload, workspace)


def _remaining_budget(deadline: float | None) -> float:
    if deadline is None:
        return _MAX_NATIVE_BUDGET_SECONDS
    return min(_MAX_NATIVE_BUDGET_SECONDS, deadline - time.monotonic() - _SAFETY_MARGIN_SECONDS)


def _evidence_binding(result: Mapping[str, object]) -> Mapping[str, object] | None:
    evidence = result.get("command_extensions")
    binding = evidence.get("binding") if isinstance(evidence, Mapping) else None
    return binding if isinstance(binding, Mapping) else None


def _settleable_uncertainties_only(evidence: Mapping[str, object], count: object) -> bool:
    """True when every uncertain observation is a rule observation the counterfactual can settle.

    Any extension's rule may be proposed: the hint is only stored when
    re-evaluating with its permission enabled actually allows the command, so
    this gate only checks that the uncertainty Rust paused on is fully
    accounted for by rule observations (never ruleless permission evidence).
    """
    if count == 0:
        return True
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        return False
    permission_observations = evidence.get("permission_observations")
    if isinstance(permission_observations, list) and any(
        isinstance(item, Mapping) and item.get("uncertainty_reasons") for item in permission_observations
    ):
        return False
    observations = evidence.get("observations")
    if not isinstance(observations, list):
        return False
    uncertain = [item for item in observations if isinstance(item, Mapping) and item.get("uncertainty_reasons")]
    return len(uncertain) == count


def _definite_review_binding(native_result: Mapping[str, object]) -> Mapping[str, object] | None:
    """Return the evidence binding when Rust paused on definite or settleable extension evidence."""

    if native_result.get("minimum_action") not in ("review", "require-reapproval"):
        return None
    # The hint promises an extension Allow settles the pause, which is only
    # ever true when the pause is the extension review itself. A fixed
    # PreTool floor (sensitive access, Guard self-protection, ...) carries
    # its own reason and reviews whatever the extensions say.
    if native_result.get("reason_code") != "native_command_review_required":
        return None
    evidence = native_result.get("command_extensions")
    if not isinstance(evidence, Mapping) or evidence.get("evaluation_error"):
        return None
    binding = _evidence_binding(native_result)
    if binding is None or not _settleable_uncertainties_only(evidence, binding.get("uncertainty_count")):
        return None
    if not isinstance(binding.get("observations_digest"), str):
        return None
    return binding


def _observed_risk_classes(native_result: Mapping[str, object]) -> list[str]:
    """Risk classes of the catalog rules the native evidence observed in this command.

    A critical rule or a destructive shell rule also records ``destructive`` so the
    connector recommendation keeps its caution for a pending delete.
    """

    evidence = native_result.get("command_extensions")
    observations = evidence.get("observations") if isinstance(evidence, Mapping) else None
    classes: list[str] = []
    for observation in observations if isinstance(observations, list) else []:
        rule_id = observation.get("rule_id") if isinstance(observation, Mapping) else None
        rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get_rule(rule_id) if isinstance(rule_id, str) else None
        if rule is not None:
            classes.extend(rule.risk_classes)
            if rule.severity == "critical" or "destructive_shell" in rule.risk_classes:
                classes.append("destructive")
    return sorted(set(classes))


def native_review_hint(
    store: object,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    deadline: float | None,
    connector: SetupConnector | None,
) -> dict[str, object] | None:
    """The queue-time hint for a paused review: the connector to set up, else the extension allow hint.

    A setup review waits on a CLI Guard does not know, so no command extension
    permission describes it; the connector hint is the only advice it carries.
    """

    if connector is not None:
        return connector_setup_hint(
            cli_id=connector.cli_id,
            identity_hash=connector.identity_hash,
            display_name=connector_display_name(connector),
            surface=connector.surface,
            risk_classes=_observed_risk_classes(native_result),
        )
    return native_review_extension_allow_hint(
        store,
        payload=payload,
        native_result=native_result,
        workspace=workspace,
        home_dir=home_dir,
        deadline=deadline,
    )


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
    if not hint_authority_admitted(snapshot) or budget < _MIN_NATIVE_BUDGET_SECONDS:
        return None
    cwd = _launch_cwd(payload, workspace)
    # The hint re-reviews the same command the hook just decided, so it reads
    # the shell the hook was stamped from rather than the daemon's own
    # environment. A worker that had nothing to stamp passes None and the
    # rules that need an inherited variable proven away stay at review.
    stamped = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    reviewed = review_command_native(
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
        extension_control_snapshot=snapshot,
        execution_environment=stamped if isinstance(stamped, Mapping) else None,
        timeout_seconds=budget,
        record_health=False,
        admit_unenrolled=True,
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
        guard_home=guard_home,
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
    guard_home: Path | None = None,
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
        guard_home=guard_home,
        deadline=deadline,
    )


def live_approval_extension_allow_hint(
    approval: Mapping[str, object],
    *,
    guard_home: Path,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> dict[str, object] | None:
    """Derive an advisory extension allow hint on read for a pending command review without a stored hint."""

    if approval.get("status") != "pending" or not hint_authority_admitted(snapshot):
        return None
    envelope = approval.get("action_envelope_json")
    if isinstance(envelope, Mapping) and envelope.get("action_type") not in (None, "shell_command"):
        return None
    raw_command = approval.get("raw_command_text")
    envelope_command = envelope.get("command") if isinstance(envelope, Mapping) else None
    command = (
        raw_command
        if isinstance(raw_command, str) and raw_command.strip()
        else (envelope_command if isinstance(envelope_command, str) and envelope_command.strip() else None)
    )
    if command is None:
        return None
    workspace_text = approval.get("workspace")
    workspace_path = Path(workspace_text) if isinstance(workspace_text, str) and workspace_text.strip() else None
    raw_payload = envelope.get("raw_payload_redacted") if isinstance(envelope, Mapping) else None
    if isinstance(raw_payload, Mapping) and pre_tool_input(raw_payload) is not None:
        if not _command_only_payload(raw_payload):
            return None
        cwd = _stored_launch_cwd(raw_payload, workspace_path)
        if cwd is None and _names_launch_directory(raw_payload):
            return None
    else:
        cwd = workspace_path
    try:
        reviewed = contextvars.copy_context().run(
            review_command_native,
            command,
            guard_home=guard_home,
            cwd=cwd,
            home_dir=Path.home(),
            extension_control_snapshot=snapshot,
            timeout_seconds=0.35,
            record_health=False,
            admit_unenrolled=True,
        )
    except Exception:
        return None
    if reviewed is None or _definite_review_binding(reviewed.payload) is None:
        return None
    return compute_extension_allow_hint(
        reviewed.evaluation,
        command_text=command,
        snapshot=snapshot,
        native_evidence=reviewed.payload,
        cwd=cwd,
        home_dir=Path.home(),
        guard_home=guard_home,
        deadline=time.monotonic() + _MAX_NATIVE_BUDGET_SECONDS,
    )


__all__ = [
    "hint_for_reviewed_command",
    "live_approval_extension_allow_hint",
    "native_review_extension_allow_hint",
    "native_review_hint",
]
