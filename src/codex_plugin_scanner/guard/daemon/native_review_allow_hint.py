"""Extension hints for paused native PreToolUse reviews, decided by the resident.

The resident's ``extension_review_hint`` op answers both hints a review carries:
the coverage hint, read out of the evidence the review paused on, and the allow
hint, stored only when the command reviewed again under the admitted snapshot
is exactly the review that paused and enabling the hinted permissions would
really settle it. Python sends the hook payload and the paused result and
shape-checks the answer; there is no Python evaluator and no fallback. A reply
that is not a bound, strictly decoded ``ok`` means no hint, so the dashboard
never promises an Extensions change that would not work.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ..native_daemon_route import _decide
from ..native_resident_decision import ResidentOperation
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_allow_hint import (
    connector_setup_hint,
    hint_authority_admitted,
    validated_extension_allow_hint,
)
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from ..runtime.extension_coverage_hint import (
    validated_extension_coverage_hint,
    with_extension_coverage,
)
from .hook_native_exact_action import launch_cwd as _launch_cwd
from .hook_request_parsing import pre_tool_input
from .native_review_connector import connector_display_name

if TYPE_CHECKING:
    from ..local_cli_hook import SetupConnector

EXTENSION_REVIEW_HINT_FEATURE: Final = "extension-review-hint-v1"
# A hook with no deadline still bounds the hint, as the allow-hint ask does.
_DEFAULT_BUDGET_SECONDS: Final = 5.0
# The read-time review and its counterfactual, plus the resident's safety
# margin: the budget the inbox gave the two asks this replaces.
_LIVE_BUDGET_SECONDS: Final = 1.2
# Approval persistence and the hook response still need time after the
# queue-time ask, and the ask's timeout also covers a slot wait and the round
# trip the resident's own margin cannot see.
_SAFETY_MARGIN_SECONDS: Final = 0.35
_MIN_BUDGET_SECONDS: Final = 0.15
_MAX_BUDGET_MS: Final = 10_000
# The resident refuses a canonical request over 1 MiB, so the client never
# sends a larger envelope.
_MAX_REQUEST_BYTES: Final = 1024 * 1024
_SLOTS: Final = threading.BoundedSemaphore(4)
# Tool-input keys that never carry a path, payload, or other content the
# command-only re-review could miss. A stored row with any other key may hold
# an independent review floor, so nothing is recovered for it.
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


class NativeExtensionReviewHintError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION: Final = ResidentOperation(
    operation="extension_review_hint",
    feature=EXTENSION_REVIEW_HINT_FEATURE,
    prefix="native_extension_review_hint",
    request_schema="guard-extension-review-hint-request.v1",
    request_id_prefix="extension-review-hint",
    result_schema="guard-extension-review-hint-result.v1",
    timeout_seconds=_DEFAULT_BUDGET_SECONDS,
    error=NativeExtensionReviewHintError,
)


def _ask_review_hint(
    payload: Mapping[str, object],
    *,
    guard_home: Path,
    workspace: Path | None,
    home_dir: Path | None,
    budget_seconds: float,
    paused: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """The resident's hints for ``payload``'s command, shape-checked, or None."""

    budget_ms = min(_MAX_BUDGET_MS, int(budget_seconds * 1000))
    if budget_ms <= 0:
        return None
    query: dict[str, object] = {
        "kind": "review_hint",
        "payload": dict(payload),
        "workspace": str(workspace) if workspace is not None else "",
        "home_dir": str(home_dir) if home_dir is not None else "",
        "budget_ms": budget_ms,
    }
    if paused is not None:
        query["paused"] = dict(paused)
    parsed: list[dict[str, object] | None] = []

    def validate(answer: dict[str, Any]) -> None:
        hint = answer["hint"]
        if hint is None:
            parsed.append(None)
            return
        checked = with_extension_coverage(validated_extension_allow_hint(hint), validated_extension_coverage_hint(hint))
        if checked is None:
            raise _OPERATION.fail(_OPERATION.invalid)
        parsed.append(checked)

    try:
        _decide(
            query,
            guard_home,
            {"hint": (dict, type(None))},
            validate,
            operation=replace(_OPERATION, timeout_seconds=budget_ms / 1000),
            max_request_bytes=_MAX_REQUEST_BYTES,
            slots=_SLOTS,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        # The hint is optional. A failure here must never affect the review itself.
        return None
    return parsed[0]


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
    """The queue-time hint for a paused review: the connector to set up, else the extension hints.

    A setup review waits on a CLI Guard does not know, so no command extension
    permission describes it; the connector hint is the only advice it carries.

    Every other paused review also carries the coverage hint, which names the
    extension that matched each step. The resident reads it out of the evidence
    it already returned, so it survives the budget, digest and all-or-nothing
    gates the allow hint has to clear, and most paused commands only ever earn
    this one.
    """

    if connector is not None:
        return connector_setup_hint(
            cli_id=connector.cli_id,
            identity_hash=connector.identity_hash,
            display_name=connector_display_name(connector),
            surface=connector.surface,
            risk_classes=_observed_risk_classes(native_result),
        )
    guard_home = getattr(store, "guard_home", None)
    # Both hints are read out of the extension evidence the review paused on;
    # without it there is nothing to ask for.
    if not isinstance(guard_home, Path) or not isinstance(native_result.get("command_extensions"), Mapping):
        return None
    budget = _DEFAULT_BUDGET_SECONDS if deadline is None else deadline - time.monotonic() - _SAFETY_MARGIN_SECONDS
    if budget < _MIN_BUDGET_SECONDS:
        return None
    return _ask_review_hint(
        payload,
        guard_home=guard_home,
        workspace=workspace,
        home_dir=home_dir,
        budget_seconds=budget,
        paused=native_result,
    )


def _live_reviewed_command(approval: Mapping[str, object]) -> tuple[str, Path | None] | None:
    """The command of a pending approval and where to review it again, for both read-time hints.

    A stored envelope redacts a launch directory outside the home directory to
    its last segment, so an approval queued from one can only be re-reviewed
    somewhere else. Extension rules read the directory — a Git rule matches
    differently inside a repository than outside one — so a review run in the
    workspace can name an extension that never governed the real command. That
    is wrong for a settlement and equally wrong for a step label pointing at a
    permission to pre-configure, so nothing is recovered for those rows.
    """

    if approval.get("status") != "pending":
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
        cwd = _launch_cwd({}, workspace_path)
    return command, cwd


def live_approval_extension_hint(
    approval: Mapping[str, object],
    *,
    guard_home: Path,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> dict[str, object] | None:
    """Both read-time hints from one re-review, for a pending review with nothing stored.

    Rows queued before the hints existed still reach the review screen, so the
    detail route recovers what it can for them rather than showing a command
    with no Extensions affordance at all.
    """

    if not hint_authority_admitted(snapshot):
        return None
    live = _live_reviewed_command(approval)
    if live is None:
        return None
    command, cwd = live
    payload: dict[str, object] = {"tool_input": {"command": command}}
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return _ask_review_hint(
        payload,
        guard_home=guard_home,
        workspace=None,
        home_dir=Path.home(),
        budget_seconds=_LIVE_BUDGET_SECONDS,
    )


def reviewed_command_extension_allow_hint(
    command: str,
    *,
    native_result: Mapping[str, object],
    snapshot: ExtensionControlRuntimeSnapshot,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The allow hint for a command reviewed outside a hook, such as for a support bundle."""

    if not hint_authority_admitted(snapshot):
        return None
    payload: dict[str, object] = {"tool_input": {"command": command}}
    if cwd is not None:
        payload["cwd"] = str(cwd)
    hint = _ask_review_hint(
        payload,
        guard_home=guard_home,
        workspace=None,
        home_dir=home_dir,
        budget_seconds=_DEFAULT_BUDGET_SECONDS,
        paused=native_result,
    )
    return validated_extension_allow_hint(hint)


def recovered_approval_extension_hint(
    stored: object,
    approval: Mapping[str, object],
    *,
    guard_home: Path,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> object:
    """The stored hint, plus whatever one read-time review can still recover.

    A queue-time review that ran out of budget, missed the digest or found no
    all-or-nothing settlement still stores the coverage it read out of the
    evidence it already had. So a stored hint no longer proves the settlement
    question was answered, and a row carrying coverage alone has to re-review
    exactly as a row carrying nothing does, or it silently loses the Always
    allow offer it used to get back here.
    """

    coverage = validated_extension_coverage_hint(stored)
    if stored is not None and (coverage is None or validated_extension_allow_hint(stored) is not None):
        return stored
    live = live_approval_extension_hint(approval, guard_home=guard_home, snapshot=snapshot)
    if coverage is None:
        # Nothing stored, so the read-time review is the whole answer and is
        # handed on exactly as it was before a row could store coverage alone.
        return live if live is not None else stored
    if live is None:
        return stored
    # The queue-time coverage saw the directory the command really ran in, so
    # it outranks anything this review measured.
    merged = with_extension_coverage(validated_extension_allow_hint(live), coverage)
    return merged if merged is not None else stored


__all__ = [
    "EXTENSION_REVIEW_HINT_FEATURE",
    "live_approval_extension_hint",
    "native_review_hint",
    "recovered_approval_extension_hint",
    "reviewed_command_extension_allow_hint",
]
