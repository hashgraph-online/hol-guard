"""Non-authorizing native observations used by code-version regressions."""

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon import hook_native_exact_action
from codex_plugin_scanner.guard.native_daemon_route import _decide
from tests import native_review_evidence_support as review_support


def native_launch_evidence(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask the resident's ``launch_evidence`` kind for observations only.

    No runtime caller sends this kind; regressions use it to see the code,
    files and configuration an exact-action identity would cover. The
    resident observes the hook review through the exact action it derives.
    """
    del tool_name  # The resident reads the tool name from the payload.
    try:
        review = review_support._hook_review_query(
            harness=harness,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        )
        reply = _decide(
            {"kind": "launch_evidence", "action": review},
            guard_home,
            {"evidence": (dict, type(None)), "unavailable_reason": (str, type(None))},
            validate_launch_evidence,
            operation=review_support._OPERATION,
            max_request_bytes=review_support._MAX_REQUEST_BYTES,
        )
        return reply["evidence"], reply["unavailable_reason"]
    except (review_support.NativeExactActionError, OSError, RuntimeError, TypeError, ValueError):
        return None, hook_native_exact_action.UNPROVEN_LAUNCH


def validate_launch_evidence(payload: dict[str, Any]) -> None:
    """An observation never carries approval authority or an ambiguous identity."""
    invalid = review_support.NativeExactActionError(review_support._OPERATION.invalid)
    evidence, reason = payload["evidence"], payload["unavailable_reason"]
    if evidence is None:
        if reason not in hook_native_exact_action._ONCE_ONLY_REASONS:
            raise invalid
        return
    expected = {
        "schema": "guard-native-launch-evidence.v1",
        "code_identity_complete": False,
        "unknown_edges": ["unverified_code_closure"],
        "risk_verdict": "not_evaluated",
        "execution_binding": "unavailable",
        "duration": "none",
        "scope": "observed_invocation",
        "can_run_once": False,
        "can_persist": False,
    }
    if reason is not None or set(evidence) != {*expected, "inventory_sha256"}:
        raise invalid
    if any(evidence[key] != value or type(evidence[key]) is not type(value) for key, value in expected.items()):
        raise invalid
    digest = evidence["inventory_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise invalid


def native_exact_action(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
    tool_name: str | None = None,
) -> tuple[str | None, str | None]:
    """The exact-action token of one review, or why it stays once-only."""
    del tool_name  # The resident reads the tool name from the payload.
    _valid, _binding, token, reason = review_support.native_review_evidence(
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )
    return token, reason


def _arguments(
    command: str,
    workspace: Path,
    *,
    result: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
    payload_extra: dict[str, object] | None = None,
) -> dict[str, Any]:
    from tests.test_native_review_exact_action_always import _verdict

    default_result, default_receipt = _verdict()
    payload: dict[str, object] = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(workspace)}
    payload.update(payload_extra or {})
    return {
        "harness": "claude-code",
        "tool_name": "Bash",
        "payload": payload,
        "native_result": result or default_result,
        "native_receipt": receipt or default_receipt,
        "workspace": workspace,
        "home_dir": workspace.parent / "home",
    }


# The reason the resident gave for the most recent withheld observation, so a
# regression names its cause instead of only ``None``.
LAST_UNAVAILABLE_REASON: str | None = None


def _inventory(command: str, workspace: Path, **kwargs: Any) -> str | None:
    global LAST_UNAVAILABLE_REASON
    evidence, reason = native_launch_evidence(**_arguments(command, workspace, **kwargs))
    LAST_UNAVAILABLE_REASON = reason
    if evidence is None:
        assert isinstance(reason, str)
        return None
    assert reason is None
    assert evidence["code_identity_complete"] is False
    assert evidence["can_run_once"] is False and evidence["can_persist"] is False
    assert evidence["risk_verdict"] == "not_evaluated"
    digest = evidence["inventory_sha256"]
    assert isinstance(digest, str) and len(digest) == 64
    assert not digest.startswith("guard-approval-context:")
    return digest


def _permission(command: str, workspace: Path, **kwargs: Any) -> tuple[str | None, str | None]:
    return native_exact_action(**_arguments(command, workspace, **kwargs))
