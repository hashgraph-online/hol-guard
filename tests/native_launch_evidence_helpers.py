"""Non-authorizing native observations used by code-version regressions."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon import hook_native_exact_action
from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_exact_action


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
    files and configuration an exact-action identity would cover.
    """
    try:
        action = hook_native_exact_action._exact_query(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        )
        reply = hook_native_exact_action._answer({"kind": "launch_evidence", "action": action}, guard_home)
        return reply["evidence"], reply["unavailable_reason"]
    except (hook_native_exact_action.NativeExactActionError, OSError, RuntimeError, TypeError, ValueError):
        return None, hook_native_exact_action.UNPROVEN_LAUNCH


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
