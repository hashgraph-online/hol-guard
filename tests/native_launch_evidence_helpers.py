"""Non-authorizing native observations used by code-version regressions."""

from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_exact_action, native_launch_evidence


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
