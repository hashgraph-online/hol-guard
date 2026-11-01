"""Review a hook payload through the production HookWorker path.

Tests that pinned a verdict on the retired Python hook-artifact composition
retarget here: the daemon's ``review_http_payload`` hands the payload to the
native hook edge, which is the path every harness hook takes. Callers need the
``native_hook_force`` fixture so ``HOL_GUARD_NATIVE_BINARY`` is authoritative.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore

# A warn with one of these reasons is recorded in the receipt but shows nothing.
_SILENT_WARNING_CODES = frozenset({"native_policy_observed", "native_policy_warning"})
_SHELL_TOOL = {"codex": "Bash", "claude-code": "Bash", "zcode": "Bash", "omp": "bash", "pi": "bash", "cursor": "Shell"}


def live_hook_review(
    payload: dict[str, object],
    *,
    harness: str,
    home_dir: Path,
    cwd: Path,
    workspace: Path | None = None,
    guard_home: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Return the daemon's answer to one hook payload, as the harness receives it.

    ``workspace`` defaults to ``cwd``: a harness hook names the workspace it
    runs in, and the native review fails closed on a hook that names none.
    """

    workspace = workspace if workspace is not None else cwd
    guard_home = guard_home if guard_home is not None else home_dir / ".guard"
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("HOME", str(home_dir))
        # The native Git and ripgrep proofs fail closed on runner overrides an
        # agent never carries, so strip them as the benign gate does.
        for name in list(os.environ):
            upper = name.upper()
            if upper.startswith(("GIT_", "LD_", "DYLD_")) or upper == "RIPGREP_CONFIG_PATH":
                patch.delenv(name)
        patch.setenv("XDG_CONFIG_HOME", str(home_dir / ".config"))
        for name, value in (environment or {}).items():
            patch.setenv(name, value)
        worker = HookWorker(store=GuardStore(guard_home), workspace=workspace)
        try:
            return worker.review_http_payload(
                payload={
                    "session_id": "live-hook-review",
                    "tool_call_id": "live-hook-review-1",
                    "cwd": str(cwd),
                    **payload,
                    "guard_execution_environment": collect_hook_execution_environment(),
                },
                params={},
                default_harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
        finally:
            worker.close()


def live_shell_review(
    command: str,
    *,
    home_dir: Path,
    cwd: Path,
    harness: str = "codex",
    workspace: Path | None = None,
    guard_home: Path | None = None,
    event: str = "PreToolUse",
    tool_name: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Return the daemon's answer to a shell tool call."""

    tool = tool_name if tool_name is not None else _SHELL_TOOL.get(harness, "Bash")
    return live_hook_review(
        {"hook_event_name": event, "tool_name": tool, "tool_input": {"command": command}},
        harness=harness,
        home_dir=home_dir,
        cwd=cwd,
        workspace=workspace,
        guard_home=guard_home,
        environment=environment,
    )


def live_post_tool_review(
    payload: dict[str, object],
    *,
    home_dir: Path,
    cwd: Path,
    harness: str = "codex",
    workspace: Path | None = None,
    guard_home: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Return the daemon's answer to a finished tool call and its output.

    ``payload`` carries ``tool_name``, ``tool_input`` and ``tool_response`` as
    the harness reports them; the event name is filled in here.
    """

    return live_hook_review(
        {"hook_event_name": "PostToolUse", "tool_name": "Bash", **payload},
        harness=harness,
        home_dir=home_dir,
        cwd=cwd,
        workspace=workspace,
        guard_home=guard_home,
        environment=environment,
    )


def post_tool_output_flagged(result: dict[str, object]) -> bool:
    """Whether the live post-tool review held, masked or replaced the output."""

    if result.get("policy_action") in {"block", "require-reapproval"}:
        return True
    if result.get("output_masked") is True:
        return True
    return result.get("model_output_action") not in (None, "allow_original")


def live_post_tool_flag(
    *,
    payload: dict[str, object],
    cwd: Path,
    home_dir: Path | None = None,
    harness: str = "codex",
) -> dict[str, object] | None:
    """Review a finished tool call; None when its output passes untouched.

    The live counterpart of the retired post-tool output artifact: a result
    means the output was held, masked or replaced.
    """

    home = home_dir if home_dir is not None else cwd.parent / "live-home"
    home.mkdir(parents=True, exist_ok=True)
    cwd.mkdir(parents=True, exist_ok=True)
    result = live_post_tool_review(payload, home_dir=home, cwd=cwd, harness=harness)
    return result if post_tool_output_flagged(result) else None


def assert_secret_output_held(result: dict[str, object] | None) -> None:
    """The live post-tool review found a credential in the output and withheld it from the model."""

    assert result is not None
    assert result["reason_code"] == "output_secret_match"
    assert result["model_output_action"] == "block"


def live_decision(result: dict[str, object]) -> str:
    """The effective verdict across harness response shapes: allow, ask or deny."""

    specific = result.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    permission = permission or result.get("permission") or result.get("decision")
    if result.get("continue") is False or result.get("policy_action") == "block" or permission in {"deny", "block"}:
        return "deny"
    if permission == "ask":
        return "ask"
    return "allow"


def quietly_allowed(result: dict[str, object]) -> bool:
    """Allowed with no review: the live counterpart of "no runtime artifact"."""

    if live_decision(result) != "allow":
        return False
    action = result.get("policy_action")
    reason = result.get("reason_code")
    if action == "warn":
        return reason in _SILENT_WARNING_CODES
    return action in (None, "allow")


# Shapes whose verdict only the retired Python hook-artifact composition gave.
# The live hook path disagrees; each stays pinned with its original expectation
# until the native runtime is brought into line or the expectation is retired.
LIVE_ALLOWS_RETIRED_REVIEW = pytest.mark.xfail(
    reason="the live hook path allows this shape; only the retired Python composition reviewed it",
    strict=True,
)
LIVE_REVIEWS_RETIRED_ALLOW = pytest.mark.xfail(
    reason="the live hook path reviews this shape; only the retired Python composition allowed it",
    strict=True,
)


# Shapes whose live verdict turns on where the host installs the program
# (npm, git): the Linux CI runner and a macOS developer host disagree. Each
# host gives a fixed answer, so the retired expectation is pinned strictly on
# the platform that disagrees and asserted plainly everywhere else.
def live_allows_retired_review_on(platform: str) -> pytest.MarkDecorator:
    """``LIVE_ALLOWS_RETIRED_REVIEW``, only where ``sys.platform`` starts with ``platform``."""

    return pytest.mark.xfail(
        sys.platform.startswith(platform),
        reason=f"on {platform} the live hook path allows this shape; only the retired Python composition reviewed it",
        strict=True,
    )


def live_reviews_retired_allow_on(platform: str) -> pytest.MarkDecorator:
    """``LIVE_REVIEWS_RETIRED_ALLOW``, only where ``sys.platform`` starts with ``platform``."""

    return pytest.mark.xfail(
        sys.platform.startswith(platform),
        reason=f"on {platform} the live hook path reviews this shape; only the retired Python composition allowed it",
        strict=True,
    )
