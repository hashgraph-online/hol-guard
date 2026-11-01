"""Install concise agent guidance that reduces avoidable Guard reviews.

The native runtime (`agent-safety-guidance --stdin`) writes the managed
`~/.codex/AGENTS.md` block and `~/.hol-support/SAFETY.md`, and removes only
what Guard wrote.
"""

from __future__ import annotations

from pathlib import Path

_FEATURE = "native-agent-safety-guidance-v1"
_SCHEMA = "agent-safety-guidance.v1"
_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT = 64 * 1024


def install_agent_safety_guidance(home_dir: Path) -> dict[str, object]:
    """Install the Guard-owned guide and its managed global AGENTS.md pointer."""

    return _run("install", "install", home_dir)


def uninstall_agent_safety_guidance(home_dir: Path) -> dict[str, object]:
    """Remove only Guard-managed guidance after the last harness uninstall."""

    return _run("uninstall", "remove", home_dir)


def _run(op: str, action: str, home_dir: Path) -> dict[str, object]:
    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        "agent-safety-guidance",
        {"schema": _SCHEMA, "op": op, "home_dir": str(home_dir.absolute())},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise RuntimeError(
            f"Guard could not {action} agent safety guidance "
            + "(agents_changed=false, safety_changed=false): native runtime unavailable"
        )
    failure = answer.get("failure")
    if failure is not None:
        raise RuntimeError(failure if isinstance(failure, str) else f"Guard could not {action} agent safety guidance")
    return answer
