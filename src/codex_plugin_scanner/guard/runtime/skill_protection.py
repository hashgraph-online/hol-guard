"""Native skill content risk detection for Guard.

Rust owns the skill content detector and the content-addressed skill
identity; Python asks the resident for the risk signals and never runs a
Python evaluator.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2

_MAX_SIGNALS = 64


def detect_skill_content_risk(
    content: str,
    *,
    guard_home: Path | None = None,
) -> tuple[RiskSignalV2, ...]:
    """Return the native risk signals for SKILL.md content."""
    payload = native_runner_authority("skill_content_risk", {"content": content}, guard_home)
    signals = payload.get("signals")
    if not isinstance(signals, list) or len(signals) > _MAX_SIGNALS:
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    try:
        return tuple(RiskSignalV2.from_dict(signal) for signal in signals)
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid") from error
