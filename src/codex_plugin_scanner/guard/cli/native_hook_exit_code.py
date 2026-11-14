"""Single source of truth for native-hook verdict exit codes.

Every verdict-bearing emit path, including structured JSON responses, uses
``native_hook_verdict_exit_code`` with the canonical harness and hook event.

- cursor/devin/kimi/hermes: blocking verdicts exit 2.
- opencode/superagent: blocking verdicts exit 1.
- codex/claude-code/copilot/pi/omp: pre-execution and approval verdicts travel
  in JSON and exit 0; blocking observation events exit 1.
- grok: blocking verdicts exit 2 unless the Guard home records protection off.
- zcode: a review-tier PreToolUse exits 0 so ZCode opens its own prompt;
  other blocking verdicts exit 2.

The native runtime answers these codes itself; this module serves the
outage path, where no resident is left to ask.

Missing event context never assumes that the host will consume an envelope.
An action this build does not recognise is normalized to the review tier before
any exit code is chosen, so a newer or malformed producer value can never leave
the process on the allow path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..action_lattice import normalize_guard_action

_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_RC_BLOCK_IS_ONE = frozenset({"opencode", "superagent"})
_RC_BLOCK_IS_TWO = frozenset({"cursor", "devin", "kimi", "hermes"})
_RC_BLOCK_IS_ZERO_ENVELOPE = frozenset({"codex", "claude-code", "copilot", "pi", "omp", "muse"})
_PREEMPTIVE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit", "PermissionRequest"})
_ZCODE_ASK_ACTIONS = frozenset({"review", "require-reapproval"})


def native_hook_verdict_exit_code(
    harness: str,
    policy_action: str,
    event_name: str | None = None,
) -> int:
    """Return the process exit code a harness expects for ``policy_action``.

    ``policy_action`` is the resolved action (``"allow"``, ``"block"``,
    ``"review"``, ``"require-reapproval"``, ``"sandbox-required"``, …), not the
    wire ``decision`` string.  Callers pass ``"block"`` for the unavailable /
    fail-closed deny and the adapter's own contract decides the rc.

    An action outside the canonical lattice is not evidence of permission, so
    it is normalized to the review tier rather than falling through to the
    non-blocking exit code.
    """

    policy_action = normalize_guard_action(policy_action)
    blocking = policy_action in _BLOCKING_ACTIONS
    if harness == "grok":
        return 2 if blocking and not _grok_recording_only() else 0
    if harness == "zcode":
        return zcode_hook_process_exit(policy_action=policy_action, event_name=event_name)
    if harness in _RC_BLOCK_IS_TWO:
        return 2 if blocking else 0
    if harness in _RC_BLOCK_IS_ONE:
        return 1 if blocking else 0
    if harness in _RC_BLOCK_IS_ZERO_ENVELOPE:
        if not blocking or event_name in _PREEMPTIVE_EVENTS:
            return 0
        return 1
    # Unknown harness: fail safe on the exit status only for blocking verdicts.
    return 1 if blocking else 0


def zcode_hook_process_exit(*, policy_action: str, event_name: str | None = None) -> int:
    """The exit code ZCode expects: exit 2 discards stdout, so a review-tier
    PreToolUse exits 0 and its ``ask`` envelope opens ZCode's own prompt."""

    compact = (event_name or "PreToolUse").replace("_", "").replace("-", "").lower()
    normalized = normalize_guard_action(policy_action)
    if compact == "pretooluse" and normalized in _ZCODE_ASK_ACTIONS:
        return 0
    return 2 if normalized in _BLOCKING_ACTIONS else 0


def _grok_recording_only() -> bool:
    """Whether the Guard home this hook names has protection turned off."""

    home_value = None
    if "--guard-home" in sys.argv:
        index = sys.argv.index("--guard-home")
        if index + 1 < len(sys.argv):
            home_value = sys.argv[index + 1]
    home_value = home_value or os.environ.get("HOL_GUARD_HOME")
    if not home_value:
        return False
    from ..config import load_guard_config
    from ..protection_posture import protection_is_off
    from ..store import GuardStore

    config = load_guard_config(GuardStore(Path(home_value)).guard_home)
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


__all__ = ["native_hook_verdict_exit_code", "zcode_hook_process_exit"]
