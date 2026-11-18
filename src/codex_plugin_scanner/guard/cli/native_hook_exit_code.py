"""The process exit status a native hook sends its harness.

The verdict-to-exit-code table is Guard's native runtime (`hook-exit-code`,
`hook_decision_directive::exit_code`): which harness exits 2, which exits 1,
which carries a block in its envelope and exits 0, and how an action this
build does not recognise is treated as the review tier. This module sends it
the verdict and the one fact it cannot know: for grok, whether the Guard home
records protection as off.

With no native runtime there is nothing to ask: the outage path applies the
same table in this process, so an unavailable runtime exits exactly as the
runtime would have, and never leaves a blocking verdict on the allow path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_FEATURE = "native-hook-exit-code-v1"
_COMMAND = "hook-exit-code"
_OUTPUT_LIMIT = 4096
_TIMEOUT_SECONDS = 5.0
_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_RC_BLOCK_IS_ONE = frozenset({"opencode", "superagent"})
_RC_BLOCK_IS_TWO = frozenset({"cursor", "devin", "kimi", "hermes"})
_RC_BLOCK_IS_ZERO_ENVELOPE = frozenset({"codex", "claude-code", "copilot", "pi", "omp", "muse"})
_PREEMPTIVE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit", "PermissionRequest"})
_ZCODE_ASK_ACTIONS = frozenset({"review", "require-reapproval"})


def native_hook_verdict_exit_code(
    harness: str,
    policy_action: object,
    event_name: str | None = None,
) -> int:
    """Return the process exit code a harness expects for ``policy_action``.

    ``policy_action`` is the resolved action, not the wire ``decision`` string;
    an unrecognised value is the review tier. Without the native runtime the
    outage table below answers.
    """

    from ..mdm.runtime_request import runtime_answer

    encoded = _encode(harness, policy_action, event_name)
    answer = runtime_answer(_FEATURE, _COMMAND, encoded, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)
    code = None if answer is None else answer.get("exit_code")
    if isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 255:
        return code
    return _outage_exit_code(harness, policy_action, event_name)


def _outage_exit_code(harness: str, policy_action: object, event_name: str | None) -> int:
    """The runtime's table, for the one moment no runtime can be asked."""

    from ..action_lattice import normalize_guard_action

    action = normalize_guard_action(policy_action)
    blocking = action in _BLOCKING_ACTIONS
    if harness == "grok":
        return 2 if blocking and not _grok_recording_only() else 0
    if harness == "zcode":
        compact = (event_name or "PreToolUse").replace("_", "").replace("-", "").lower()
        if compact == "pretooluse" and action in _ZCODE_ASK_ACTIONS:
            return 0
        return 2 if blocking else 0
    if harness in _RC_BLOCK_IS_TWO:
        return 2 if blocking else 0
    if harness in _RC_BLOCK_IS_ONE:
        return 1 if blocking else 0
    if harness in _RC_BLOCK_IS_ZERO_ENVELOPE:
        return 0 if not blocking or event_name in _PREEMPTIVE_EVENTS else 1
    # Unknown harness: fail safe on the exit status only for blocking verdicts.
    return 1 if blocking else 0


def _encode(harness: str, policy_action: object, event_name: str | None) -> str:
    request = {
        "harness": harness,
        "policy_action": policy_action,
        "event_name": event_name,
        "recording_only": _grok_recording_only() if harness == "grok" else False,
    }
    try:
        return json.dumps(request, allow_nan=False)
    except (TypeError, ValueError):
        # A value JSON cannot carry is not evidence of permission: the runtime
        # reads a missing action as the review tier.
        request["policy_action"] = None
        return json.dumps(request, allow_nan=False)


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
    from ..config_file_io import ConfigFileTrustError
    from ..protection_posture import protection_is_off
    from ..store import GuardStore

    try:
        config = load_guard_config(GuardStore(Path(home_value)).guard_home)
    except ConfigFileTrustError:
        # A config Guard cannot read keeps protection on.
        return False
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


__all__ = ["native_hook_verdict_exit_code"]
