"""The process exit status a native hook sends its harness.

The verdict-to-exit-code table is Guard's native runtime (`hook-exit-code`,
`hook_decision_directive::exit_code`): which harness exits 2, which exits 1,
which carries a block in its envelope and exits 0, and how an action this
build does not recognise is treated as the review tier. This module sends it
the verdict and the one fact it cannot know: for grok, whether the Guard home
records protection as off.

With no native runtime the outage policy is block and repair: a verdict that
blocks exits with the fixed blocking code and the hook says how to repair; an
allow still lets the turn continue, as the caller chose when it picked it.
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
RUNTIME_ABSENT_EXIT_CODE = 2
_PASSING_ACTIONS = frozenset({"allow", "warn"})
RUNTIME_ABSENT_REPAIR_HINT = (
    "HOL Guard's native runtime is unavailable, so this action is blocked. Run `hol-guard repair`."
)


def native_hook_verdict_exit_code(
    harness: str,
    policy_action: object,
    event_name: str | None = None,
) -> int:
    """Return the process exit code a harness expects for ``policy_action``.

    ``policy_action`` is the resolved action, not the wire ``decision`` string;
    an unrecognised value is the review tier. Without the native runtime the
    status is ``RUNTIME_ABSENT_EXIT_CODE`` unless the action is allow or warn.
    """

    from ..mdm.runtime_request import runtime_answer

    encoded = _encode(harness, policy_action, event_name)
    answer = runtime_answer(_FEATURE, _COMMAND, encoded, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)
    code = None if answer is None else answer.get("exit_code")
    if isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 255:
        return code
    if policy_action in _PASSING_ACTIONS:
        return 0
    _ = sys.stderr.write(RUNTIME_ABSENT_REPAIR_HINT + "\n")
    return RUNTIME_ABSENT_EXIT_CODE


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


__all__ = ["RUNTIME_ABSENT_EXIT_CODE", "RUNTIME_ABSENT_REPAIR_HINT", "native_hook_verdict_exit_code"]
