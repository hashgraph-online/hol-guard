"""Grok Build CLI hook exit status for HOL Guard."""

from __future__ import annotations

import os
import sys

from ..action_lattice import normalize_guard_action

# Every tier at or above review denies in Grok; an action Guard cannot place in
# the lattice normalizes to review before it is tested against this set.
_GROK_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})


def grok_hook_process_exit(policy_action: str) -> int:
    """Return the exit code Grok expects, failing closed on an unknown action."""

    if _recording_only_from_guard_home():
        return 0
    normalized = normalize_guard_action(policy_action)
    return 2 if normalized in _GROK_BLOCKING_ACTIONS else 0


def _guard_store_from_argv():
    home_value = None
    if "--guard-home" in sys.argv:
        index = sys.argv.index("--guard-home")
        if index + 1 < len(sys.argv):
            home_value = sys.argv[index + 1]
    if not home_value:
        home_value = os.environ.get("HOL_GUARD_HOME")
    if not home_value:
        return None
    from pathlib import Path

    from ..store import GuardStore

    return GuardStore(Path(home_value))


def _recording_only_from_guard_home() -> bool:
    store = _guard_store_from_argv()
    if store is None:
        return False
    from ..config import load_guard_config
    from ..protection_posture import protection_is_off

    config = load_guard_config(store.guard_home)
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


__all__ = [
    "grok_hook_process_exit",
]
