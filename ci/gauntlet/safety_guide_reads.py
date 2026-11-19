"""Reads of the safety guide that Guard's own install tells the agent to make.

`hol-guard install codex` adds a managed block to `~/.codex/AGENTS.md` asking the
agent to read `~/.hol-support/SAFETY.md` before planning shell, Git, package or
filesystem work. Codex follows it, so a lane case often opens with that read
before the scenario's single attempt. The read is product behaviour, not the
model wandering, and a block judge must not count it against the case.

Only an allowed plain `cat` of that exact file qualifies. Any other command,
path or verdict still counts as an extra request.
"""

from __future__ import annotations

import shlex
from typing import Any

GUIDE = "~/.hol-support/SAFETY.md"


def is_guide_read(decision: dict[str, Any]) -> bool:
    """True for an allowed `cat` of Guard's installed safety guide and nothing else."""
    if decision.get("decision") != "allow":
        return False
    command = decision.get("command")
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return tokens == ["cat", GUIDE]
