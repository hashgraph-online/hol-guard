"""Proof of user presence for removing every Guard hook.

When the local approval gate is enabled, removal goes through the normal
step-up (`require_high_risk`, password or authenticator code). When no gate is
configured there is nothing to step up against, so removal needs a different
proof that a person is at the keyboard. The choice here is a typed confirmation
phrase on an interactive terminal, and a refusal everywhere else:

* a phrase cannot be satisfied by an agent, script, or pipe, because stdin must
  be a TTY and the phrase must be typed back verbatim;
* it changes no stored state, unlike silently creating a password the user did
  not ask for, so declining leaves the install untouched;
* the command still tells the user how to enable the real gate.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from .approval_gate import ApprovalGateError, public_config

CONFIRMATION_PHRASE = "remove guard hooks"
_NO_GATE_NOTICE = (
    "No local approval gate is configured, so Guard cannot ask for a password or authenticator code. "
    "Enable one in `hol-guard dashboard` under Settings > Approval gate to protect this action."
)


def removal_gate_enabled(authority_home: Path) -> bool:
    return bool(public_config(authority_home).enabled)


def require_typed_presence(
    *,
    affected: str,
    isatty: Callable[[], bool] | None = None,
    read_line: Callable[[str], str] | None = None,
    error_stream: TextIO | None = None,
) -> None:
    """Require the confirmation phrase on an interactive terminal, else raise."""

    stream = error_stream or sys.stderr
    tty = isatty if isatty is not None else sys.stdin.isatty
    if not tty():
        raise ApprovalGateError(
            "approval_gate_interactive_required",
            "Removing all Guard hooks needs an interactive terminal when no approval gate is configured. "
            "Run `hol-guard hooks remove --all` yourself, or enable the approval gate first.",
        )
    print(_NO_GATE_NOTICE, file=stream)
    print(f"This will remove Guard hooks from: {affected}", file=stream)
    prompt = f'Type "{CONFIRMATION_PHRASE}" to continue: '
    reader = read_line if read_line is not None else input
    try:
        typed = reader(prompt)
    except (EOFError, KeyboardInterrupt) as error:
        raise ApprovalGateError("approval_gate_confirmation_declined", "Removal was not confirmed.") from error
    if typed.strip().lower() != CONFIRMATION_PHRASE:
        raise ApprovalGateError("approval_gate_confirmation_declined", "Confirmation phrase did not match.")


__all__ = ["CONFIRMATION_PHRASE", "removal_gate_enabled", "require_typed_presence"]
