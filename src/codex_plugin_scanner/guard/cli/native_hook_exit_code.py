"""Single source of truth for native-hook verdict exit codes.

Every hook emit path must translate a resolved ``policy_action`` into the
process exit code the host harness expects for that verdict through
``native_hook_verdict_exit_code``.  The per-harness mapping lives here — not
re-derived in ``commands_hook_native_finish``, ``commands_hook_native_*``,
or the adapters — so a deny can never mean rc 0 on one harness and rc 2 on
another for the same contract.

Contracts (PRD S10; MAJ-AC-06):

- ``cursor`` / ``devin`` / ``kimi`` / ``hermes``: blocking verdicts exit ``2``
  (the harness reads the exit status; the JSON is advisory).
- ``grok``: delegate to ``grok_hook_process_exit`` (``0`` in recording-only or
  when the last observed action was allow; else ``2`` on blocking actions).
- ``zcode``: delegate to ``zcode_hook_process_exit`` (``2`` on block, but ``0``
  on PreToolUse ``ask`` so the native permission prompt opens).
- ``opencode`` / ``superagent``: rc-driven generic contract — the generated
  pretool plugin maps ``exitCode 1`` to block and ``0`` to allow, so a
  blocking verdict must exit ``1``.
- ``codex`` / ``claude-code`` / ``copilot`` / ``pi`` / ``omp``: envelope-driven —
  the deny rides ``hookSpecificOutput.permissionDecision`` (codex/claude/
  copilot) or ``decision:"deny"`` (pi/omp).  On a preemptive hook they must
  exit ``0``: a nonzero rc makes the harness treat the hook as errored and
  silently permit.  Verified by the local Guard Gauntlet (omp PreToolUse deny
  arrives as a ``decision=="deny"`` envelope while the host exits 0).  On
  ``PostToolUse`` the tool already ran, so a blocking verdict exits ``1`` to
  flag the violation.
"""

from __future__ import annotations

_BLOCKING_ACTIONS = frozenset(
    {"review", "require-reapproval", "sandbox-required", "block"}
)

# Harnesses whose deny/block travels on the process exit code rather than the
# JSON envelope.  opencode is listed here because its generated pretool plugin
# branches on ``result.exitCode === 1`` to throw the block (see
# adapters/opencode_pretool_template.py); codex/claude/kimi are NOT listed —
# they read ``permissionDecision`` and must exit 0 on deny.
_RC_BLOCK_IS_ONE = frozenset({"opencode", "superagent"})
# devin/cursor/kimi/hermes exit 2 on a blocking verdict (the emitted JSON is
# advisory and the exit status is what denies the action).  pi/omp are NOT
# here — they are envelope-driven (gauntlet-verified) and deny on rc 0.
_RC_BLOCK_IS_TWO = frozenset({"cursor", "devin", "kimi", "hermes"})
# Envelope-driven harnesses: on a PREEMPTIVE hook the deny rides a JSON
# decision envelope (``hookSpecificOutput.permissionDecision`` for
# codex/claude-code/copilot, ``decision:"deny"`` for pi/omp) and the hook must
# exit ``0`` — a nonzero rc reads as a hook error and the harness silently
# permits.  Confirmed by the local gauntlet: omp PreToolUse deny arrives as a
# ``decision=="deny"`` envelope while the host process exits 0.  On
# ``PostToolUse`` the tool already ran, so there is no permission decision to
# preempt; the hook exits ``1`` on a blocking verdict to flag the violation.
_RC_BLOCK_IS_ZERO_ENVELOPE = frozenset({"codex", "claude-code", "copilot", "pi", "omp"})
# Events that can preempt the action — only these honor the envelope-only rc 0.
_PREEMPTIVE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit"})


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
    """

    blocking = policy_action in _BLOCKING_ACTIONS
    if harness == "grok":
        from ..adapters.grok_hooks import grok_hook_process_exit

        return grok_hook_process_exit(policy_action)
    if harness == "zcode":
        from ..adapters.zcode_hooks import zcode_hook_process_exit

        return zcode_hook_process_exit(policy_action=policy_action, event_name=event_name)
    if harness in _RC_BLOCK_IS_TWO:
        return 2 if blocking else 0
    if harness in _RC_BLOCK_IS_ONE:
        return 1 if blocking else 0
    if harness in _RC_BLOCK_IS_ZERO_ENVELOPE:
        # Preemptive deny is inside hookSpecificOutput.permissionDecision; rc 0
        # so the harness honors the envelope.  PostToolUse cannot preempt —
        # flag the violation on the exit status instead.
        if not blocking or event_name in _PREEMPTIVE_EVENTS:
            return 0
        return 1
    # Unknown harness: fail safe on the exit status only for blocking verdicts.
    return 1 if blocking else 0


__all__ = ["native_hook_verdict_exit_code"]
