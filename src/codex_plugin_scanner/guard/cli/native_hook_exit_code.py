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
- ``pi`` / ``omp`` / ``opencode`` / ``superagent``: rc-driven generic contract —
  the pretool plugin maps ``exitCode 1`` to block and ``0`` to allow, so a
  blocking verdict must exit ``1``.
- ``codex`` / ``claude-code`` / ``opencode``-family envelope harnesses carry the
  deny inside ``hookSpecificOutput.permissionDecision``.  They must exit ``0``
  on a plain deny: a nonzero rc makes the harness treat the hook as errored and
  silently permit.  (``opencode`` is the exception — see above — it is rc-driven
  despite emitting a JSON envelope.)
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
_RC_BLOCK_IS_ONE = frozenset({"pi", "omp", "opencode", "superagent"})
_RC_BLOCK_IS_TWO = frozenset({"cursor", "devin", "kimi", "hermes"})
# Envelope-driven harnesses that must exit 0 even on a blocking verdict.
_RC_BLOCK_IS_ZERO_ENVELOPE = frozenset({"codex", "claude-code"})


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
        # Deny is inside hookSpecificOutput.permissionDecision; rc 0 so the
        # harness honors the envelope instead of reading an error.
        return 0
    # Unknown harness: fail safe on the exit status only for blocking verdicts.
    return 1 if blocking else 0


__all__ = ["native_hook_verdict_exit_code"]
