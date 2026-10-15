"""Single source of truth for native-hook verdict exit codes.

Every verdict-bearing emit path, including structured JSON responses, uses
``native_hook_verdict_exit_code`` with the canonical harness and hook event.

- cursor/devin/kimi/hermes: blocking verdicts exit 2.
- opencode/superagent: blocking verdicts exit 1.
- codex/claude-code/copilot/pi/omp: pre-execution and approval verdicts travel
  in JSON and exit 0; blocking observation events exit 1.
- grok/zcode: preserve the adapter's event-aware or recording-mode contract.

Missing event context never assumes that the host will consume an envelope.
"""

from __future__ import annotations

_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_RC_BLOCK_IS_ONE = frozenset({"opencode", "superagent"})
_RC_BLOCK_IS_TWO = frozenset({"cursor", "devin", "kimi", "hermes"})
_RC_BLOCK_IS_ZERO_ENVELOPE = frozenset({"codex", "claude-code", "copilot", "pi", "omp"})
_PREEMPTIVE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit", "PermissionRequest"})


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
        if not blocking or event_name in _PREEMPTIVE_EVENTS:
            return 0
        return 1
    # Unknown harness: fail safe on the exit status only for blocking verdicts.
    return 1 if blocking else 0


__all__ = ["native_hook_verdict_exit_code"]
