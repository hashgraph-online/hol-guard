"""Native OpenCode and Grok verification used by harness setup flows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..harness_context import HarnessContext
from ..store import GuardStore


def _opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    """Verify the managed OpenCode plugin, launcher, and MCP routing configuration."""
    from ..native_harness_client import ask

    answer = ask("protection", context, harness="opencode", store_home=None if store is None else str(store.guard_home))
    return json.loads(str(answer["checks"]))


#: A hook check may verify a signed Desktop proxy, which runs three `codesign` checks of up to 5s each.
_GROK_HOOK_CHECK_TIMEOUT_SECONDS = 60.0


def _grok_hook_check(op: str, context: HarnessContext | None, **fields: Any) -> dict[str, Any]:
    """Ask the native runtime a Grok hook question, owned by ``context`` or by no one."""
    from ..config import resolve_guard_home
    from ..native_harness_client import ask

    scope = context or HarnessContext(Path.home(), None, resolve_guard_home())
    return ask(op, scope, owner=context is not None, timeout_seconds=_GROK_HOOK_CHECK_TIMEOUT_SECONDS, **fields)


def _grok_hook_command_is_guard(command: str, context: HarnessContext | None = None) -> bool:
    """Whether a serialized hook invocation is Guard's native Grok hook, not arbitrary marker text."""
    return _grok_hook_check("grok_hook_command", context, command=command)["valid"] is True


def _grok_hook_files(context: HarnessContext, pretool_hook: Path, prompt_hook: Path) -> tuple[bool, bool]:
    """Whether the pre-tool file is the managed catch-all and the prompt file has the prompt and lifecycle hooks."""
    answer = _grok_hook_check("grok_hook_files", context, pretool=str(pretool_hook), prompt=str(prompt_hook))
    return answer["pretool"] is True, answer["prompt"] is True


def grok_protection(context: HarnessContext) -> dict[str, Any]:
    """Grok's protection paths, deny rules and hook timeouts, as the native adapter names them."""
    from ..native_harness_client import ask

    return ask("protection", context, harness="grok")


def grok_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Whether Grok's catch-all PreToolUse and prompt screening hooks are installed.

    The managed permission rules are a second layer, so a missing config does not fail this.
    """
    return _grok_hook_check("grok_hooks_verified", context)["verified"] is True


def grok_hooks_protection_ready(context: HarnessContext) -> bool:
    """Whether live Grok hook files and managed permission rules are active."""
    return _grok_hook_check("grok_hooks_ready", context)["ready"] is True


def _grok_protection_checks(context: HarnessContext) -> dict[str, object]:
    """The native verification of Grok's hook files, permission rules and launcher, with repair warnings."""
    checks = _grok_hook_check("grok_protection_checks", context)["checks"]
    return dict(checks) if isinstance(checks, dict) else {}
