"""What Codex adds to the generic harness operations, answered by the native runtime.

The runtime plans every Codex file, decides every refusal and answers every launch question (see
``codex_harness_client``). These functions run what must run in the Guard process: the authenticated hook
manifest baseline, the launch processes the runtime names, and the hook state the doctor reports.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from . import codex_harness_client
from .codex_harness_client import (
    _PUBLISH_TIMEOUT_SECONDS,
    _plan_file,
    codex_native_request,
    raise_untrusted,
)
from .codex_hook_registration import codex_doctor_result
from .codex_remote_client import (
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefixes,
)
from .harness_context import HarnessContext, PreparedHarnessInstall

_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


def _require_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_harness_client.codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


def _executable(context: HarnessContext) -> str:
    from .native_harness_ops import resolved_executable

    return resolved_executable("codex", context) or "codex"


def detect_fields(context: HarnessContext) -> dict[str, object]:
    """What the runtime's Codex detection asks of this process."""
    return codex_native_request(context)


def codex_launch_command(context: HarnessContext, passthrough_args: list[str]) -> list[str]:
    _require_authoritative_shell_hook(context)
    return guarded_codex_launch_command(
        executable=_executable(context), home_dir=context.home_dir, passthrough_args=passthrough_args
    )


def codex_preview_launch_commands(context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
    _require_authoritative_shell_hook(context)
    return guarded_codex_launch_command_candidates(
        executable=_executable(context), home_dir=context.home_dir, passthrough_args=passthrough_args
    )


def codex_launch_command_from_prefixes(
    context: HarnessContext,
    passthrough_args: list[str],
    *,
    authorized_executable_prefixes: Sequence[Sequence[str]],
    launch_environment: Mapping[str, str],
) -> list[str]:
    _require_authoritative_shell_hook(context)
    return guarded_codex_launch_command_from_prefixes(
        executable_prefixes=authorized_executable_prefixes,
        home_dir=context.home_dir,
        passthrough_args=passthrough_args,
        environ=launch_environment,
    )


def codex_prepare_install(context: HarnessContext) -> PreparedHarnessInstall:
    """The enrolled native installation, including retirements, planned without publication."""
    from .native_harness_client import run_op
    from .native_transition_files import _exception
    from .shims import shim_interpreter

    answer = run_op(
        "codex",
        "prepare_install",
        context,
        timeout_seconds=_PUBLISH_TIMEOUT_SECONDS,
        interpreter=shim_interpreter(),
        **codex_native_request(context),
    )
    if "untrusted" in answer:
        raise_untrusted(answer["untrusted"])
    if "fault" in answer:
        raise _exception(answer["fault"])
    return PreparedHarnessInstall(
        tuple(_plan_file(item) for item in answer["files"]), json.loads(str(answer["manifest"]))
    )


def codex_diagnostics(context: HarnessContext, payload: dict[str, Any]) -> dict[str, object]:
    """The doctor report with Codex's hook state folded in."""
    hook_state = codex_harness_client.codex_native_hook_state(context)
    warning_items = payload.get("warnings")
    items = warning_items if isinstance(warning_items, list) else []
    warnings, setup_status = codex_doctor_result(
        [str(item) for item in items if isinstance(item, str)], hook_state, payload.get("setup_status")
    )
    payload["warnings"] = warnings
    payload["setup_status"] = setup_status
    payload["native_hook_state"] = hook_state
    return payload
