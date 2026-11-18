"""Codex install, uninstall, detection and launch, run through the native runtime.

The runtime plans every file, decides every refusal and answers every launch
question (see ``codex_harness_client``). This class runs what must run in the
Guard process: the install transaction and its locks, the authenticated hook
manifest baseline and key, the transition journal that publishes a plan, and
the launch processes the runtime names.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import codex_harness_client
from .codex_harness_client import (
    _PUBLISH_TIMEOUT_SECONDS,
    _codex,
    _plan_file,
    codex_native_request,
    codex_paths,
    raise_untrusted,
)
from .codex_hook_registration import codex_doctor_result
from .codex_remote_client import (
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefixes,
)
from .harness.native_harness import NativeHarnessAdapter
from .harness_context import HarnessContext, PreparedHarnessInstall

_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


def _command_available(context: HarnessContext) -> bool:
    """Whether the Codex CLI is on the caller's PATH or in a user install directory."""

    return _codex("command_available", context).get("available") is True


def _require_codex_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_harness_client.codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


class CodexHarnessAdapter(NativeHarnessAdapter):
    """The Codex harness: the runtime answers it, this process publishes and launches."""

    def __init__(self) -> None:
        super().__init__("codex", (), "")

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_candidates(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_from_prefixes(
            executable_prefixes=authorized_executable_prefixes,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
            environ=launch_environment,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        environment = self._ask("launch_env", context).get("env")
        return {str(key): str(value) for key, value in environment.items()} if isinstance(environment, dict) else {}

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        return codex_paths(context).backup

    def _detect_fields(self, context: HarnessContext) -> dict[str, object]:
        return codex_native_request(context)

    def _check_detected(self, answer: dict[str, Any]) -> None:
        if "untrusted" in answer:
            raise_untrusted(answer["untrusted"])

    def prepare_install(self, context: HarnessContext, *, surface: str | None = None) -> PreparedHarnessInstall:
        """The enrolled native installation, including retirements, planned without publication."""
        from .native_transition_files import _exception
        from .shims import shim_interpreter

        answer = self._ask(
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

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
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
