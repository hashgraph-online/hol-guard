"""Stand-ins for the launch ops ``guard_run_launch`` asks the native runtime."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

import pytest

from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.runtime import guard_run_launch

LaunchCommand = Callable[[HarnessContext, list[str]], list[str]]


def use_launch(
    monkeypatch: pytest.MonkeyPatch,
    launch_command: LaunchCommand,
    *,
    preview: Callable[[HarnessContext, list[str]], tuple[list[str], ...]] | None = None,
    from_plan: Callable[..., list[str]] | None = None,
) -> None:
    """Answer the launch questions from ``launch_command`` the way a plain harness does.

    A preview is the one launch command and finalizing re-asks for it. Pass ``preview``
    or ``from_plan`` for a harness whose preview or finalizing step differs.
    """

    def preview_launch_commands(_harness: str, context: HarnessContext, args: list[str]) -> tuple[list[str], ...]:
        if preview is not None:
            return preview(context, args)
        return (launch_command(context, args),)

    def launch_command_from_authorized_plan(
        _harness: str,
        context: HarnessContext,
        args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        if from_plan is not None:
            return from_plan(
                context,
                args,
                authorized_executable_prefixes=authorized_executable_prefixes,
                launch_environment=launch_environment,
            )
        return launch_command(context, args)

    monkeypatch.setattr(guard_run_launch, "preview_launch_commands", preview_launch_commands)
    monkeypatch.setattr(guard_run_launch, "launch_command_from_authorized_plan", launch_command_from_authorized_plan)
    monkeypatch.setattr(
        guard_run_launch, "prepare_launch_environment", lambda _harness, _context, inherited: dict(inherited)
    )


def use_native_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the runtime's own launch answers back after an autouse stub."""
    for name in ("preview_launch_commands", "launch_command_from_authorized_plan", "prepare_launch_environment"):
        monkeypatch.setattr(guard_run_launch, name, getattr(harness_ops, name))
