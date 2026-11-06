"""Test-side adapter over the native runner-authority gate (Rust owns the verdict)."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime import runner_native_authority

__all__ = ["evaluation_authority_error", "runner_native_authority"]


def evaluation_authority_error(evaluation: object, *, require_launch_permitted: bool = False) -> str | None:
    return runner_native_authority.authority_error(
        evaluation,  # type: ignore[arg-type]
        require_launch_permitted=require_launch_permitted,
    )
