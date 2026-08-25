from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.authority import (
    AuthorityMode,
    AuthorityValidationError,
    ControlEffect,
    ControlInstruction,
    compose_control_instructions,
)


def _control(
    effect: ControlEffect,
    authority: AuthorityMode,
    source: str,
) -> ControlInstruction:
    return ControlInstruction(
        "command.git",
        "command.git.permission.push",
        effect,
        authority,
        source,
    )


def test_local_block_tightens_cloud_permit() -> None:
    result = compose_control_instructions(
        (
            _control(
                ControlEffect.PERMIT,
                AuthorityMode.WORKSPACE_SHARED,
                "cloud",
            ),
            _control(ControlEffect.BLOCK, AuthorityMode.PERSONAL_SHARED, "local"),
        )
    )
    assert result.effect is ControlEffect.BLOCK


def test_managed_block_cannot_be_weakened_by_local_permit() -> None:
    result = compose_control_instructions(
        (
            _control(
                ControlEffect.BLOCK,
                AuthorityMode.MANAGED_RESTRICTIVE,
                "organization",
            ),
            _control(ControlEffect.PERMIT, AuthorityMode.PERSONAL_SHARED, "local"),
        )
    )
    assert result.effect is ControlEffect.BLOCK
    assert result.managed_floor


def test_remembered_local_allow_cannot_bypass_managed_restriction() -> None:
    result = compose_control_instructions(
        (
            _control(
                ControlEffect.PERMIT,
                AuthorityMode.PERSONAL_SHARED,
                "remembered-allow:exact-command-context",
            ),
            _control(
                ControlEffect.BLOCK,
                AuthorityMode.MANAGED_RESTRICTIVE,
                "managed-control-set",
            ),
        )
    )
    assert result.effect is ControlEffect.BLOCK
    assert result.managed_floor


def test_managed_authority_cannot_publish_permit() -> None:
    with pytest.raises(AuthorityValidationError):
        _control(
            ControlEffect.PERMIT,
            AuthorityMode.MANAGED_RESTRICTIVE,
            "organization",
        )


def test_authority_rejects_string_enum_bypass_and_mixed_targets() -> None:
    with pytest.raises(AuthorityValidationError):
        ControlInstruction(
            "command.git",
            "command.git.permission.push",
            ControlEffect.PERMIT,
            "managed-restrictive",  # type: ignore[arg-type]
            "organization",
        )
    with pytest.raises(AuthorityValidationError):
        compose_control_instructions(
            (
                ControlInstruction(
                    "command.git",
                    "command.git.permission.push",
                    ControlEffect.BLOCK,
                    AuthorityMode.PERSONAL_SHARED,
                    "first",
                ),
                ControlInstruction(
                    "command.npm",
                    "command.npm.permission.install",
                    ControlEffect.PERMIT,
                    AuthorityMode.PERSONAL_SHARED,
                    "second",
                ),
            )
        )
