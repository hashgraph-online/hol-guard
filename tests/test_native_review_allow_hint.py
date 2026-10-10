"""Native daemon reviews store an Extensions allow hint only when enabling it would really allow."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.native_review_allow_hint import hint_for_reviewed_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import validated_extension_allow_hint
from tests.native_command_test_support import project_native_review_fixture, real_native_review_fixture


def _hint(command: str, tmp_path: Path, *, controls=(), native_result_override: dict[str, object] | None = None):
    fixture = real_native_review_fixture(command, cwd=tmp_path, home_dir=tmp_path, controls=controls)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    native_result = {**fixture.payload, **(native_result_override or {})}
    return fixture, hint_for_reviewed_command(
        native_result=native_result,
        reviewed=reviewed,
        snapshot=fixture.snapshot,
        command=command,
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_plain_origin_fetch_hints_the_origin_refresh_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin main", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert hint["rule_ids"] == ["command.git.unverified-fetch"]
    assert hint["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert validated_extension_allow_hint(hint) == hint
    assert "main" not in repr(hint)


def test_uncertain_fetch_forms_store_no_hint(tmp_path: Path) -> None:
    for command in (
        "git -c core.sshCommand=payload fetch origin",
        "git fetch origin --upload-pack=payload",
        "git fetch https://example.invalid/project.git",
    ):
        _fixture, hint = _hint(command, tmp_path)
        assert hint is None, command


def test_no_hint_when_the_origin_refresh_permission_is_already_allowed(tmp_path: Path) -> None:
    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        controls=(("permission", "command.git.permission.unverified-fetch", "enabled"),),
    )

    assert hint is None


def test_hint_requires_the_fresh_evidence_to_match_the_paused_decision(tmp_path: Path) -> None:
    fixture, _hint_value = _hint("git fetch origin", tmp_path)
    binding = dict(fixture.payload["command_extensions"]["binding"])  # type: ignore[index]
    binding["observations_digest"] = "0" * 64

    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        native_result_override={"command_extensions": {**fixture.payload["command_extensions"], "binding": binding}},  # type: ignore[dict-item]
    )

    assert hint is None


def test_no_hint_for_a_blocked_native_decision(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin", tmp_path, native_result_override={"minimum_action": "block"})

    assert hint is None
