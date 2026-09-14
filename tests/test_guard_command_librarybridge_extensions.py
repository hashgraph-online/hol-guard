"""Structured LibraryBridge command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)

LIBRARYBRIDGE_MUTATIONS: tuple[tuple[str, str, str, bool], ...] = (
    ("librarybridge fix 01234567 --force", "LibraryBridge fix command", "command.librarybridge.fix", True),
    ("librarybridge undo 01234567", "LibraryBridge undo command", "command.librarybridge.undo", True),
    ("librarybridge backup 01234567", "LibraryBridge backup command", "command.librarybridge.backup", True),
    (
        "librarybridge lutris import --plan /tmp/librarybridge-plan.json",
        "LibraryBridge Lutris import command",
        "command.librarybridge.lutris-import",
        True,
    ),
    (
        "librarybridge evidence 01234567 --record launch=yes",
        "LibraryBridge evidence recording command",
        "command.librarybridge.evidence-record",
        False,
    ),
    (
        "librarybridge lutris plan --candidate 01234567 --output /tmp/librarybridge-plan.json",
        "LibraryBridge Lutris plan command",
        "command.librarybridge.lutris-plan",
        True,
    ),
    (
        "librarybridge lutris forget --entry game-slug",
        "LibraryBridge Lutris forget command",
        "command.librarybridge.lutris-forget",
        True,
    ),
)


def test_librarybridge_mutations_review_but_dry_runs_do_not(tmp_path: Path) -> None:
    """Mutating LibraryBridge commands review while previews stay automatic."""

    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.librarybridge"),
                state=ControlState.ENABLED,
            ),
        ),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
        )
    )

    with use_extension_control_snapshot(snapshot):
        for command, action_class, rule_id, dry_run_is_safe in LIBRARYBRIDGE_MUTATIONS:
            reviewed = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
            assert reviewed["status"] == "review", command
            assert reviewed["classification"]["action_class"] == action_class, command
            assert reviewed["controlling_rule_id"] == rule_id, command

            for preview_flag in ("--dry-run", "-n"):
                preview = inspect_command(f"{command} {preview_flag}", cwd=tmp_path, home_dir=tmp_path)
                expected_status = "no_match" if dry_run_is_safe else "review"
                assert preview["status"] == expected_status, f"{command} {preview_flag}"

        for command in ("librarybridge scan", "librarybridge storage", "librarybridge evidence 01234567"):
            observer = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
            assert observer["status"] == "no_match", command
