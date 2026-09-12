"""Structured Errand command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
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
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

ERRAND_RUN_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (command, "Errand execution command", "command.errand.run")
    for command in (
        "errand -- make test",
        "errand --on linux -- make test",
        "errand --on=linux --detach --no-apply -- make test",
        "errand -on linux -d -- make test",
        'errand --profile dev --workdir "path with spaces" -- make test',
        "errand --on local --no-snapshot -- make test",
        "errand --on $RUNNER -- make test",
        "errand $OPTIONS -- make test",
        "errand -- make --help",
        "env BUILD_MODE=test errand -- make test",
        "exec errand -- make test",
        "xargs -n 1 errand -- make test",
        "errand.exe -- make test",
        "errand.cmd --on linux -- make test",
        "exec errand.exe -- make test",
    )
)
ERRAND_APPLY_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (command, "Errand checkout apply command", "command.errand.fetch-apply")
    for command in (
        "errand fetch --apply linux/job",
        "errand fetch -apply linux/job",
        "errand fetch --apply=true linux/job",
        "errand fetch --on linux --apply linux/job",
        "errand fetch --json --apply linux/job",
        "exec errand fetch --apply linux/job",
        "xargs -n 1 errand fetch --apply linux/job",
        "errand.exe fetch --apply linux/job",
    )
)
ERRAND_SAFE_COMMANDS: tuple[str, ...] = (
    "errand ps",
    "errand ps --json",
    "errand status linux/job",
    "errand doctor",
    "errand doctor --json",
    "errand version",
    "errand --help",
    "errand -h",
    "errand --on linux --help -- make test",
    "errand fetch linux/job",
    "errand fetch --output ./results linux/job",
    "errand fetch --apply=false linux/job",
    "errand fetch --help",
    "xargs errand ps",
    "exec errand doctor",
    "errand.exe ps",
    "errand.cmd doctor",
)


def _errand_enabled_snapshot() -> ExtensionControlRuntimeSnapshot:
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.errand"),
                state=ControlState.ENABLED,
            ),
        ),
    )
    return ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            1,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (layer,),
        )
    )


def test_errand_execution_and_apply_require_review_but_inspection_does_not(tmp_path: Path) -> None:
    with use_extension_control_snapshot(_errand_enabled_snapshot()):
        assert_reviewed_command_cases(ERRAND_RUN_CASES, tmp_path)
        assert_reviewed_command_cases(ERRAND_APPLY_CASES, tmp_path)
        assert_safe_command_cases(ERRAND_SAFE_COMMANDS, tmp_path)


def test_errand_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in (*ERRAND_RUN_CASES, *ERRAND_APPLY_CASES):
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.errand" for item in evaluation.extension_observations)


def test_errand_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.errand")
    assert extension is not None
    assert extension.to_dict()["trust_class"] == "external"
    assert extension.to_dict()["enabled"] is False
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
