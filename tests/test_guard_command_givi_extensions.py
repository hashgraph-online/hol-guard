"""GiviLoop CLI boundaries evaluated by native code without running GiviLoop."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.native_command_test_support import (
    project_native_review_fixture,
    real_native_review_fixtures,
)

ROOT = Path(__file__).resolve().parents[1]
ENABLE = (("extension", "command.givi", "enabled"),)
OPERATIONS = (
    ("auto-review enable", "auto-review-config"),
    ("auto-review disable", "auto-review-config"),
    ("auto-review acknowledge", "auto-review-config"),
    ("auto-review run", "auto-review-run"),
    ("findings add", "findings-write"),
    ("findings update", "findings-write"),
)


def givi_segments(payload: dict[str, object]) -> dict[str, list[int]]:
    batch = payload.get("command_extensions")
    assert isinstance(batch, dict)
    assert batch.get("evaluation_error") is None
    observations = batch.get("observations")
    assert isinstance(observations, list)
    return {
        row["rule_id"]: row["effective_segment_indexes"]
        for row in observations
        if row["extension_id"] == "command.givi" and row["effective_segment_indexes"]
    }


@pytest.mark.parametrize(("operation", "permission"), OPERATIONS)
def test_givi_operation_reaches_native_inspection_and_runtime(operation: str, permission: str, tmp_path: Path) -> None:
    command = f"givi {operation}"
    rule_id = "command.givi." + operation.replace(" ", "-")
    native = real_native_review_fixtures((command,), controls=ENABLE)[0]
    assert native.payload["command_model"]["confidence"] == "exact"
    assert native.payload["minimum_action"] == "review"
    assert givi_segments(native.payload) == {rule_id: [0]}
    reviewed = project_native_review_fixture(native, cwd=tmp_path, home_dir=tmp_path)
    # Only replace the resident transport with its authentic offline result.
    # Production inspection consumes the unchanged native model and evidence.
    with patch(
        "codex_plugin_scanner.guard.runtime.command_inspection.review_command_native",
        return_value=reviewed,
    ):
        inspected = inspect_command(command, cwd=tmp_path, home_dir=tmp_path, guard_home=tmp_path)
    assert inspected["status"] == "review"
    assert inspected["side_effects"] == "none"
    assert rule_id in {row["rule_id"] for row in inspected["rules"]}
    blocked = real_native_review_fixtures(
        (command,),
        controls=(*ENABLE, ("permission", "command.givi.permission." + permission, "disabled")),
    )[0]
    assert blocked.payload["minimum_action"] == "block"
    assert givi_segments(blocked.payload) == {rule_id: [0]}


def test_excluded_commands_do_not_match_any_givi_rule() -> None:
    fixture = json.loads((ROOT / "tests/fixtures/command-source-givi.v1.json").read_text())
    commands = (
        *(case["command"] for case in fixture["cases"] if case["id"].startswith("excluded-")),
        "givi report --run-id R --stdout",
        "givi findings list --repo update --run-id add",
        "givi auto-review status --repo enable",
        "givi ask --question 'findings update'",
        "givi --repo=fixture-project auto-review enable",
        "givi findings --repo update list",
        "npm run givi -- auto-review enable",
        "npm --prefix 'another project' run givi -- auto-review enable",
        "node 'unrelated project/dist/cli.js' findings update",
        "node dist/mcp-server.js",
        "npm run mcp",
        "givi.cmd findings update",
        "givi.exe findings update",
    )
    active = real_native_review_fixtures(commands, controls=ENABLE)
    inactive = real_native_review_fixtures(commands)
    for command, enabled, disabled in zip(commands, active, inactive, strict=True):
        assert givi_segments(enabled.payload) == {}, command
        assert enabled.payload["minimum_action"] == disabled.payload["minimum_action"], command


def test_external_extension_requires_local_enable_and_off_is_inert() -> None:
    commands = tuple(f"givi {operation}" for operation, _ in OPERATIONS)
    for controls, managed in (
        ((), ()),
        ((), ENABLE),  # Signed-cloud enable cannot activate an external extension.
        ((("extension", "command.givi", "disabled"),), ()),
    ):
        for result in real_native_review_fixtures(commands, controls=controls, managed_controls=managed):
            assert result.payload["minimum_action"] == "review"
            assert not any(
                row["extension_id"] == "command.givi" for row in result.payload["command_extensions"]["observations"]
            )


@pytest.mark.parametrize(("operation", "_permission"), OPERATIONS)
def test_sudo_n_preserves_exact_givi_evidence_and_stronger_floor(operation: str, _permission: str) -> None:
    # The portable contract only admits allow/review/block; require-reapproval
    # is asserted here rather than weakened to review in a portable fixture.
    result = real_native_review_fixtures((f"sudo -n givi {operation}",), controls=ENABLE)[0]
    assert result.payload["command_model"]["confidence"] == "exact"
    assert result.payload["minimum_action"] == "require-reapproval"
    assert givi_segments(result.payload) == {"command.givi." + operation.replace(" ", "-"): [0]}


def test_unsupported_wrappers_and_malformed_shell_are_not_claimed_as_coverage() -> None:
    commands = (
        "env GIVI_TEST=1 givi auto-review enable",
        "sh -c 'givi auto-review enable'",
        "zsh -lc 'givi auto-review enable'",
        "exec givi auto-review enable",
        "command givi auto-review enable",
        "xargs givi auto-review enable",
        'givi findings update --reason "unterminated',
    )
    for result in real_native_review_fixtures(commands, controls=ENABLE):
        assert result.payload["minimum_action"] == "block"
        assert result.payload["command_model"]["confidence"] == "uncertain"
        # Unsupported parsing may report native evaluation failure. It must
        # remain blocked with no GiviLoop observations, never claimed support.
        assert result.payload["command_extensions"]["observations"] == []


def test_unicode_values_and_reordered_options_preserve_operation() -> None:
    commands = (
        'givi findings update --repo "città progetto" --reason "è cambiato"',
        'givi findings --json --repo "città progetto" update --id F --status unverified',
        'givi findings --repo "città progetto" --json --run-id R update --id F --status unverified',
        'givi findings --reason "update" --run-id R update --id F --status unverified',
    )
    for result in real_native_review_fixtures(commands, controls=ENABLE):
        assert result.payload["command_model"]["confidence"] == "exact"
        assert result.payload["minimum_action"] == "review"
        assert givi_segments(result.payload) == {"command.givi.findings-update": [0]}


def test_help_cannot_clear_another_segment_or_independent_disabled_permission() -> None:
    commands = (
        "givi findings update --help; givi findings update --run-id R --id F --status unverified",
        "givi findings update --run-id R --id F --status unverified; givi findings update --help",
        "givi findings add --help; givi findings update --run-id R --id F --status unverified",
    )
    results = real_native_review_fixtures(
        commands,
        controls=(*ENABLE, ("permission", "command.givi.permission.findings-write", "disabled")),
    )
    for result, segment in zip(results, (1, 0, 1), strict=True):
        assert result.payload["minimum_action"] == "block"
        assert givi_segments(result.payload) == {"command.givi.findings-update": [segment]}
    command = "givi findings add --help; git reset --hard"
    result = real_native_review_fixtures(
        (command,),
        controls=ENABLE,
        managed_controls=(("permission", "command.git.permission.hard-reset", "disabled"),),
    )[0]
    assert result.payload["minimum_action"] == "block"
    assert not givi_segments(result.payload)
    assert any(
        row["extension_id"] == "command.git" and row["effective_segment_indexes"] == [1]
        for row in result.payload["command_extensions"]["observations"]
    )


def test_managed_lockdown_remains_stronger_than_givi_review() -> None:
    result = real_native_review_fixtures(("givi auto-review enable",), controls=ENABLE, managed_global_lockdown=True)[0]
    assert result.payload["minimum_action"] == "block"
    assert givi_segments(result.payload) == {"command.givi.auto-review-enable": [0]}
