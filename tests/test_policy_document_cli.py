from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _resolve_legacy_args, main
from codex_plugin_scanner.guard.policy_authority import PolicyAuthorityError
from codex_plugin_scanner.guard.store import GuardStore


def test_hol_guard_routes_policy_as_a_top_level_command() -> None:
    assert _resolve_legacy_args(
        ["policy", "validate", "policy.yaml"],
        program_mode="combined",
        program_name="hol-guard",
    ) == ["guard", "policy", "validate", "policy.yaml"]


def test_policy_export_validate_format_and_diff(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    policy_file = tmp_path / "policy.yaml"

    export_rc = main(
        [
            "guard",
            "policy",
            "export",
            "--home",
            str(home),
            "--output",
            str(policy_file),
            "--json",
        ]
    )
    export_payload = json.loads(capsys.readouterr().out)
    validate_rc = main(["guard", "policy", "validate", str(policy_file), "--json"])
    validate_payload = json.loads(capsys.readouterr().out)
    format_rc = main(["guard", "policy", "fmt", str(policy_file), "--check", "--json"])
    capsys.readouterr()
    diff_rc = main(
        [
            "guard",
            "policy",
            "diff",
            str(policy_file),
            "--home",
            str(home),
            "--json",
        ]
    )
    diff_payload = json.loads(capsys.readouterr().out)

    assert export_rc == 0
    assert export_payload["rules"] == 0
    assert validate_rc == 0
    assert validate_payload["valid"] is True
    assert format_rc == 0
    assert diff_rc == 0
    assert diff_payload == {
        "changed": False,
        "diff": "",
        "additions": [],
        "modifications": [],
        "removals": [],
        "impacted_scopes": [],
        "impacted_harnesses": [],
        "impacted_artifact_families": [],
        "conflict_warnings": [],
        "broadened_rules": [],
        "narrowed_rules": [],
        "unchanged_rules": [],
        "effective_action_changes": [],
        "broad_relaxing_changes": [],
        "requires_high_risk_approval": False,
    }


def test_policy_import_is_feature_gated_and_dry_run_by_default(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    policy_file = tmp_path / "policy.yaml"
    assert (
        main(
            [
                "guard",
                "policy",
                "export",
                "--home",
                str(home),
                "--output",
                str(policy_file),
            ]
        )
        == 0
    )
    capsys.readouterr()

    disabled_rc = main(
        [
            "guard",
            "policy",
            "import",
            str(policy_file),
            "--home",
            str(home),
            "--replace",
            "--json",
        ]
    )
    disabled_payload = json.loads(capsys.readouterr().out)

    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    dry_run_rc = main(
        [
            "guard",
            "policy",
            "import",
            str(policy_file),
            "--home",
            str(home),
            "--replace",
            "--json",
        ]
    )
    dry_run_payload = json.loads(capsys.readouterr().out)

    assert disabled_rc == 4
    assert disabled_payload["error"] == "policy_import_disabled"
    assert dry_run_rc == 0
    assert dry_run_payload["dry_run"] is True
    assert dry_run_payload["changed"] is False
    assert dry_run_payload["compiled_rows"] == 0
    assert dry_run_payload["additions"] == []
    assert dry_run_payload["impacted_scopes"] == []
    assert dry_run_payload["import_additions"] == []
    assert GuardStore(home).list_policy_decisions() == []


def test_policy_file_error_does_not_disclose_the_local_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "sensitive-workspace" / "private-policy.yaml"

    result = main(["guard", "policy", "validate", str(missing), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 4
    assert payload["error"] == "policy_parent_unavailable"
    assert str(missing) not in json.dumps(payload)


def test_policy_import_reports_authority_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    policy_file = tmp_path / "policy.yaml"
    assert (
        main(
            [
                "guard",
                "policy",
                "export",
                "--home",
                str(home),
                "--output",
                str(policy_file),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_dispatch_policy_document.prompt_for_approval_gate",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_dispatch_policy_document.require_high_risk",
        lambda *_args, **_kwargs: object(),
    )

    def reject_import(*_args: object, **_kwargs: object) -> None:
        raise PolicyAuthorityError("remote_policy_source_requires_validated_sync_path")

    monkeypatch.setattr(GuardStore, "import_policy_document", reject_import)

    result = main(
        [
            "guard",
            "policy",
            "import",
            str(policy_file),
            "--replace",
            "--apply",
            "--home",
            str(home),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 4
    assert payload["error"] == "PolicyAuthorityError"
    assert payload["message"] == "remote_policy_source_requires_validated_sync_path"
