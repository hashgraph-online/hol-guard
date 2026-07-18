from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm


def test_user_status_cli_is_versioned_read_only_and_nonhealthy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(["mdm", "status", "--scope", "user", "--home", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["schemaVersion"] == "hol-guard-mdm-status.v1"
    assert payload["scope"] == "user"
    assert payload["state"] == "absent"
    assert list(tmp_path.iterdir()) == []


def test_mutating_cli_rejects_relative_or_wrong_user_home(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del tmp_path
    exit_code = cli.main(
        ["mdm", "activate", "--home", "relative", "--user", "not-the-current-user", "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["reasonCodes"] == ["mdm_home_must_be_absolute"]


def test_cli_cannot_claim_managed_authority_from_a_policy_argument(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "mdm",
                "status",
                "--scope",
                "machine",
                "--policy-path",
                str(tmp_path / "policy.json"),
                "--json",
            ]
        )
    assert error.value.code == 2


def test_authorize_deactivation_cli_requires_auditable_actor_and_reason(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "mdm",
                "authorize-deactivation",
                "--home",
                str(tmp_path),
                "--user",
                "developer",
                "--json",
            ]
        )
    assert error.value.code == 2


def test_authorize_deactivation_cli_forwards_auditable_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    def authorize(
        home: Path,
        user: str,
        *,
        actor: str,
        reason: str,
        token_name: str | None = None,
    ) -> dict[str, object]:
        captured.update(home=home, user=user, actor=actor, reason=reason, token_name=token_name)
        return {"schemaVersion": "hol-guard-mdm-status.v1", "operation": "authorize-deactivation"}

    monkeypatch.setattr(commands_dispatch_mdm, "authorize_deactivation", authorize)
    exit_code = cli.main(
        [
            "mdm",
            "authorize-deactivation",
            "--home",
            str(tmp_path),
            "--user",
            "developer",
            "--actor",
            "mdm-admin@example.test",
            "--reason",
            "approved retirement",
            "--token-name",
            "developer.json",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["operation"] == "authorize-deactivation"
    assert captured == {
        "home": tmp_path,
        "user": "developer",
        "actor": "mdm-admin@example.test",
        "reason": "approved retirement",
        "token_name": "developer.json",
    }
