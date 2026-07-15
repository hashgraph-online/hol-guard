from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli


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
