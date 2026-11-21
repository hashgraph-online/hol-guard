"""Alpha builds saved a separate Cloud actions sign-in; upgrading removes it.

The records are written in the alpha layout: a profile file per sign-in naming
a secret in Guard's encrypted secret store, plus `clients.json` and
`last-check.json`. Settings backups made by `ai-tools configure` stay.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli.cloud_actions_alpha_cleanup import (
    ALPHA_SIGN_IN_REMOVED_NOTICE,
    remove_alpha_sign_ins,
)
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

ALPHA_REF = "cloud-actions-default-0123456789abcdef"
OTHER_REF = "guard-oauth-local-credentials"


def _alpha_sign_in(guard_home: Path, name: str = "default", ref: str = ALPHA_REF) -> None:
    root = guard_home / "cloud-actions"
    (root / "profiles").mkdir(parents=True, exist_ok=True)
    (root / "profiles" / f"{name}.json").write_text(json.dumps({"name": name, "secret_ref": ref}), encoding="utf-8")
    (root / "clients.json").write_text("{}", encoding="utf-8")
    (root / "last-check.json").write_text("{}", encoding="utf-8")
    EncryptedFileSecretStore(guard_home).set_secret(ref, "alpha-sign-in")


def test_upgrade_removes_alpha_sign_ins_and_their_secrets(tmp_path: Path) -> None:
    _alpha_sign_in(tmp_path)
    _alpha_sign_in(tmp_path, "work", "cloud-actions-work-fedcba9876543210")
    secrets = EncryptedFileSecretStore(tmp_path)
    secrets.set_secret(OTHER_REF, "kept")
    backup = tmp_path / "cloud-actions" / "settings-backups" / "codex.toml"
    backup.parent.mkdir(parents=True)
    backup.write_text("kept", encoding="utf-8")

    assert remove_alpha_sign_ins(tmp_path) is True

    root = tmp_path / "cloud-actions"
    assert sorted(path.name for path in root.iterdir()) == ["settings-backups"]
    assert secrets.get_secret(ALPHA_REF) is None
    assert secrets.get_secret("cloud-actions-work-fedcba9876543210") is None
    assert secrets.get_secret(OTHER_REF) == "kept"
    assert backup.read_text(encoding="utf-8") == "kept"
    assert remove_alpha_sign_ins(tmp_path) is False


def test_a_profile_naming_another_secret_never_deletes_it(tmp_path: Path) -> None:
    secrets = EncryptedFileSecretStore(tmp_path)
    secrets.set_secret(OTHER_REF, "kept")
    _alpha_sign_in(tmp_path, ref=OTHER_REF)

    assert remove_alpha_sign_ins(tmp_path) is True

    assert secrets.get_secret(OTHER_REF) == "alpha-sign-in"
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_a_secret_that_could_not_be_deleted_keeps_its_profile_for_the_next_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _alpha_sign_in(tmp_path)
    secrets = EncryptedFileSecretStore(tmp_path)
    real_delete = EncryptedFileSecretStore.delete_secret

    def failing_delete(self: EncryptedFileSecretStore, secret_id: str) -> None:
        raise OSError("busy")

    monkeypatch.setattr(EncryptedFileSecretStore, "delete_secret", failing_delete)
    assert remove_alpha_sign_ins(tmp_path) is True
    assert (tmp_path / "cloud-actions" / "profiles" / "default.json").is_file()
    assert secrets.get_secret(ALPHA_REF) == "alpha-sign-in"

    monkeypatch.setattr(EncryptedFileSecretStore, "delete_secret", real_delete)
    assert remove_alpha_sign_ins(tmp_path) is True
    assert secrets.get_secret(ALPHA_REF) is None
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_profiles_past_one_runs_limit_are_removed_by_later_runs(tmp_path: Path) -> None:
    refs = [f"cloud-actions-p{index:03d}-{index:016x}" for index in range(70)]
    for index, ref in enumerate(refs):
        _alpha_sign_in(tmp_path, f"p{index:03d}", ref)
    secrets = EncryptedFileSecretStore(tmp_path)

    assert remove_alpha_sign_ins(tmp_path) is True
    assert remove_alpha_sign_ins(tmp_path) is True

    assert not (tmp_path / "cloud-actions" / "profiles").exists()
    assert all(secrets.get_secret(ref) is None for ref in refs)
    assert remove_alpha_sign_ins(tmp_path) is False


def test_nothing_to_remove_creates_nothing(tmp_path: Path) -> None:
    assert remove_alpha_sign_ins(tmp_path / "guard") is False

    assert not (tmp_path / "guard").exists()


def test_a_cloud_actions_command_says_once_that_it_removed_the_sign_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _alpha_sign_in(tmp_path)
    argv = ["cloud-actions", "status", "--guard-home", str(tmp_path), "--json"]

    assert cli.main(argv) == 0
    first = capsys.readouterr()
    assert cli.main(argv) == 0
    second = capsys.readouterr()

    assert first.err.strip() == ALPHA_SIGN_IN_REMOVED_NOTICE
    assert second.err == ""
    assert json.loads(first.out)["state"] == "not_paired"
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_the_bridge_leaves_alpha_records_for_a_command_to_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _alpha_sign_in(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    try:
        code = cli.main(["cloud-actions", "bridge", "codex", "--guard-home", str(tmp_path)])
    except SystemExit as exit_:
        code = int(exit_.code or 0)

    assert code == 4
    assert (tmp_path / "cloud-actions" / "profiles" / "default.json").exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["status", "--offline", "--json"],
        ["ai-tools", "configure", "codex", "--dry-run", "--json"],
    ],
)
def test_the_previews_guard_admits_as_reads_change_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    _alpha_sign_in(tmp_path)
    before = sorted(str(path) for path in tmp_path.rglob("*"))

    with contextlib.suppress(SystemExit):
        _ = cli.main(["cloud-actions", *argv, "--guard-home", str(tmp_path)])

    assert sorted(str(path) for path in tmp_path.rglob("*")) == before
    assert ALPHA_SIGN_IN_REMOVED_NOTICE not in capsys.readouterr().err
