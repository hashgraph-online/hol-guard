from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and permission semantics are required")


def test_config_target_accepts_group_write_when_group_is_private_to_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('model = "gpt-5"\n', encoding="utf-8")
    config.chmod(0o664)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: True)

    metadata = validate_regular_file(config, role="config_target", executable_required=False)

    assert metadata.st_uid == os.getuid()
    assert metadata.st_mode & 0o777 == 0o664


def test_config_target_rejects_group_write_when_group_is_shared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('model = "gpt-5"\n', encoding="utf-8")
    config.chmod(0o664)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: False)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(config, role="config_target", executable_required=False)

    assert error.value.reason == "codex_hook_config_target_permissions_unsafe"


def test_codex_install_accepts_private_group_config_and_rewrites_owner_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    config = home_dir / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('model = "gpt-5"\n', encoding="utf-8")
    config.chmod(0o664)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: True)
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")

    installed = CodexHarnessAdapter().install(context)

    assert installed["active"] is True
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def test_private_group_detection_counts_primary_and_explicit_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import grp
    import pwd

    owner = SimpleNamespace(pw_name="alice", pw_gid=1000)
    other = SimpleNamespace(pw_name="bob", pw_gid=2000)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: owner)
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_mem=[]))
    monkeypatch.setattr(pwd, "getpwall", lambda: [owner, other])

    assert integrity._owner_is_only_group_member(1000, 1000) is True

    monkeypatch.setattr(pwd, "getpwall", lambda: [owner, SimpleNamespace(pw_name="bob", pw_gid=1000)])
    assert integrity._owner_is_only_group_member(1000, 1000) is False

    monkeypatch.setattr(pwd, "getpwall", lambda: [owner, other])
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_mem=["bob"]))
    assert integrity._owner_is_only_group_member(1000, 1000) is False
