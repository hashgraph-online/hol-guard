from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests import harness_ops_support as harness_support
from tests.codex_hook_private_group_support import group_is_private_to_owner

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and permission semantics are required")


def test_config_target_group_write_follows_whether_the_group_is_private(tmp_path: Path) -> None:
    """The runtime reads the real account database, so the expectation
    follows the account running the test."""
    config = tmp_path / "config.toml"
    config.write_text('model = "gpt-5"\n', encoding="utf-8")
    config.chmod(0o664)

    if not group_is_private_to_owner(config):
        with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
            validate_regular_file(config, role="config_target", executable_required=False)
        assert error.value.reason == "codex_hook_config_target_permissions_unsafe"
        return
    metadata = validate_regular_file(config, role="config_target", executable_required=False)

    assert metadata.st_uid == os.getuid()
    assert metadata.st_mode & 0o777 == 0o664


def test_codex_install_accepts_private_group_config_and_rewrites_owner_only(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    config = home_dir / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('model = "gpt-5"\n', encoding="utf-8")
    if not group_is_private_to_owner(config):
        pytest.skip("this account's file group is shared with another account")
    config.chmod(0o664)
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir / ".hol-guard")

    installed = harness_support.install("codex", context)

    assert installed["active"] is True
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
