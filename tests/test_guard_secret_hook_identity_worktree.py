from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook
from codex_plugin_scanner.guard.secrets.setup_diagnostics import inspect_secrets_setup


def _token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _repository(root: Path) -> Path:
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "guard-test@example.invalid").returncode == 0
    assert _git(root, "config", "user.name", "Guard Test").returncode == 0
    (root / "README.md").write_text("safe\n", encoding="utf-8")
    assert _git(root, "add", "README.md").returncode == 0
    assert _git(root, "commit", "-m", "baseline").returncode == 0
    return root


def test_managed_hook_pins_an_absolute_guard_identity(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")

    install_precommit_hook(root)
    hook = (root / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")

    assert "HOL_GUARD_SECRETS_PRE_COMMIT_V1" in hook
    assert "command -v hol-guard" not in hook
    assert "exec hol-guard " not in hook
    assert "scan --staged --fail-on-findings" in hook
    assert "pinned Guard executable is unavailable" in hook
    assert str(Path(os.sys.executable).resolve()).replace("\\", "/") in hook or "hol-guard" in hook


@pytest.mark.skipif(os.name == "nt", reason="POSIX PATH-hijack proof; Windows is covered by exact-wheel Git smoke")
def test_path_hijack_cannot_replace_pinned_guard_hook(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    install_precommit_hook(root)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker = tmp_path / "fake-ran"
    fake = fake_bin / "hol-guard"
    fake.write_text(f"#!/bin/sh\nprintf fake > '{marker}'\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    (root / "credentials.env").write_text(f"GITHUB_TOKEN={_token()}\n", encoding="utf-8")
    assert _git(root, "add", "credentials.env").returncode == 0
    environment = dict(os.environ)
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")

    commit = _git(root, "commit", "-m", "must remain blocked", env=environment)

    assert commit.returncode != 0
    assert not marker.exists()
    assert _token() not in commit.stdout + commit.stderr


def test_reinstall_repairs_a_stale_managed_hook_identity(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    first = install_precommit_hook(root)
    hook_path = root / ".git" / "hooks" / "pre-commit"
    stale = hook_path.read_text(encoding="utf-8").replace("scan --staged", "scan-stale --staged")
    hook_path.write_text(stale, encoding="utf-8")
    hook_path.chmod(0o755)

    second = install_precommit_hook(root)

    assert first.status == "installed"
    assert second.status == "updated"
    repaired = hook_path.read_text(encoding="utf-8")
    assert "scan-stale" not in repaired
    assert "scan --staged --fail-on-findings" in repaired


def test_linked_worktree_refuses_shared_hook_mutation(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    linked = tmp_path / "linked"
    added = _git(root, "worktree", "add", "-b", "linked-branch", str(linked))
    assert added.returncode == 0, added.stderr

    with pytest.raises(ValueError, match="linked worktree"):
        install_precommit_hook(linked)

    report = inspect_secrets_setup(linked)
    check = next(item for item in report.checks if item.code == "linked_worktree_shared_hooks")
    assert check.status == "warn"
    assert not (root / ".git" / "hooks" / "pre-commit").exists()


def test_standard_main_worktree_remains_installable(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")

    result = install_precommit_hook(root)

    assert result.status == "installed"
    assert (root / ".git" / "hooks" / "pre-commit").is_file()


def test_hook_uses_current_python_fallback_when_command_shim_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path / "repository")
    real_which = shutil.which

    def selective_which(command: str) -> str | None:
        if command == "hol-guard":
            return None
        return real_which(command)

    monkeypatch.setattr("codex_plugin_scanner.guard.secrets.precommit.shutil.which", selective_which)

    install_precommit_hook(root)
    hook = (root / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")

    assert "codex_plugin_scanner.guard.secrets.cli" in hook
    assert str(Path(os.sys.executable).resolve()).replace("\\", "/") in hook
