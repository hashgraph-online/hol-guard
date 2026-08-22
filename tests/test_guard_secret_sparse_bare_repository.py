from __future__ import annotations

import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
from codex_plugin_scanner.guard.secrets.setup_diagnostics import inspect_secrets_setup


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(root: Path) -> Path:
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "guard-test@example.invalid").returncode == 0
    assert _git(root, "config", "user.name", "Guard Test").returncode == 0
    return root


def test_sparse_checkout_is_partial_not_clean(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    (source / "visible").mkdir()
    (source / "hidden").mkdir()
    (source / "visible" / "safe.txt").write_text("safe\n", encoding="utf-8")
    (source / "hidden" / "secret.env").write_text("SECRET_KEY=not-a-real-value\n", encoding="utf-8")
    assert _git(source, "add", ".").returncode == 0
    assert _git(source, "commit", "-m", "tree").returncode == 0
    clone = tmp_path / "sparse"
    result = subprocess.run(
        ["git", "clone", source.as_uri(), str(clone)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert _git(clone, "sparse-checkout", "init", "--cone").returncode == 0
    assert _git(clone, "sparse-checkout", "set", "visible").returncode == 0

    scan = scan_repository_secrets(clone)

    assert scan.truncated is True
    assert "git_sparse_checkout_partial" in scan.errors


def test_bare_repository_reports_missing_working_tree_but_scans_history(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    (source / "safe.txt").write_text("safe\n", encoding="utf-8")
    assert _git(source, "add", "safe.txt").returncode == 0
    assert _git(source, "commit", "-m", "safe").returncode == 0
    bare = tmp_path / "bare.git"
    result = subprocess.run(
        ["git", "clone", "--bare", source.as_uri(), str(bare)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    scan = scan_repository_secrets(bare, include_history=True, max_commits=10)

    assert scan.truncated is True
    assert "bare_repository_working_tree_unavailable" in scan.errors
    assert scan.history_enabled is True
    assert scan.commits_scanned >= 1


def test_doctor_identifies_bare_repository_without_claiming_hook_readiness(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    (source / "safe.txt").write_text("safe\n", encoding="utf-8")
    assert _git(source, "add", "safe.txt").returncode == 0
    assert _git(source, "commit", "-m", "safe").returncode == 0
    bare = tmp_path / "bare.git"
    result = subprocess.run(
        ["git", "clone", "--bare", source.as_uri(), str(bare)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    report = inspect_secrets_setup(bare)

    bare_check = next(item for item in report.checks if item.code == "git_bare_repository")
    assert bare_check.status == "warn"
    assert not any(item.code == "git_metadata_writable" and item.status == "pass" for item in report.checks)
