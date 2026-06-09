"""Security tests for dashboard asset sync source verification."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.dashboard_sync import (
    _export_committed_static_files,
    _is_safe_committed_tree_path,
    _is_trusted_hol_guard_origin,
    _list_committed_static_files,
    _normalize_github_repo_slug,
    _relative_static_path,
    verify_source_checkout,
)


def _init_fake_checkout(root: Path, *, remote_url: str) -> Path:
    checkout = root / "hol-guard"
    (checkout / "dashboard").mkdir(parents=True)
    (checkout / "dashboard" / "package.json").write_text("{}", encoding="utf-8")
    (checkout / "src" / "codex_plugin_scanner").mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=checkout, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "remote", "add", "origin", remote_url],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )
    static_dir = checkout / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "static"
    static_dir.mkdir(parents=True)
    (static_dir / "index.html").write_text("<html>safe</html>", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=checkout, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.email=guard@test", "-c", "user.name=Guard", "commit", "-m", "seed"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )
    return checkout


def test_normalize_github_repo_slug_requires_exact_repo_path() -> None:
    trusted_https = "https://github.com/hashgraph-online/hol-guard.git"
    trusted_ssh = "git@github.com:hashgraph-online/hol-guard.git"
    spoofed_host = "https://evil.example/hashgraph-online/hol-guard.git"
    wrong_owner = "https://github.com/evil/hashgraph-online/hol-guard.git"
    assert _normalize_github_repo_slug(trusted_https) == "hashgraph-online/hol-guard"
    assert _normalize_github_repo_slug(trusted_ssh) == "hashgraph-online/hol-guard"
    assert _normalize_github_repo_slug(spoofed_host) is None
    assert _normalize_github_repo_slug(wrong_owner) == "evil/hashgraph-online/hol-guard"


def test_is_trusted_hol_guard_origin_rejects_spoofed_hosts() -> None:
    assert _is_trusted_hol_guard_origin("https://github.com/hashgraph-online/hol-guard.git") is True
    assert _is_trusted_hol_guard_origin("https://evil.example/hashgraph-online/hol-guard.git") is False
    assert _is_trusted_hol_guard_origin("https://github.com/evil/hashgraph-online/hol-guard.git") is False


def test_verify_source_checkout_rejects_substring_spoof_remote(tmp_path: Path) -> None:
    checkout = _init_fake_checkout(
        tmp_path,
        remote_url="https://evil.example/repos/hashgraph-online/hol-guard-backdoor.git",
    )

    assert verify_source_checkout(checkout) is None


def test_verify_source_checkout_accepts_canonical_origin(tmp_path: Path) -> None:
    checkout = _init_fake_checkout(
        tmp_path,
        remote_url="https://github.com/hashgraph-online/hol-guard.git",
    )

    assert verify_source_checkout(checkout) == checkout


@pytest.mark.parametrize(
    "bad_path",
    [
        "src/static/../../evil.py",
        "src/static/./hidden.js",
        "/etc/passwd",
        "src\\static\\evil.py",
        "src/static/\x00evil.py",
        "",
        "src/static//double-slash",
    ],
)
def test_is_safe_committed_tree_path_rejects_unsafe_paths(bad_path: str) -> None:
    assert _is_safe_committed_tree_path(bad_path) is False


def test_relative_static_path_rejects_traversal_suffix() -> None:
    static_prefix = "src/codex_plugin_scanner/guard/daemon/static"
    traversal_path = f"{static_prefix}/../../evil.py"

    assert _relative_static_path(traversal_path, static_prefix) is None


class _FakeGitLsTreeResult:
    returncode = 0

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def test_list_committed_static_files_skips_unsafe_ls_tree_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    static_prefix = "src/codex_plugin_scanner/guard/daemon/static"
    safe_path = f"{static_prefix}/index.html"
    traversal_path = f"{static_prefix}/../../evil.py"

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.dashboard_sync._git_run",
        lambda *_args, **_kwargs: _FakeGitLsTreeResult(f"{safe_path}\n{traversal_path}\n"),
    )

    assert _list_committed_static_files(checkout, static_prefix) == [safe_path]


def test_export_committed_static_files_rejects_traversal_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    static_prefix = "src/codex_plugin_scanner/guard/daemon/static"
    safe_path = f"{static_prefix}/index.html"
    traversal_path = f"{static_prefix}/../../evil.py"

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.dashboard_sync._list_committed_static_files",
        lambda *_args, **_kwargs: [safe_path, traversal_path],
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.dashboard_sync._read_committed_file",
        lambda _checkout, path: (
            b"<html>safe</html>" if path == safe_path else b"malicious"
        ),
    )

    installed_static = tmp_path / "installed-static"
    installed_static.mkdir(parents=True)
    (installed_static / "index.html").write_text("<html>safe</html>", encoding="utf-8")

    copied_count = _export_committed_static_files(
        source_checkout=checkout,
        static_prefix=static_prefix,
        installed_static=installed_static,
    )

    assert copied_count == 1
    assert (installed_static / "index.html").is_file()
    assert not (tmp_path / "evil.py").exists()
    assert not (installed_static / "evil.py").exists()
