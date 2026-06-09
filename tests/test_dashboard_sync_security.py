"""Security tests for dashboard asset sync source verification."""

from __future__ import annotations

import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.cli.dashboard_sync import (
    _is_trusted_hol_guard_origin,
    _normalize_github_repo_slug,
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
