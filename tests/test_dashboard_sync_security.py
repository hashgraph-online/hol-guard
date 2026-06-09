"""Security tests for dashboard asset sync source verification."""

from __future__ import annotations

import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.cli.dashboard_sync import (
    _export_committed_static_files,
    _is_safe_committed_tree_path,
    _is_trusted_hol_guard_origin,
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


def test_is_safe_committed_tree_path_rejects_traversal_segments() -> None:
    static_prefix = "src/codex_plugin_scanner/guard/daemon/static"
    traversal_path = f"{static_prefix}/../../evil.py"

    assert _is_safe_committed_tree_path(traversal_path) is False
    assert _relative_static_path(traversal_path, static_prefix) is None


def _hash_blob(checkout: Path, payload: bytes) -> str:
    return (
        subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=checkout,
            input=payload,
            capture_output=True,
            check=True,
            text=False,
        )
        .stdout.decode("utf-8")
        .strip()
    )


def _mktree(checkout: Path, entries: list[tuple[str, str, str, str]]) -> str:
    lines = [f"{mode} {kind} {obj_hash}\t{name}" for mode, kind, obj_hash, name in entries]
    result = subprocess.run(
        ["git", "mktree"],
        cwd=checkout,
        input="\n".join(lines).encode("utf-8") + b"\n",
        capture_output=True,
        check=True,
        text=False,
    )
    return result.stdout.decode("utf-8").strip()


def _parse_ls_tree_line(line: str) -> tuple[str, str, str, str]:
    mode, obj_type, obj_hash, name = line.split(maxsplit=3)
    return mode, obj_type, obj_hash, name.removeprefix('"').removesuffix('"')


def _replace_tree_at_path(
    checkout: Path,
    tree_hash: str,
    parts: list[str],
    replacement_hash: str,
) -> str:
    if not parts:
        return replacement_hash

    part = parts[0]
    child_entries: list[tuple[str, str, str, str]] = []
    child_hash = ""
    for line in subprocess.run(
        ["git", "ls-tree", tree_hash],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.splitlines():
        mode, obj_type, obj_hash, name = _parse_ls_tree_line(line)
        if name == part:
            child_hash = obj_hash
        child_entries.append((mode, obj_type, obj_hash, name))

    if child_hash == "":
        raise RuntimeError(f"missing tree segment: {part}")

    updated_child = (
        replacement_hash
        if len(parts) == 1
        else _replace_tree_at_path(checkout, child_hash, parts[1:], replacement_hash)
    )
    return _mktree(
        checkout,
        [
            (mode, obj_type, updated_child if name == part else obj_hash, name)
            for mode, obj_type, obj_hash, name in child_entries
        ],
    )


def _commit_tree_with_traversal_entry(
    checkout: Path,
    *,
    static_prefix: str,
    blob_text: str,
) -> None:
    safe_index_path = f"{static_prefix}/index.html"
    safe_index_bytes = subprocess.run(
        ["git", "show", f"HEAD:{safe_index_path}"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=False,
    ).stdout
    safe_blob_hash = _hash_blob(checkout, safe_index_bytes)
    evil_blob_hash = _hash_blob(checkout, blob_text.encode("utf-8"))
    parent_tree = _mktree(checkout, [("100644", "blob", evil_blob_hash, "evil.py")])
    static_tree = _mktree(
        checkout,
        [
            ("100644", "blob", safe_blob_hash, "index.html"),
            ("040000", "tree", parent_tree, ".."),
        ],
    )
    head_tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    root_tree = _replace_tree_at_path(
        checkout,
        head_tree,
        static_prefix.split("/"),
        static_tree,
    )
    parent_hash = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    commit_hash = subprocess.run(
        ["git", "commit-tree", root_tree, "-p", parent_hash, "-m", "add traversal entry"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=checkout,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-ref", f"refs/heads/{branch}", commit_hash],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )


def test_export_committed_static_files_rejects_git_tree_traversal(
    tmp_path: Path,
) -> None:
    checkout = _init_fake_checkout(
        tmp_path,
        remote_url="https://github.com/hashgraph-online/hol-guard.git",
    )
    static_prefix = "src/codex_plugin_scanner/guard/daemon/static"
    _commit_tree_with_traversal_entry(
        checkout,
        static_prefix=static_prefix,
        blob_text="malicious",
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
    assert not (installed_static.parent / "evil.py").exists()
