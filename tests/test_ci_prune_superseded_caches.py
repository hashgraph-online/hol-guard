"""Tests for scripts/ci/prune_superseded_caches.py."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.ci.prune_superseded_caches import cache_family, main, superseded

ROOT = Path(__file__).resolve().parents[1]


def _entry(entry_id: int, key: str, created: str, ref: str = "refs/heads/main") -> dict[str, object]:
    return {"id": entry_id, "key": key, "ref": ref, "createdAt": created}


def test_only_known_families_are_prunable() -> None:
    assert cache_family("v0-rust-ci-workspace-test-Linux-x64-6d080bc0-7a487ddb") == (
        "v0-rust-ci-workspace-test-Linux-x64-6d080bc0"
    )
    assert cache_family(
        "codeql-overlay-base-database-1-a84155eaf49db831-python-2.27.2-b40649d950597b2d9355572f1f38fae50da0588c-38062182760-1"
    ) == ("codeql-overlay-base-database-1-a84155eaf49db831-python-2.27.2")
    assert cache_family("sccache/c/f/f/cfff0eca148ba9b831cb77d6eab911c1f73550a002843afa8fff28903aa99898") is None
    assert cache_family("setup-uv-2-x86_64-unknown-linux-gnu-ubuntu-abc") is None
    assert cache_family("v0-rust-") is None
    assert cache_family("codeql-overlay-base-database-1-a8-python-2.27.2-not-a-commit") is None


def test_keeps_newest_entry_per_family_on_main() -> None:
    entries = [
        _entry(1, "v0-rust-ci-workspace-test-Linux-x64-6d080bc0-3d4fb91d", "2026-10-10T13:07:00Z"),
        _entry(2, "v0-rust-ci-workspace-test-Linux-x64-6d080bc0-7a487ddb", "2026-10-10T15:00:00Z"),
        _entry(3, "v0-rust-ci-workspace-clippy-Linux-x64-923da8c6-3d4fb91d", "2026-10-10T13:02:00Z"),
        _entry(
            4,
            "codeql-overlay-base-database-1-a8-python-2.27.2-29d2f37b3238374ab59e1de9159c1c6e0c26392a-38060867605-1",
            "2026-10-10T14:53:00Z",
        ),
        _entry(
            5,
            "codeql-overlay-base-database-1-a8-python-2.27.2-644faeac5228a3a46eb4ec203dacdffba56ea3ad-38061151566-1",
            "2026-10-10T14:57:00Z",
        ),
        _entry(
            6,
            "codeql-overlay-base-database-1-a8-python-2.27.2-b40649d950597b2d9355572f1f38fae50da0588c-38062182760-1",
            "2026-10-10T15:10:00Z",
        ),
        _entry(
            7, "release-native-v1-release-x86_64-unknown-linux-musl-Linux-x64-8e2866fd-3d4fb91d", "2026-10-10T12:52:00Z"
        ),
        _entry(
            8, "release-native-v1-release-x86_64-unknown-linux-musl-Linux-x64-8e2866fd-7a487ddb", "2026-10-10T14:50:00Z"
        ),
    ]
    assert superseded(entries) == [1, 4, 5, 7]


def test_never_selects_pull_request_or_unknown_entries() -> None:
    entries = [
        _entry(1, "v0-rust-ci-workspace-test-Linux-x64-6d080bc0-old", "2026-10-09T00:00:00Z", "refs/pull/1/merge"),
        _entry(2, "v0-rust-ci-workspace-test-Linux-x64-6d080bc0-new", "2026-10-10T00:00:00Z"),
        _entry(3, "sccache/a/b/6/ab6f", "2026-10-01T00:00:00Z"),
        _entry(4, "sccache/a/b/6/ab6f", "2026-10-02T00:00:00Z"),
        _entry(5, "node-cache-Linux-x64-npm-old", "2026-10-01T00:00:00Z"),
        _entry(6, "node-cache-Linux-x64-npm-new", "2026-10-02T00:00:00Z"),
        {"id": "7", "key": "v0-rust-x-old", "ref": "refs/heads/main", "createdAt": "2026-10-01T00:00:00Z"},
        {"id": 8, "key": None, "ref": "refs/heads/main", "createdAt": "2026-10-01T00:00:00Z"},
    ]
    assert superseded(entries) == []


def test_same_timestamp_keeps_highest_id() -> None:
    entries = [
        _entry(10, "v0-rust-sonar-Linux-x64-923da8c6-a", "2026-10-10T00:00:00Z"),
        _entry(11, "v0-rust-sonar-Linux-x64-923da8c6-b", "2026-10-10T00:00:00Z"),
    ]
    assert superseded(entries) == [10]


def test_cli_prints_one_id_per_line(tmp_path: Path, capsys) -> None:
    listing = tmp_path / "caches.json"
    listing.write_text(
        json.dumps(
            [
                _entry(1, "v0-rust-sonar-Linux-x64-923da8c6-a", "2026-10-09T00:00:00Z"),
                _entry(2, "v0-rust-sonar-Linux-x64-923da8c6-b", "2026-10-10T00:00:00Z"),
            ]
        )
    )
    assert main([str(listing)]) == 0
    assert capsys.readouterr().out == "1\n"


def test_cli_rejects_non_list(tmp_path: Path) -> None:
    listing = tmp_path / "caches.json"
    listing.write_text("{}")
    assert main([str(listing)]) == 2


def test_workflow_runs_trusted_main_code_with_least_privilege() -> None:
    workflow = yaml.load((ROOT / ".github/workflows/cache-cleanup.yml").read_text(), Loader=yaml.BaseLoader)
    assert workflow["permissions"] == {}
    job = workflow["jobs"]["prune"]
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    trigger = workflow["on"]["workflow_run"]
    assert trigger["branches"] == ["main"]
    assert "github.event.workflow_run.event == 'push'" in job["if"]
