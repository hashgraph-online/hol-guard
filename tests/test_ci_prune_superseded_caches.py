"""Tests for scripts/ci/prune_superseded_caches.py."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.ci.prune_superseded_caches import (
    cache_family,
    idle_compiler_entries,
    main,
    overlay_status_entries,
    rust_job_name,
    superseded,
    superseded_compiler_generations,
)

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
    assert cache_family(f"macos-hol-guard-runtime-v2-ARM64-macos26-{'a' * 64}-lto-false-cgu-16-{'b' * 64}") == (
        f"macos-hol-guard-runtime-v2-ARM64-macos26-{'a' * 64}-lto-false-cgu-16"
    )
    assert cache_family(
        f"native-offline-previous-v1-X64-ubuntu24-{'a' * 64}-lto-false-cgu-16-{'c' * 40}-{'b' * 64}"
    ) == (f"native-offline-previous-v1-X64-ubuntu24-{'a' * 64}-lto-false-cgu-16")
    assert cache_family(f"shipped-runtime-v2-Linux-X64-ubuntu24-20261012.334.1-{'a' * 64}-{'b' * 64}") == (
        f"shipped-runtime-v2-Linux-X64-ubuntu24-20261012.334.1-{'a' * 64}"
    )


def test_overlay_status_entries_selects_only_main_status_flags() -> None:
    base_key = f"codeql-overlay-base-database-1-a8-python-2.27.2-{'b' * 40}-1-1"
    entries = [
        _entry(1, "codeql-overlay-status-python-2.27.2-runner-140GB", "2026-10-15T18:18:45Z"),
        _entry(2, "codeql-overlay-status-javascript-2.27.2-runner-140GB", "2026-10-15T18:18:45Z"),
        _entry(3, "codeql-overlay-status-python-2.27.2-runner-140GB", "2026-10-15T18:18:45Z", "refs/pull/1/merge"),
        _entry(4, base_key, "2026-10-15T18:18:45Z"),
    ]
    assert overlay_status_entries(entries) == [1, 2]


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
        _entry(
            9,
            f"native-offline-previous-v1-X64-ubuntu24-{'a' * 64}-lto-false-cgu-16-{'1' * 40}-{'b' * 64}",
            "2026-10-10T12:00:00Z",
        ),
        _entry(
            10,
            f"native-offline-previous-v1-X64-ubuntu24-{'a' * 64}-lto-false-cgu-16-{'2' * 40}-{'c' * 64}",
            "2026-10-10T15:00:00Z",
        ),
    ]
    assert superseded(entries) == [1, 4, 5, 7, 9]


def test_drops_compiler_generations_older_than_the_two_newest_saves() -> None:
    entries = [
        _entry(1, "v0-rust-native-wheel-Linux-x64-11111111-aaaaaaaa", "2026-10-10T00:00:00Z"),
        _entry(2, "v0-rust-native-wheel-Linux-x64-22222222-bbbbbbbb", "2026-10-16T00:00:00Z"),
        _entry(3, "v0-rust-native-wheel-Linux-x64-33333333-dddddddd", "2026-10-12T00:00:00Z"),
        _entry(6, "v0-rust-native-wheel-Windows_NT-x64-11111111-aaaaaaaa", "2026-10-10T00:00:00Z"),
        _entry(4, "v0-rust-native-wheel-Linux-x64-22222222-cccccccc", "2026-10-12T00:00:00Z", "refs/pull/9/merge"),
        _entry(5, "setup-uv-2-aaaaaaaa-bbbbbbbb", "2026-10-01T00:00:00Z"),
    ]
    assert rust_job_name("v0-rust-native-wheel-Linux-x64-22222222-bbbbbbbb") == ("v0-rust-native-wheel-Linux-x64")
    assert rust_job_name("setup-uv-2-aaaaaaaa-bbbbbbbb") is None
    assert superseded_compiler_generations(entries) == [1]


def test_late_save_from_an_older_run_does_not_evict_the_other_generation() -> None:
    entries = [
        _entry(1, "v0-rust-native-wheel-Linux-x64-11111111-aaaaaaaa", "2026-10-16T09:00:00Z"),
        _entry(2, "v0-rust-native-wheel-Linux-x64-22222222-bbbbbbbb", "2026-10-16T10:00:00Z"),
        _entry(3, "v0-rust-native-wheel-Linux-x64-33333333-cccccccc", "2026-10-16T08:00:00Z"),
    ]
    assert superseded_compiler_generations(entries) == [3]


def test_two_late_saves_of_one_environment_do_not_evict_the_other() -> None:
    entries = [
        _entry(1, "v0-rust-native-wheel-Linux-x64-11111111-aaaaaaaa", "2026-10-16T10:00:00Z"),
        _entry(2, "v0-rust-native-wheel-Linux-x64-22222222-bbbbbbbb", "2026-10-16T10:05:00Z"),
        _entry(3, "v0-rust-native-wheel-Linux-x64-22222222-cccccccc", "2026-10-16T10:10:00Z"),
        _entry(4, "v0-rust-native-wheel-Linux-x64-33333333-dddddddd", "2026-10-16T08:00:00Z"),
    ]
    assert superseded_compiler_generations(entries) == [4]
    assert superseded(entries) == [2]


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


def test_runtime_archives_keep_each_distinct_build_environment_and_non_main_ref() -> None:
    family = f"runtime-test-archive-v2-X64-ubuntu24-image-{'a' * 64}-lto-false-cgu-16"
    old_key, new_key = f"{family}-{'b' * 64}", f"{family}-{'c' * 64}"
    assert cache_family(old_key) == family
    entries = [
        _entry(1, old_key, "2026-10-16T01:00:00Z"),
        _entry(2, new_key, "2026-10-16T02:00:00Z"),
        _entry(3, old_key.replace("cgu-16", "cgu-8"), "2026-10-16T01:00:00Z"),
        _entry(4, old_key.replace("ubuntu24-image", "ubuntu24-other"), "2026-10-16T01:00:00Z"),
        _entry(5, old_key.replace("a" * 64, "d" * 64), "2026-10-16T01:00:00Z"),
        _entry(6, old_key, "2026-10-16T01:00:00Z", "refs/pull/1/merge"),
        _entry(7, old_key.replace("-v2-", "-v1-"), "2026-10-16T01:00:00Z"),
        _entry(8, old_key.replace("-X64-", "-ARM64-"), "2026-10-16T01:00:00Z"),
    ]
    assert superseded(entries) == [1]
    assert cache_family(old_key.replace("-v2-", "-v3-")) == family.replace("-v2-", "-v3-")
    for malformed in (f"{family}-short", f"{family}-{'b' * 63}", old_key + "\n", old_key.replace("-v2-", "-v4-")):
        assert cache_family(malformed) is None


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


def _object(
    entry_id: int, accessed: str | None, ref: str = "refs/heads/main", version: str | None = "ci"
) -> dict[str, object]:
    entry = _entry(entry_id, f"sccache/a/b/{entry_id}/{entry_id:064x}", "2026-10-08T00:00:00Z", ref)
    if version is not None:
        entry["version"] = version
    if accessed is not None:
        entry["lastAccessedAt"] = accessed
    return entry


def test_compiler_objects_idle_before_newest_read_are_selected() -> None:
    entries = [
        _object(1, "2026-10-11T13:20:00.104384Z"),
        _object(2, "2026-10-11T11:30:00Z"),
        _object(3, "2026-10-11T11:10:00Z"),
        _object(4, "2026-10-11T03:00:00Z"),
        _object(5, "2026-10-11T03:00:00Z", "refs/pull/7/merge"),
        _object(6, None),
        _object(7, "not-a-time"),
        _object(8, "2026-10-11T03:00:00"),
        _entry(9, "v0-rust-sonar-Linux-x64-923da8c6-a", "2026-10-01T00:00:00Z")
        | {"lastAccessedAt": "2026-10-01T00:00:00Z", "version": "ci"},
        _object(10, "2026-10-11T03:00:00Z", version=None),
        _object(11, "2026-10-11T03:00:00Z", version=""),
    ]
    assert idle_compiler_entries(entries) == [3, 4]
    assert idle_compiler_entries(entries, idle_hours=12) == []


def test_quiet_period_keeps_the_last_warm_set() -> None:
    # Nothing has built for days; the newest read anchors the cutoff, not the clock.
    entries = [
        _object(1, "2026-10-01T10:00:00Z"),
        _object(2, "2026-10-01T09:30:00Z"),
        _object(3, "2026-09-30T00:00:00Z"),
    ]
    assert idle_compiler_entries(entries) == [3]
    assert idle_compiler_entries([]) == []


def test_each_compiler_cache_version_keeps_its_own_warm_set() -> None:
    # Routine CI reads its namespace every push; the release namespace was last
    # read hours ago and must still keep the set its newest build used.
    entries = [
        _object(1, "2026-10-11T13:00:00Z", version="ci"),
        _object(2, "2026-10-11T08:00:00Z", version="ci"),
        _object(3, "2026-10-11T04:00:00Z", version="release"),
        _object(4, "2026-10-11T03:30:00Z", version="release"),
        _object(5, "2026-10-10T20:00:00Z", version="release"),
    ]
    assert idle_compiler_entries(entries) == [2, 5]


def test_cli_combines_superseded_and_idle_entries(tmp_path: Path, capsys) -> None:
    listing = tmp_path / "caches.json"
    listing.write_text(
        json.dumps(
            [
                _entry(1, "v0-rust-sonar-Linux-x64-923da8c6-a", "2026-10-09T00:00:00Z"),
                _entry(2, "v0-rust-sonar-Linux-x64-923da8c6-b", "2026-10-10T00:00:00Z"),
                _object(3, "2026-10-11T13:00:00Z"),
                _object(4, "2026-10-11T08:00:00Z"),
            ]
        )
    )
    assert main([str(listing)]) == 0
    assert capsys.readouterr().out == "1\n4\n"
    assert main([str(listing), "--idle-hours", "6"]) == 0
    assert capsys.readouterr().out == "1\n"
    for invalid in ("0", "-1", "nan", "inf"):
        assert main([str(listing), "--idle-hours", invalid]) == 2


def test_workflow_lists_last_access_for_idle_pruning() -> None:
    text = (ROOT / ".github/workflows/cache-cleanup.yml").read_text()
    assert "--limit 5000 --json id,key,ref,createdAt,lastAccessedAt,version" in text


def test_workflow_runs_trusted_main_code_with_least_privilege() -> None:
    workflow = yaml.load((ROOT / ".github/workflows/cache-cleanup.yml").read_text(), Loader=yaml.BaseLoader)
    assert workflow["permissions"] == {}
    job = workflow["jobs"]["prune"]
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    trigger = workflow["on"]["workflow_run"]
    assert trigger["branches"] == ["main"]
    assert "github.event.workflow_run.event == 'push'" in job["if"]
