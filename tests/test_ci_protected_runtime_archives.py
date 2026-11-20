"""Live trusted sources must survive late cache saves and discovery uncertainty."""

from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from scripts.ci import protected_runtime_archives as protection
from scripts.ci.prune_superseded_caches import deletion_plan, protected_digests, superseded

MAIN = "a" * 40
ACTIVE = "b" * 40
PR = "c" * 40


def manifest():
    return dict(
        schema=protection.SCHEMA,
        complete=True,
        discovery=dict(main_sha=MAIN, sources=[MAIN], runs=[]),
        sources=[dict(source_sha=MAIN, digests=dict(core="a" * 64, command="b" * 64, runtime="c" * 64))],
    )


def archive(entry_id, digest, created, partition="core", environment="env", version="one"):
    prefix = f"{partition}-" if partition != "runtime" else ""
    return dict(
        id=entry_id,
        key=f"runtime-test-archive-v3-{prefix}X64-ubuntu24-{environment}-{digest}",
        ref="refs/heads/main",
        createdAt=created,
        version=version,
        sizeInBytes=1024,
    )


def test_old_source_finishing_late_cannot_displace_current_source():
    current = archive(1, "a" * 64, "2026-10-23T11:43:58Z")
    late_old = archive(2, "d" * 64, "2026-10-23T11:52:00Z")
    obsolete = archive(3, "e" * 64, "2026-10-23T10:00:00Z")
    entries = [current, late_old, obsolete]
    assert superseded(entries) == [1, 3]  # The parent timestamp policy loses current.
    plan = deletion_plan(entries, manifest())
    assert [entry["id"] for entry in plan["selected"]] == [3]
    assert plan["selected"][0]["sizeInBytes"] == 1024
    assert plan["selected"][0]["reasons"] == ["superseded"]
    assert [(entry["id"], entry["reasons"]) for entry in plan["retained_archives"]] == [
        (1, ["protected_current_or_active_source"]),
        (2, ["newest_in_family"]),
    ]
    assert plan["retained_archives"][0]["sizeInBytes"] == 1024


def test_all_cache_versions_and_environments_of_protected_source_survive():
    entries = []
    for environment in ("env1", "env2"):
        for version in ("one", "two"):
            entries.append(
                archive(len(entries) + 1, "a" * 64, "2026-10-23T11:00:00Z", environment=environment, version=version)
            )
        entries.append(archive(len(entries) + 1, "d" * 64, "2026-10-23T12:00:00Z", environment=environment))
    assert deletion_plan(entries, manifest())["selected"] == []


@pytest.mark.parametrize("report", [None, {}, {"complete": False}, {"schema": protection.SCHEMA, "complete": True}])
def test_uncertain_protection_keeps_archives_but_preserves_other_policies(report):
    entries = [archive(1, "a" * 64, "2026-10-23T11:00:00Z"), archive(2, "d" * 64, "2026-10-23T12:00:00Z")]
    entries += [
        dict(id=3, key="v0-rust-job-env-old", ref="refs/heads/main", createdAt="2026-10-23T11:00:00Z"),
        dict(id=4, key="v0-rust-job-env-new", ref="refs/heads/main", createdAt="2026-10-23T12:00:00Z"),
    ]
    plan = deletion_plan(entries, report)
    assert not plan["archive_pruning_enabled"]
    assert [entry["id"] for entry in plan["selected"]] == [3]
    assert [entry["reasons"] for entry in plan["retained_archives"]] == [["discovery_incomplete"]] * 2


def test_unknown_future_archive_formats_are_retained_with_reason():
    entry = archive(1, "a" * 64, "2026-10-23T11:00:00Z")
    entry["key"] = entry["key"].replace("-v3-", "-v4-")
    plan = deletion_plan([entry], manifest())
    assert not plan["selected"]
    assert plan["retained_archives"][0]["reasons"] == ["unknown_key_format"]


def test_partial_source_digest_set_is_not_authoritative():
    report = manifest()
    del report["sources"][0]["digests"]["runtime"]
    assert protected_digests(report) is None


class FakeGitHub:
    repository = "owner/repo"

    def __init__(self):
        self.rows = []

    def api(self, path):
        if path == "repos/owner/repo":
            return dict(id=7, full_name=self.repository, default_branch="main")
        raise AssertionError("Discovery must not look up deleted historical workflows")

    def main_sha(self):
        return MAIN

    def runs(self, status):
        return [row for row in self.rows if row["status"] == status]


def run(sha=ACTIVE, event="push", status="queued"):
    return dict(
        id=42,
        head_sha=sha,
        event=event,
        status=status,
        head_branch="main",
        workflow_id=10,
        path=".github/workflows/ci.yml",
        repository=dict(id=7),
        head_repository=dict(id=7),
    )


def derive(client, sha):
    return dict(source_sha=sha, digests={partition: "a" * 64 for partition in protection.PARTITIONS})


@pytest.mark.parametrize("status", protection.ACTIVE_STATUSES)
def test_current_and_active_trusted_main_sources_are_derived(status):
    client = FakeGitHub()
    client.rows = [run(status=status)]
    seen = []

    def capture(client, sha):
        seen.append(sha)
        return derive(client, sha)

    report = protection.discover(client, capture)
    assert report["complete"]
    assert seen == [MAIN, ACTIVE]
    assert protected_digests(report) == {(partition, "a" * 64) for partition in protection.PARTITIONS}


def test_pr_source_is_never_exported_or_executed():
    client = FakeGitHub()
    client.rows = [run(PR, "pull_request")]
    seen = []
    report = protection.discover(client, lambda client, sha: seen.append(sha) or derive(client, sha))
    assert report["complete"] and seen == [MAIN]


def test_historical_warmer_remains_protected_without_workflow_lookup():
    client = FakeGitHub()
    row = run()
    row["path"] = ".github/workflows/rust-test-cache-warm.yml"
    client.rows = [row]
    report = protection.discover(client, derive)
    assert report["complete"] and report["discovery"]["sources"] == [MAIN, ACTIVE]


def test_fork_push_identity_fails_closed_without_deriving_any_source():
    client = FakeGitHub()
    row = run()
    row["head_repository"] = dict(id=99)
    client.rows = [row]
    seen = []
    report = protection.discover(client, lambda client, sha: seen.append(sha))
    assert not report["complete"] and seen == []


def test_source_failure_disables_archive_pruning():
    def fail(client, sha):
        raise OSError("unavailable source")

    report = protection.discover(FakeGitHub(), fail)
    assert not report["complete"]
    entries = [archive(1, "a" * 64, "2026-10-23T11:00:00Z"), archive(2, "d" * 64, "2026-10-23T12:00:00Z")]
    assert deletion_plan(entries, report)["selected"] == []


@pytest.mark.parametrize("change", ["new_run", "new_main", "api_error"])
def test_sources_changing_after_plan_upload_skip_all_archives_only(change):
    client = FakeGitHub()
    if change == "new_run":
        client.rows = [run()]
    elif change == "new_main":
        client.main_sha = lambda: ACTIVE
    else:

        def fail(path):
            raise protection.DiscoveryError("unavailable")

        client.api = fail
    selected = [archive(1, "d" * 64, "2026-10-23T11:00:00Z"), dict(id=2, key="v0-rust-job-old")]
    result = protection.verify_plan(client, dict(protection=manifest(), selected=selected))
    reason = "source_snapshot_unavailable" if change == "api_error" else "source_snapshot_changed"
    assert result["source_verification"] == reason
    assert result["selected"] == [selected[1]]
    assert result["skipped_archives"] == [dict(selected[0], reasons=[reason])]


def test_unchanged_snapshot_allows_original_deletion_plan_without_exporting_source():
    selected = [archive(1, "d" * 64, "2026-10-23T11:00:00Z")]
    result = protection.verify_plan(FakeGitHub(), dict(protection=manifest(), selected=selected))
    assert result["source_verification"] == "verified"
    assert result["selected"] == selected and result["skipped_archives"] == []


def test_archives_are_deleted_before_older_unrelated_ids_after_source_check():
    selected = [
        dict(id=1, key="v0-rust-old"),
        archive(4, "d" * 64, "2026-10-23T11:00:00Z"),
        dict(id=2, key="sccache/old"),
        archive(3, "e" * 64, "2026-10-23T11:00:00Z"),
    ]
    result = protection.verify_plan(FakeGitHub(), dict(protection=manifest(), selected=selected))
    assert [entry["id"] for entry in result["selected"]] == [3, 4, 1, 2]
    assert result["skipped_archives"] == []


def test_sources_changing_during_hashing_fail_closed():
    client = FakeGitHub()

    def change(client, sha):
        client.rows = [run()]
        return derive(client, sha)

    assert not protection.discover(client, change)["complete"]


def test_run_finishing_during_hashing_keeps_the_protected_superset_authoritative():
    client = FakeGitHub()
    client.rows = [run()]

    def finish(client, sha):
        client.rows = []
        return derive(client, sha)

    report = protection.discover(client, finish)
    assert report["complete"]
    assert report["discovery"]["sources"] == [MAIN, ACTIVE]
    assert [source["source_sha"] for source in report["sources"]] == [MAIN, ACTIVE]


def test_run_finishing_after_plan_upload_does_not_skip_archive_deletions():
    client = FakeGitHub()
    client.rows = [run()]
    saved = protection.discover(client, derive)
    client.rows = []
    selected = [archive(1, "d" * 64, "2026-10-23T11:00:00Z")]
    result = protection.verify_plan(client, dict(protection=saved, selected=selected))
    assert result["source_verification"] == "verified"
    assert result["selected"] == selected and result["skipped_archives"] == []


@pytest.mark.parametrize("change", ["main", "source", "run_id", "run_identity"])
def test_snapshot_coverage_still_rejects_additions_and_identity_changes(change):
    client = FakeGitHub()
    client.rows = [run()]
    saved = protection.trusted_sources(client)
    fresh = protection.trusted_sources(client)
    if change == "main":
        fresh["main_sha"] = ACTIVE
    elif change == "source":
        fresh["sources"].append(PR)
    elif change == "run_id":
        fresh["runs"][0]["id"] += 1
    else:
        fresh["runs"][0]["workflow_id"] += 1
    assert not protection.still_covered(saved, fresh)


def test_paginated_discovery_reads_every_page(monkeypatch):
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    pages = []

    def api(path):
        page = int(parse_qs(urlparse(path).query)["page"][0])
        pages.append(page)
        assert "/actions/runs?" in path
        return dict(total_count=101, workflow_runs=[dict(id=i) for i in (range(1, 101) if page == 1 else [101])])

    monkeypatch.setattr(client, "api", api)
    assert len(client.runs("pending")) == 101
    assert pages == [1, 2]


@pytest.mark.parametrize("second", [[], [dict(id=1)], [dict(id=101), dict(id=102)]])
def test_incomplete_or_duplicate_pagination_disables_protection(monkeypatch, second):
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    monkeypatch.setattr(
        client,
        "api",
        lambda path: dict(
            total_count=101, workflow_runs=[dict(id=i) for i in range(1, 101)] if "page=1" in path else second
        ),
    )
    with pytest.raises(protection.DiscoveryError):
        client.runs("in_progress")


@pytest.mark.parametrize("count", [1000, -1, None])
def test_capped_or_invalid_inventory_is_not_authoritative(monkeypatch, count):
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    monkeypatch.setattr(client, "api", lambda path: dict(total_count=count, workflow_runs=[]))
    with pytest.raises(protection.DiscoveryError):
        client.runs("queued")


def test_changing_page_total_is_not_authoritative(monkeypatch):
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    monkeypatch.setattr(
        client,
        "api",
        lambda path: dict(
            total_count=101 if "page=1" in path else 102,
            workflow_runs=[dict(id=i) for i in range(1, 101)] if "page=1" in path else [dict(id=101)],
        ),
    )
    with pytest.raises(protection.DiscoveryError):
        client.runs("queued")


def test_run_api_failure_prevents_source_execution():
    client = FakeGitHub()
    seen = []

    def fail(status):
        raise protection.DiscoveryError("unavailable")

    client.runs = fail
    report = protection.discover(client, lambda client, sha: seen.append(sha))
    assert not report["complete"] and seen == []


def test_wrong_fetched_commit_prevents_archive_and_source_execution():
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    commands = []

    def command(arguments, **kwargs):
        commands.append(arguments)
        return ACTIVE.encode() if "rev-parse" in arguments else b""

    client.command = command
    with pytest.raises(protection.DiscoveryError, match="source_commit_mismatch"):
        protection.source_digests(client, MAIN)
    assert len(commands) == 3 and all(command[0] == "git" for command in commands)


def test_verified_export_runs_only_trust_stage_and_three_fingerprints():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as contents:
        member = tarfile.TarInfo("tracked.txt")
        member.size = 1
        contents.addfile(member, io.BytesIO(b"x"))
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    commands, source_paths = [], []

    def command(arguments, **kwargs):
        commands.append(arguments)
        if "rev-parse" in arguments:
            return MAIN.encode()
        if "archive" in arguments:
            kwargs["output"].write(data.getvalue())
        if arguments[0] != "git":
            source = kwargs["cwd"]
            source_paths.append(source)
            assert (source / "tracked.txt").read_bytes() == b"x"
            return b"digest=" + b"a" * 64
        return b""

    client.command = command
    result = protection.source_digests(client, MAIN)
    assert result == dict(source_sha=MAIN, digests={partition: "a" * 64 for partition in protection.PARTITIONS})
    assert commands[4][1:] == ["scripts/refresh_extension_artifacts.py", "--trust-only"]
    assert [command[1:] for command in commands[5:]] == [
        ["-m", "scripts.ci.rust_test_archive_inputs", "--partition", partition] for partition in protection.PARTITIONS
    ]
    assert len(commands) == 8 and all(not source.exists() for source in source_paths)


def test_unsafe_source_archive_is_rejected_before_any_code_runs():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as contents:
        member = tarfile.TarInfo("checkout/../../escape")
        member.size = 1
        contents.addfile(member, io.BytesIO(b"x"))
    client = protection.GitHub("owner/repo", time.monotonic() + 60)
    commands = []

    def command(arguments, **kwargs):
        commands.append(arguments)
        if "rev-parse" in arguments:
            return MAIN.encode()
        if "archive" in arguments:
            kwargs["output"].write(data.getvalue())
        return b""

    client.command = command
    with pytest.raises(protection.DiscoveryError, match="unsafe_source_archive"):
        protection.source_digests(client, MAIN)
    assert len(commands) == 4 and all(command[0] == "git" for command in commands)


def test_workflow_persists_structured_evidence_before_any_deletion():
    root = Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / ".github/workflows/cache-cleanup.yml").read_text())["jobs"]["prune"]["steps"]
    planning = next(
        i for i, step in enumerate(steps) if step.get("name") == "Plan superseded main-branch cache cleanup"
    )
    upload = next(
        i for i, step in enumerate(steps) if step.get("name") == "Retain the cleanup plan before deleting any cache"
    )
    deletion = next(i for i, step in enumerate(steps) if step.get("name") == "Delete planned main-branch caches")
    assert planning < upload < deletion
    assert steps[upload]["with"]["if-no-files-found"] == "error"
    assert "continue-on-error" not in steps[upload] and "if" not in steps[deletion]
    assert "sizeInBytes" in steps[planning]["run"] and "--report" in steps[planning]["run"]
    assert "protected-archives.json" in steps[upload]["with"]["path"]
    command = steps[deletion]["run"]
    assert command.index("--verify-plan") < command.index("skipped_archives") < command.index("gh cache delete")
    final = next(step for step in steps if step.get("name") == "Retain final source verification")
    assert "always()" in final["if"] and final["with"]["if-no-files-found"] == "error"
