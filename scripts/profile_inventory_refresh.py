#!/usr/bin/env python3
"""Attribute real local inventory refresh/SQL work; no cloud or daemon SLO claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

STAMP = "2026-09-17T00:00:00Z"


def timed(operation, samples):
    rows = []
    result = None
    for sample in range(samples):
        wall, cpu = time.perf_counter(), time.process_time()
        result = operation()
        rows.append({"sample": sample, "wall_s": time.perf_counter() - wall, "cpu_s": time.process_time() - cpu})
    return result, rows


def fixture(root, count):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    home, workspace = root / "home", root / "workspace"
    workspace.mkdir(parents=True)
    for index in range(count):
        skill = home / ".gemini" / "skills" / f"fixture-{index:04d}"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: fixture-{index:04d}\ndescription: Local fixture.\n---\n" + "Local notes.\n" * 85,
            encoding="utf-8",
        )
        (skill / "reference.txt").write_text("Additional local evidence.\n", encoding="utf-8")
    return HarnessContext(home, workspace, root / "guard", home_override_explicit=True)


def root_profile(context, detection, samples):
    from codex_plugin_scanner.guard.inventory_cisco import _skill_scan_roots

    def roots():
        return _skill_scan_roots(harness="gemini", context=context, detection=detection)

    selected, observations = timed(roots, samples)
    counts = Counter()
    original = Path.rglob

    def counted(path, pattern, *args, **kwargs):
        counts["recursive_walks"] += 1
        for item in original(path, pattern, *args, **kwargs):
            counts["matched_documents"] += 1
            yield item

    with patch.object(Path, "rglob", counted):
        assert roots() == selected
    expected = (context.home_dir / ".gemini" / "skills",)
    assert selected == expected
    return {"samples": observations, "separate_walk_witness": dict(counts), "selected_collections": 1}


def detection_witness(context):
    from codex_plugin_scanner.guard import skill_directory_identity as identity
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter

    counts = Counter()
    original = identity._hash_regular_file

    def hashed(*args, **kwargs):
        result = original(*args, **kwargs)
        counts["verified_file_hashes"] += 1
        counts["verified_bytes_hashed"] += result[1]
        return result

    with patch.object(identity, "_hash_regular_file", hashed):
        detection = GeminiHarnessAdapter().detect(context)
    return detection, dict(counts)


def directory_hashes(detection):
    return {
        artifact.artifact_id: artifact.metadata["skillDirectoryIdentity"]["contentHash"]
        for artifact in detection.artifacts
        if "skillDirectoryIdentity" in artifact.metadata
    }


def filesystem_profile(context, count, samples):
    from codex_plugin_scanner.guard import aibom_cli as api
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(context.guard_home)
    store.set_sync_payload("aibom_sync_summary", {"synced": True, "synced_at": STAMP, "snapshots": 1}, STAMP)
    states = []
    previous = None
    selected = context.home_dir / ".gemini" / "skills" / "fixture-0000"
    for state in ("initial", "unchanged", "same_size_same_mtime", "added_reference", "burst_changes", "removed_skill"):
        if state == "same_size_same_mtime":
            path = selected / "SKILL.md"
            metadata = path.stat()
            body = path.read_bytes().replace(b"Local notes.", b"Other notes.")
            assert len(body) == metadata.st_size
            path.write_bytes(body)
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        elif state == "added_reference":
            (selected / "new.txt").write_text("New file.\n", encoding="utf-8")
        elif state == "burst_changes":
            for index in range(32):
                (selected / "new.txt").write_text(f"Last burst value {index}.\n", encoding="utf-8")
        elif state == "removed_skill":
            (selected / "SKILL.md").unlink()
        detection, observations = timed(lambda: GeminiHarnessAdapter().detect(context), samples)
        witnessed, reads = detection_witness(context)
        hashes = directory_hashes(detection)
        assert hashes == directory_hashes(witnessed)
        changed = (
            sum(previous.get(key) != value for key, value in hashes.items()) if previous is not None else len(hashes)
        )
        removed = len(set(previous or ()) - set(hashes))
        if state == "unchanged":
            assert changed == 0
        if state in {"same_size_same_mtime", "added_reference", "burst_changes"}:
            assert changed == 1
        if state == "removed_skill":
            assert removed == 1 and len(hashes) == count - 1
        # This is the actual existing due predicate, not an invented watcher.
        due = api._aibom_sync_is_due(store, generated_at="2026-09-17T00:01:00Z", min_interval_seconds=900)
        assert due is False
        states.append(
            {
                "state": state,
                "skills": len(hashes),
                "changed": changed,
                "removed": removed,
                "due_at_60_seconds": due,
                "samples": observations,
                "separate_hash_witness": reads,
            }
        )
        previous = hashes
    assert api._aibom_sync_is_due(store, generated_at="2026-09-17T00:15:00Z", min_interval_seconds=900)
    return states


def persist_artifacts(store, artifacts, *, related=False, now=STAMP):
    for index, artifact in enumerate(artifacts):
        digest = f"sha256:{index:064x}"
        store.record_inventory_artifact(
            artifact=artifact, artifact_hash=digest, policy_action="allow", changed=False, now=now, approved=True
        )
        if related:
            store.save_artifact_capability(
                harness=artifact.harness,
                artifact_id=artifact.artifact_id,
                capability_snapshot={"filesystem_paths": [artifact.config_path]},
                now=now,
            )
            store.upsert_provenance_cache(artifact_hash=digest, payload={"source_kind": "local"}, now=now)
            store.record_diff(artifact.harness, artifact.artifact_id, ["content"], None, digest, now)
            store.save_snapshot(artifact.harness, artifact.artifact_id, {"artifact_hash": digest}, digest, now)


def statement_witness(operation):
    counts = Counter()
    original = sqlite3.connect

    def connection(*args, **kwargs):
        counts["connections"] += 1
        result = original(*args, **kwargs)

        def statement(sql):
            normalized = " ".join(sql.split()).lower()
            counts[normalized.split(" ", 1)[0]] += 1
            if normalized.startswith("select first_seen_at from artifact_inventory"):
                counts["preliminary_first_seen_selects"] += 1

        result.set_trace_callback(statement)
        return result

    with patch.object(sqlite3, "connect", connection):
        operation()
    return dict(counts)


def sqlite_profile(context, detection, samples, *, advance_timestamps=False):
    from codex_plugin_scanner.guard import aibom_cli as api
    from codex_plugin_scanner.guard.sqlite_profile import SQLiteProfiler
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(context.guard_home)
    artifacts = detection.artifacts
    persist_artifacts(store, artifacts)
    stages = {}
    write_generation = 0
    for name, related in (("inventory_upsert", False), ("five_related_writes_excluding_receipt", True)):
        store.__dict__["_guard_sqlite_profiler"] = SQLiteProfiler()

        def operation(related=related):
            nonlocal write_generation
            write_generation += 1
            now = f"2026-09-17T00:{write_generation:02d}:00Z" if advance_timestamps else STAMP
            return persist_artifacts(store, artifacts, related=related, now=now)

        _result, observations = timed(operation, samples)
        profile = store.sqlite_profile()
        counts = statement_witness(operation)
        stages[name] = {"samples": observations, "sqlite_profile": profile, "separate_statement_witness": counts}
    snapshot = api.inventory_snapshot_from_detection(
        detection, generated_at=STAMP, home_dir=context.home_dir, workspace_dir=context.workspace_dir, cisco_runs=()
    )
    snapshots = (snapshot,)
    for name, operation in (
        ("list_inventory", store.list_inventory),
        ("metadata_hash_join_index", lambda: api._metadata_lookup_from_snapshots(snapshots)),
        (
            "stored_rows_with_metadata_and_redaction",
            lambda: api._artifact_rows_from_store(store, snapshots, context=context, generated_at=STAMP),
        ),
    ):
        store.__dict__["_guard_sqlite_profiler"] = SQLiteProfiler()
        result, observations = timed(operation, samples)
        stages[name] = {"samples": observations, "rows": len(result), "sqlite_profile": store.sqlite_profile()}
    rows = store.list_inventory()
    assert len(rows) == len(artifacts)
    assert all(row["first_seen_at"] == STAMP and row["last_policy_action"] == "allow" for row in rows)
    expected_last_seen = f"2026-09-17T00:{write_generation:02d}:00Z" if advance_timestamps else STAMP
    assert all(row["last_seen_at"] == expected_last_seen for row in rows)
    normalized = [{**row, "config_path": str(Path(row["config_path"]).relative_to(context.home_dir))} for row in rows]
    return {
        "stages": stages,
        "final_inventory_sha256": hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--section", choices=("all", "roots", "filesystem", "sqlite"), default="all")
    parser.add_argument("--counts", type=int, nargs="+", default=[24, 128, 486])
    parser.add_argument("--advance-timestamps", action="store_true", help="Advance last_seen for each SQL write pass")
    args = parser.parse_args()
    if not 1 <= args.samples <= 10 or any(not 1 <= count <= 500 for count in args.counts):
        parser.error("samples must be 1..10 and counts 1..500")
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter

    root = Path(__file__).resolve().parents[1]
    sources = [
        "guard/inventory_cisco.py",
        "guard/store_inventory.py",
        "guard/skill_directory_identity.py",
        "guard/aibom_commands.py",
        "guard/aibom_reporting.py",
        "guard/store_connection_schema.py",
    ]
    rows = []
    with patch.dict(os.environ, {"GUARD_AIBOM_TRUST_ATTESTATION_V2": "0"}):
        for count in args.counts:
            with tempfile.TemporaryDirectory(prefix="hol-inventory-refresh-") as directory:
                context = fixture(Path(directory), count)
                detection = GeminiHarnessAdapter().detect(context)
                row = {"skills": count, "artifacts": len(detection.artifacts)}
                if args.section in {"all", "roots"}:
                    row["cisco_target_discovery"] = root_profile(context, detection, args.samples)
                if args.section in {"all", "sqlite"}:
                    row["sqlite"] = sqlite_profile(
                        context, detection, args.samples, advance_timestamps=args.advance_timestamps
                    )
                if args.section in {"all", "filesystem"}:
                    row["filesystem_refresh"] = filesystem_profile(context, count, args.samples)
                rows.append(row)
    report = {
        "schema": "guard.inventory-refresh-profile.v1",
        "label": args.label,
        "advancing_write_timestamps": args.advance_timestamps,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_sha256": {
            name: hashlib.sha256((root / "src/codex_plugin_scanner" / name).read_bytes()).hexdigest()
            for name in sources
        },
        "python": sys.version,
        "platform": platform.platform(),
        "scope": "real synthetic local files and SQLite; warm process; no daemon/cloud/Cisco engine qualification",
        "workloads": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "workloads": len(rows), "section": args.section}))


if __name__ == "__main__":
    main()
