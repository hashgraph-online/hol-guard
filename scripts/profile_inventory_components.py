#!/usr/bin/env python3
"""Profile local inventory stages and the unchanged atomic cloud batch contract.

Run under performance-measurement.lock. Cisco scanning and cloud HTTP are
explicitly excluded. These are synthetic local components, not end-to-end SLOs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from unittest.mock import patch

STAMP = "2026-09-17T00:00:00Z"


def observe(operation, samples):
    rows = []
    for sample in range(samples):
        wall = time.perf_counter()
        cpu = time.process_time()
        result = operation()
        rows.append(
            {"sample": sample, "wall_seconds": time.perf_counter() - wall, "cpu_seconds": time.process_time() - cpu}
        )
    tracemalloc.start()
    result = operation()
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, {"samples": rows, "separate_tracemalloc_peak_bytes": peak}


def event(snapshot_id, items, summary_bytes):
    return {
        "eventId": f"event-{snapshot_id}",
        "eventType": "agent.inventory_snapshot",
        "idempotencyKey": snapshot_id,
        "occurredAt": STAMP,
        "source": "edge",
        "workspaceId": "fixture-workspace",
        "deviceId": None,
        "payload": {
            "snapshot": {
                "snapshotId": snapshot_id,
                "agentId": "hermes:local",
                "agentType": "hermes",
                "generatedAt": STAMP,
                "items": [
                    {
                        "itemId": f"item-{index}",
                        "itemKind": "skill",
                        "displayName": f"fixture-{index}",
                        "contentHash": f"{index:064x}",
                        "sourceFingerprint": f"{index:064x}",
                        "riskLevel": "info",
                        "securityScore": 100,
                        "driftState": "unchanged",
                        "metadata": {"contentSummary": "x" * summary_bytes, "provenance": "client_unverified"},
                        "capabilityCategories": [],
                        "scannerSources": [],
                    }
                    for index in range(items)
                ],
                "findings": [],
                "drift": [],
                "dockerProofs": [],
                "sources": [],
                "redactionReport": {"rawSecretsIncluded": False, "redactedFields": []},
            }
        },
    }


def profile_batches(samples):
    from codex_plugin_scanner.guard import aibom_cli as api

    rows = []
    for case, event_count, item_count, summary_bytes in (
        ("three_small_snapshots", 3, 24, 1024),
        ("nine_medium_snapshots", 9, 128, 1024),
        ("three_large_atomic_snapshots", 3, 486, 11300),
    ):
        events = [event(f"snapshot-{index}", item_count, summary_bytes) for index in range(event_count)]

        def plan_and_encode(events=events):
            batches, oversized = api._batch_inventory_events(events)
            assert not oversized
            return [api._inventory_events_request_body(batch) for batch in batches]

        bodies, observations = observe(plan_and_encode, samples)
        expected = json.dumps({"events": events}).encode("utf-8")
        serialized_bytes = []
        original = json.dumps

        def counted(*args, _original=original, _serialized_bytes=serialized_bytes, **kwargs):
            encoded = _original(*args, **kwargs)
            _serialized_bytes.append(len(encoded.encode("utf-8")))
            return encoded

        with patch.object(json, "dumps", counted):
            witnessed = plan_and_encode()
        assert witnessed == bodies
        decoded = [row for body in bodies for row in json.loads(body)["events"]]
        assert decoded == events
        assert all(len(body) <= api._AIBOM_MAX_REQUEST_BODY_BYTES for body in bodies)
        rows.append(
            {
                "case": case,
                "events": event_count,
                "items_per_event": item_count,
                "summary_bytes_per_item": summary_bytes,
                "input_sha256": hashlib.sha256(expected).hexdigest(),
                "encoded_bodies_sha256": [hashlib.sha256(body).hexdigest() for body in bodies],
                "body_bytes": [len(body) for body in bodies],
                "json_calls_in_separate_witness": len(serialized_bytes),
                "json_bytes_in_separate_witness": sum(serialized_bytes),
                **observations,
            }
        )
    return rows


def profile_projection(samples):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
    from codex_plugin_scanner.guard.inventory_contract import (
        cloud_inventory_artifacts_from_detection,
        inventory_snapshot_from_detection,
        serialize_inventory_snapshot,
    )

    rows = []
    for count in (24, 128, 486):
        with tempfile.TemporaryDirectory(prefix="hol-inventory-component-") as directory:
            root = Path(directory)
            home = root / "home"
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "AGENTS.md").write_text("# Synthetic local instructions\n", encoding="utf-8")
            for index in range(count):
                skill = home / ".hermes" / "skills" / "fixture" / f"skill-{index}" / "SKILL.md"
                skill.parent.mkdir(parents=True)
                skill.write_text(
                    f"---\nname: skill-{index}\ndescription: Synthetic fixture.\n---\n" + "Local notes.\n" * 85,
                    encoding="utf-8",
                )
            context = HarnessContext(home, workspace, root / "guard", home_override_explicit=True)
            detection, detect_time = observe(lambda context=context: HermesHarnessAdapter().detect(context), samples)
            artifacts, artifact_time = observe(
                lambda detection=detection, home=home, workspace=workspace: cloud_inventory_artifacts_from_detection(
                    detection, home_dir=home, workspace_dir=workspace
                ),
                samples,
            )
            snapshot, snapshot_time = observe(
                lambda detection=detection, home=home, workspace=workspace, artifacts=artifacts: (
                    inventory_snapshot_from_detection(
                        detection,
                        generated_at=STAMP,
                        home_dir=home,
                        workspace_dir=workspace,
                        artifacts=artifacts,
                        cisco_runs=(),
                    )
                ),
                samples,
            )
            wire, serialize_time = observe(lambda snapshot=snapshot: serialize_inventory_snapshot(snapshot), samples)
            encoded = json.dumps(wire).encode("utf-8")
            rows.append(
                {
                    "skill_files": count,
                    "detected_artifacts": len(detection.artifacts),
                    "projected_artifacts": len(artifacts),
                    "snapshot_items": len(snapshot.items),
                    "snapshot_wire_bytes": len(encoded),
                    "detection_and_hashing": detect_time,
                    "cloud_artifact_projection": artifact_time,
                    "snapshot_assembly": snapshot_time,
                    "wire_projection_and_redaction": serialize_time,
                    "cisco": "disabled; no third-party scan measurement",
                    "cloud": "not contacted; no HTTP timing",
                    "sqlite": "not used by these local projection components",
                }
            )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--section", choices=("all", "batch", "projection"), default="all")
    args = parser.parse_args()
    if not 1 <= args.samples <= 100:
        parser.error("samples must be between 1 and 100")
    root = Path(__file__).resolve().parents[1]
    sources = (
        "src/codex_plugin_scanner/guard/aibom_sync.py",
        "src/codex_plugin_scanner/guard/aibom_cli.py",
        "src/codex_plugin_scanner/guard/inventory_contract.py",
        "src/codex_plugin_scanner/guard/adapters/hermes.py",
    )
    report = {
        "schema": "guard.inventory-component-profile.v1",
        "label": args.label,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources},
        "python": sys.version,
        "platform": platform.platform(),
        "scope": (
            "synthetic local components; no daemon, cloud, Cisco scanner, SQLite, or incremental watcher qualification"
        ),
        "batches": profile_batches(args.samples) if args.section != "projection" else [],
        "projection": profile_projection(args.samples) if args.section != "batch" else [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "label": args.label,
                "output": str(args.output),
                "batches": len(report["batches"]),
                "projection": len(report["projection"]),
            }
        )
    )


if __name__ == "__main__":
    main()
