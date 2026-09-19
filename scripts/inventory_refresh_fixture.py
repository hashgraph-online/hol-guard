"""Real inventory refresh with owned synthetic files and an offline HTTP seam.

The producer changes distinct inputs while a real refresh is awaiting its
fixture acknowledgment. Later calls use the actual freshness predicate. This
is not a daemon timer, watcher queue, remote-cloud or scanner-success substitute.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import time
from collections import Counter
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.inventory_refresh_observer import InventoryObserver, detection_identities
from scripts.native_slo_failure import failure_evidence
from scripts.profile_inventory_refresh import fixture

COUNTS = (24, 128, 486)
STAMP = "2026-09-18T00:00:00Z"
RECENT = "2026-09-18T00:01:00Z"
DUE = "2026-09-18T00:30:00Z"
URL = "https://fixture.invalid/api/v1/guard/events"
MUTATIONS = 32


def identity_change(before: Mapping[str, str], after: Mapping[str, str]) -> dict[str, int]:
    shared = before.keys() & after.keys()
    return {
        "changed": sum(before[key] != after[key] for key in shared),
        "unchanged": sum(before[key] == after[key] for key in shared),
        "added": len(after.keys() - before.keys()),
        "removed": len(before.keys() - after.keys()),
    }


def _atomic_write(path: Path, body: bytes) -> None:
    temporary = path.with_name(path.name + ".qualification-pending")
    try:
        with temporary.open("xb") as stream:
            stream.write(body)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def mutate_inputs(context: Any, observer: InventoryObserver) -> list[dict[str, object]]:
    outcomes: list[dict[str, object]] = []
    collection = context.home_dir / ".gemini" / "skills"
    with observer.refresh("overlapping_input_burst"):
        for index in range(MUTATIONS):
            row: dict[str, object] = {"mutation": index, "state": "offered"}
            observer.emit("mutation_offer", mutation=index)
            try:
                if index < 8:
                    path = collection / f"fixture-{index:04d}" / "SKILL.md"
                    before = path.stat()
                    body = path.read_bytes().replace(b"Local notes.", b"Other notes.")
                    if len(body) != before.st_size:
                        raise ValueError("same-size inventory fixture changed size")
                    _atomic_write(path, body)
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                    row.update(
                        operation="same_size_same_mtime",
                        metadata_preserved=path.stat().st_mtime_ns == before.st_mtime_ns,
                    )
                elif index < 16:
                    path = collection / f"fixture-{index + 8:04d}" / "burst-reference.txt"
                    _atomic_write(path, b"New independent local reference.\n")
                    row["operation"] = "added_reference"
                elif index < 24:
                    path = collection / f"fixture-added-{index:04d}" / "SKILL.md"
                    path.parent.mkdir()
                    _atomic_write(path, f"---\nname: fixture-added-{index:04d}\n---\nNew local notes.\n".encode())
                    row["operation"] = "added_skill"
                else:
                    path = collection / f"fixture-{index - 16:04d}" / "SKILL.md"
                    path.unlink()
                    row.update(operation="removed_skill", absent_immediately_after_unlink=not path.exists())
                row["state"] = "completed"
            except Exception as error:
                row.update(state="failed", failure=failure_evidence(error))
            outcomes.append(row)
            observer.emit("mutation_terminal", **row)
    return outcomes


class OfflineInventoryTransport:
    """Use the real HTTP retry client, with explicit synthetic acknowledgments."""

    def __init__(self, observer: InventoryObserver) -> None:
        self.observer = observer
        self.entered = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.requests = 0
        self.block_next_event = True

    def __call__(self, request: Any, *, timeout: float) -> io.BytesIO:
        if self.observer.active is None:
            raise RuntimeError("unowned inventory network request")
        if request.full_url not in {
            URL,
            "https://fixture.invalid/api/guard/aibom/workspaces/inventory-fixture/content-upload",
        }:
            raise RuntimeError("inventory fixture refused unexpected network endpoint")
        if not isinstance(request.data, bytes) or len(request.data) > 7_500_000:
            raise ValueError("inventory fixture HTTP body outside bound")
        body = json.loads(request.data)
        if not isinstance(body, dict):
            raise ValueError("inventory fixture HTTP envelope invalid")
        event_request = request.full_url == URL
        entries = body.get("events" if event_request else "items")
        if not isinstance(entries, list):
            raise ValueError("inventory fixture HTTP entries invalid")
        with self.observer.span("offline_client_wait") as detail:
            self.requests += 1
            detail.update(
                request=self.requests,
                request_kind="inventory_events" if event_request else "content_upload",
                body_bytes=len(request.data),
                body_sha256=hashlib.sha256(request.data).hexdigest(),
                requested_timeout_seconds=timeout,
                synthetic_acknowledgment=True,
                external_network_used=False,
            )
            if event_request and self.block_next_event:
                self.block_next_event = False
                started = time.perf_counter_ns()
                self.entered.set()
                if not self.release.wait(5.0):
                    raise TimeoutError("inventory producer did not release offline transport")
                detail["fixture_wait_ns"] = time.perf_counter_ns() - started
            if event_request:
                payload = {"accepted": len(entries), "rejected": 0}
            else:
                payload = {"storedCount": len(entries), "hashOnlyCount": 0, "failedCount": 0}
            return io.BytesIO(json.dumps(payload).encode())


def _summary(value: Mapping[str, Any]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key in ("synced", "skipped", "snapshots", "accepted", "rejected", "partial", "content_upload_complete"):
        item = value.get(key)
        if type(item) in {bool, int}:
            output[key] = item
    reason = value.get("reason")
    if reason in {
        "not_configured",
        "workspace_changed",
        "guard_events_endpoint_unavailable",
        "recently_synced",
        "snapshot_too_large",
        "content_upload_incomplete",
    }:
        output["reason"] = reason
    output["error_present"] = bool(value.get("error"))
    return output


def _sync(store: Any, context: Any, observer: InventoryObserver, name: str, timestamp: str) -> dict[str, object]:
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    with observer.refresh(name):
        observer.emit("refresh_offer")
        result: dict[str, object]
        try:
            with ExitStack() as lifetime:
                with observer.span("cloud_sync_lock_wait"):
                    lifetime.enter_context(store.hold_cloud_sync_lock())
                with observer.span("sync_if_due"):
                    summary = sync_aibom_snapshots_if_due(
                        store,
                        generated_at=timestamp,
                        auth_context={"sync_url": URL, "access_token": "inventory-fixture-only"},
                        expected_workspace_id="inventory-fixture",
                        home_dir=context.home_dir,
                        workspace_dir=context.workspace_dir,
                    )
            result = {"refresh": name, "state": "returned", **_summary(summary)}
        except Exception as error:
            result = {"refresh": name, "state": "failed", "failure": failure_evidence(error)}
        observer.emit("refresh_terminal", result=result)
        return result


def _consumer(store: Any, context: Any, observer: InventoryObserver, name: str) -> dict[str, object]:
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
    from codex_plugin_scanner.guard.aibom_cli import AibomCliOptions, build_inventory_json_payload
    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.consumer.service import evaluate_detection

    with observer.refresh(name):
        with observer.span("consumer_discovery"):
            detection = GeminiHarnessAdapter().detect(context)
        with observer.span("consumer_evaluation_and_persistence"):
            result = evaluate_detection(detection, store, load_guard_config(store.guard_home, context.workspace_dir))
        with observer.span("public_inventory_projection"):
            inventory = build_inventory_json_payload(
                store,
                context,
                generated_at=STAMP,
                options=AibomCliOptions(cisco_mcp_scan="auto", cisco_skill_scan="auto", cisco_timeout_seconds=30.0),
            )
        rows = store.list_inventory()
        projected = inventory["items"]
        if not isinstance(projected, list):
            raise ValueError("inventory public projection did not return rows")
        return {
            "detected": len(detection.artifacts),
            "stored_rows": len(rows),
            "projected_rows": len(projected),
            "receipts_recorded": result.get("receipts_recorded"),
            "decisions": dict(Counter(str(row.get("policy_action")) for row in result.get("artifacts", []))),
            "first_seen": {
                hashlib.sha256(str(row["artifact_id"]).encode()).hexdigest(): row["first_seen_at"] for row in rows
            },
        }


def run_inventory_witness(root: Path, count: int, ledger: Any) -> dict[str, Any]:
    if type(count) is not int or count not in COUNTS:
        raise ValueError("inventory count outside original matrix")
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.sqlite_profile import SQLiteProfiler
    from codex_plugin_scanner.guard.store import GuardStore

    if any(os.environ.get(name) for name in ("MCP_SCANNER_API_KEY", "MCP_SCANNER_LLM_API_KEY")):
        raise RuntimeError("offline inventory qualification requires remote scanner analyzers to be absent")
    context = fixture(root, count)
    # An empty static configuration exercises the real MCP process boundary
    # without adding an inventory server or executing any configured command.
    if context.workspace_dir is None:
        raise ValueError("inventory fixture requires a workspace")
    (context.workspace_dir / ".mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")
    store = GuardStore(context.guard_home)
    # A private synthetic workspace binding, never real credentials or authority.
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "inventory-fixture"}, STAMP)
    store.__dict__["_guard_sqlite_profiler"] = SQLiteProfiler()
    before = detection_identities((GeminiHarnessAdapter().detect(context),))
    if len(before) != count:
        raise ValueError("inventory fixture cardinality mismatch")
    outcomes: list[dict[str, object]] = []
    report: dict[str, Any] = {"count": count, "passed": False, "refreshes": []}
    observer = InventoryObserver(store, ledger, cell=count)
    with observer:
        report["consumer_before"] = _consumer(store, context, observer, "consumer_before")
        transport = OfflineInventoryTransport(observer)

        def produce() -> None:
            while not transport.cancelled.is_set():
                if transport.entered.wait(0.05):
                    try:
                        outcomes.extend(mutate_inputs(context, observer))
                    finally:
                        transport.release.set()
                    return

        producer = threading.Thread(target=produce, name="inventory-fixture-producer", daemon=True)
        producer.start()
        try:
            with patch.object(runner, "managed_urlopen", transport):
                report["refreshes"].append(_sync(store, context, observer, "initial_overlap", STAMP))
                for number in range(4):
                    report["refreshes"].append(_sync(store, context, observer, f"recent_{number}", RECENT))
                report["refreshes"].append(_sync(store, context, observer, "next_due", DUE))
        finally:
            transport.cancelled.set()
            transport.release.set()
            producer.join(5.0)
            report["producer_stopped"] = not producer.is_alive()
            if producer.is_alive():
                raise RuntimeError("inventory producer containment failed")
        report["consumer_after"] = _consumer(store, context, observer, "consumer_after")
        after = detection_identities((GeminiHarnessAdapter().detect(context),))
        expected = {"changed": 16, "unchanged": count - 24, "added": 8, "removed": 8}
        changes = identity_change(before, after)
        due = observer.discoveries.get("next_due", [])
        due_matches = len(due) == 1 and due[0] == after
        before_seen = report["consumer_before"].pop("first_seen")
        after_seen = report["consumer_after"].pop("first_seen")
        if not isinstance(before_seen, dict) or not isinstance(after_seen, dict):
            raise ValueError("inventory first-seen witness invalid")
        first_seen_preserved = all(after_seen.get(key) == value for key, value in before_seen.items())
        unexpectedly_present = sum(
            (context.home_dir / ".gemini" / "skills" / f"fixture-{index:04d}" / "SKILL.md").exists()
            for index in range(8, 16)
        )
        report.update(
            mutations=outcomes,
            actual_identity_changes=changes,
            expected_identity_changes=expected,
            first_seen_preserved=first_seen_preserved,
            removed_primary_files_reappeared=unexpectedly_present,
            next_due_matches_final_files=due_matches,
            initial_snapshot_precedes_mutations=observer.discoveries.get("initial_overlap") == [before],
            discovery_calls_by_refresh={key: len(value) for key, value in observer.discoveries.items()},
            offline_http_requests=transport.requests,
            sqlite_profile=store.sqlite_profile(),
        )
        report["passed"] = (
            len(outcomes) == MUTATIONS
            and all(row["state"] == "completed" for row in outcomes)
            and all(row.get("metadata_preserved") is True for row in outcomes[:8])
            and all(row.get("absent_immediately_after_unlink") is True for row in outcomes[24:])
            and unexpectedly_present == 0
            and changes == expected
            and due_matches
            and first_seen_preserved
            and report["initial_snapshot_precedes_mutations"]
            and report["producer_stopped"]
            and all(row["state"] == "returned" and not row.get("error_present") for row in report["refreshes"])
        )
    report["observer"] = observer.report()
    report["passed"] = report["passed"] and report["observer"]["spans_conserved"]
    report["qualification_complete"] = False
    report["scope"] = {
        "sync": "actual_sync_if_due_under_production_cloud_sync_lock",
        "input_overlap": "32_distinct_inputs_during_first_offline_acknowledgment_wait",
        "recent_calls": "four_sequential_calls_after_overlapping_file_events",
        "timestamps": "explicit_logical_timestamps_no_wall_clock_freshness_claim",
        "database": "separate_actual_consumer_evaluation_and_public_projection",
        "daemon_timer_or_watcher_delivery_measured": False,
        "live_cloud_measured": False,
        "scanner_success_required_for_full_acceptance": True,
        "observer_overhead_quantified": False,
    }
    return report
