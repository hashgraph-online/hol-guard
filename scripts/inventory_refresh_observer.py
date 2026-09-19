"""Bounded forwarding spans for the inventory qualification process only.

The observer retains stage names, counters and content identities, never file
contents, configuration paths, SQL text, request bodies or scanner messages.
Spans are inclusive and carry parent IDs; their durations must not be summed.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import patch

MAX_EVENTS = 100_000
_OWNERSHIP = threading.Lock()


def _reaped_child_cpu() -> float | None:
    if os.name != "posix":
        return None
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def detection_identities(detections: Any) -> dict[str, str]:
    identities: dict[str, str] = {}
    for detection in detections:
        for artifact in detection.artifacts:
            identity = artifact.metadata.get("skillDirectoryIdentity")
            if not isinstance(identity, dict):
                continue
            digest = identity.get("contentHash")
            if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
                raise ValueError("inventory directory identity unavailable")
            int(digest[7:], 16)
            key = hashlib.sha256(artifact.artifact_id.encode("utf-8")).hexdigest()
            if key in identities:
                raise ValueError("duplicate inventory directory identity")
            identities[key] = digest
    return identities


class InventoryObserver:
    """Forward each original call once while observing explicitly owned threads."""

    def __init__(self, store: Any, ledger: Any, *, cell: int | None = None) -> None:
        self.store = store
        self.ledger = ledger
        self.cell = cell
        self._local = threading.local()
        self._lock = threading.Lock()
        self._lifetime = ExitStack()
        self._sequence = 0
        self._started = time.perf_counter_ns()
        self.discoveries: dict[str, list[dict[str, str]]] = {}
        self.scanners: list[dict[str, object]] = []
        self.calls: dict[str, int] = {}
        self.started_spans = 0
        self.terminal_spans = 0
        self.closed = False

    @property
    def active(self) -> str | None:
        return getattr(self._local, "refresh", None)

    @contextmanager
    def refresh(self, name: str) -> Iterator[None]:
        if self.active is not None:
            raise RuntimeError("inventory refresh ownership already assigned")
        self._local.refresh = name
        try:
            yield
        finally:
            self._local.refresh = None

    def emit(self, kind: str, **fields: Any) -> None:
        with self._lock:
            if self.closed or self._sequence >= MAX_EVENTS:
                raise RuntimeError("inventory observer capacity or lifetime exceeded")
            self._sequence += 1
            self.ledger.write(
                {
                    "sequence": self._sequence,
                    "kind": kind,
                    "cell": self.cell,
                    "refresh": self.active,
                    "at_ns": time.perf_counter_ns() - self._started,
                    **fields,
                }
            )

    @contextmanager
    def span(self, stage: str) -> Iterator[dict[str, object]]:
        if self.active is None:
            raise RuntimeError("inventory span has no refresh owner")
        stack = getattr(self._local, "stack", None)
        if stack is None:
            stack = self._local.stack = []
        with self._lock:
            number = self.calls.get(stage, 0) + 1
            self.calls[stage] = number
        identity = f"{self.active}:{stage}:{number}"
        parent = stack[-1] if stack else None
        stack.append(identity)
        started, cpu = time.perf_counter_ns(), time.thread_time_ns()
        detail: dict[str, object] = {}
        self.emit("span_start", span=identity, parent=parent, stage=stage)
        with self._lock:
            self.started_spans += 1
        state = "completed"
        try:
            yield detail
        except BaseException:
            state = "failed"
            raise
        finally:
            stack.pop()
            self.emit(
                "span_terminal",
                span=identity,
                parent=parent,
                stage=stage,
                state=state,
                wall_ns=time.perf_counter_ns() - started,
                thread_cpu_ns=time.thread_time_ns() - cpu,
                **detail,
            )
            with self._lock:
                self.terminal_spans += 1

    def _forward(self, owner: Any, name: str, stage: str) -> None:
        original = getattr(owner, name)

        def observed(*args: Any, **kwargs: Any) -> Any:
            if self.active is None:
                return original(*args, **kwargs)
            with self.span(stage) as details:
                children_before = _reaped_child_cpu() if stage == "scanner_process" else None
                result = original(*args, **kwargs)
                if stage == "discovery":
                    identities = detection_identities(result)
                    with self._lock:
                        self.discoveries.setdefault(str(self.active), []).append(identities)
                    details["skill_identities"] = len(identities)
                elif stage == "file_hash":
                    size = result[1]
                    if type(size) is not int or size < 0:
                        raise ValueError("inventory file hash byte count invalid")
                    details["bytes_hashed"] = size
                elif stage == "scanner":
                    self._scanner_results(result)
                elif stage == "scanner_process":
                    children_after = _reaped_child_cpu()
                    child_cpu = None
                    if children_before is not None and children_after is not None:
                        child_cpu = max(children_after - children_before, 0.0)
                    details.update(
                        returncode=result.returncode,
                        timed_out=result.timed_out,
                        stdout_bytes=len(result.stdout.encode("utf-8")),
                        stderr_bytes=len(result.stderr.encode("utf-8")),
                        reaped_children_cpu_seconds=child_cpu,
                        child_cpu_scope="process_wide_reaped_children_during_call",
                    )
                return result

        self._lifetime.enter_context(patch.object(owner, name, observed))

    def _scanner_results(self, runs: Any) -> None:
        for run in runs:
            metadata = run.metadata
            if (
                metadata.get("evidenceProvenance") != "client_unverified"
                or metadata.get("scannerResolutionSource") != "local_reported"
                or metadata.get("scannerVerificationRequired") != "guard_cloud"
            ):
                raise ValueError("inventory scanner provenance changed")
            if run.source not in {"cisco-mcp-scanner", "cisco-skill-scanner"} or run.status not in {
                "enabled",
                "skipped",
                "unavailable",
                "failed",
                "timed_out",
            }:
                raise ValueError("inventory scanner outcome outside contract")
            row: dict[str, object] = {
                "source": run.source,
                "status": run.status,
                "findings": len(run.findings),
                "evidence_provenance": "client_unverified",
                "verification_required": "guard_cloud",
            }
            with self._lock:
                self.scanners.append(row)
            self.emit("scanner_terminal", **row)

    def __enter__(self) -> InventoryObserver:
        if not _OWNERSHIP.acquire(blocking=False):
            raise RuntimeError("inventory observer already active")
        self._lifetime.callback(_OWNERSHIP.release)
        try:
            from codex_plugin_scanner.guard import aibom_cli, inventory_cisco, skill_directory_identity
            from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner

            for name, stage in (
                ("detect_all", "discovery"),
                ("run_cisco_inventory_scans", "scanner"),
                ("cloud_inventory_artifacts_from_detection", "artifact_projection"),
                ("inventory_snapshot_from_detection", "snapshot_assembly"),
                ("_metadata_lookup_from_snapshots", "metadata_join"),
                ("_artifact_rows_from_store", "stored_row_projection"),
                ("_batch_inventory_events", "batch_planning"),
                ("_inventory_events_request_body", "wire_encoding"),
            ):
                self._forward(aibom_cli, name, stage)
            self._forward(skill_directory_identity, "_hash_regular_file", "file_hash")
            self._forward(inventory_cisco, "_skill_scan_roots", "scanner_root_selection")
            self._forward(cisco_mcp_scanner, "run_bounded_scanner_process", "scanner_process")
            self._forward(cisco_skill_scanner, "run_bounded_scanner_process", "scanner_process")
            for name, stage in (
                ("list_inventory", "inventory_query"),
                ("list_snapshots", "snapshot_query"),
                ("record_inventory_artifact", "inventory_upsert"),
                ("save_artifact_capability", "capability_upsert"),
                ("upsert_provenance_cache", "provenance_upsert"),
                ("record_diff", "diff_write"),
                ("save_snapshot", "snapshot_write"),
                ("mark_inventory_removed", "inventory_remove"),
                ("add_receipt", "consumer_receipt_write"),
            ):
                self._forward(self.store, name, stage)
            return self
        except BaseException:
            self._lifetime.close()
            raise

    def __exit__(self, *exception: object) -> None:
        self._lifetime.close()
        self.closed = True

    def report(self) -> dict[str, object]:
        with self._lock:
            return {
                "events": self._sequence,
                "calls": dict(self.calls),
                "started_spans": self.started_spans,
                "terminal_spans": self.terminal_spans,
                "spans_conserved": self.started_spans == self.terminal_spans,
                "scanner_outcomes": list(self.scanners),
                "timing": "inclusive_forwarding_observer_thread_cpu_and_wall",
                "observer_overhead_quantified": False,
                "all_wrappers_restored": self.closed,
            }
