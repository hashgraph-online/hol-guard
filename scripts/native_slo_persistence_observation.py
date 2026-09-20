"""Explicit private-control admission and checks for SQLite/queue diagnostics."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
    from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation

_SCHEMA = "hol-guard.persistence-observation-request.v1"


@dataclass(frozen=True)
class PersistenceObservationSpec:
    """Pass an owned extension identity over the existing private fixture pipe."""

    extension: Path
    extension_sha256: str
    queue_max_pending: int = 65_536

    def __post_init__(self) -> None:
        if (
            not isinstance(self.extension, Path)
            or not self.extension.is_absolute()
            or len(str(self.extension).encode("utf-8")) > 1024
            or not isinstance(self.extension_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.extension_sha256) is None
            or type(self.queue_max_pending) is not int
            or not 1 <= self.queue_max_pending <= 65_536
        ):
            raise ValueError("persistence observation request is outside bounds")

    def to_request(self) -> dict[str, object]:
        return {
            "schema": _SCHEMA,
            "extension": str(self.extension),
            "extension_sha256": self.extension_sha256,
            "queue_max_pending": self.queue_max_pending,
        }

    @classmethod
    def from_request(cls, value: object) -> PersistenceObservationSpec:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema", "extension", "extension_sha256", "queue_max_pending"}
            or value.get("schema") != _SCHEMA
        ):
            raise ValueError("persistence observation request schema is invalid")
        extension, digest, capacity = (
            value.get("extension"),
            value.get("extension_sha256"),
            value.get("queue_max_pending"),
        )
        if not isinstance(extension, str) or not isinstance(digest, str) or type(capacity) is not int:
            raise ValueError("persistence observation request field types are invalid")
        return cls(Path(extension), digest, capacity)

    def create(self, session: Any) -> tuple[EvidenceQueueObservation, SQLiteVFSObservation]:
        from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
        from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation

        queue = EvidenceQueueObservation(max_pending=self.queue_max_pending)
        # Descriptor admission, content hashing and actual SQLite engine loading
        # all happen in the daemon process before any observed hook is offered.
        sqlite = SQLiteVFSObservation(
            database=session.store.path, extension=self.extension, extension_sha256=self.extension_sha256
        )
        return queue, sqlite


def _mapping(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _zero(value: object) -> bool:
    return type(value) is int and value == 0


def persistence_observation_checks(mixed: Mapping[str, object]) -> dict[str, bool]:
    """Require actual admitted observations without upgrading physical IO scope."""
    final = _mapping(mixed.get("queues_and_persistence"))
    receipts = _mapping(final.get("receipts"))
    checks = _mapping(mixed.get("checks"))
    vfs = _mapping(receipts.get("sqlite_vfs_observation"))
    queue = _mapping(receipts.get("writer_queue_observation"))
    cells = _mapping(vfs.get("vfs")).get("cells")
    writer_cells = (
        [_mapping(cell) for cell in cells if _mapping(cell).get("scope") == "writer"] if isinstance(cells, list) else []
    )
    connections = _mapping(vfs.get("attested_connections"))
    admission = _mapping(_mapping(_mapping(queue.get("groups")).get("native_receipt")).get("admission"))
    return {
        "native_receipt_integrity": checks.get("native_receipts_committed") is True
        and checks.get("every_completed_hook_bound") is True
        and _positive(receipts.get("native_receipts"))
        and receipts.get("native_receipts") == receipts.get("committed"),
        "logical_vfs_scope_complete": vfs.get("connection_scope_at_open_complete") is True
        and vfs.get("scope") == "named_vfs_connections_from_selected_store_factory",
        "logical_vfs_lifetime_closed": vfs.get("closed") is True and vfs.get("all_vfs_files_closed") is True,
        "logical_vfs_identity_unchanged": vfs.get("extension_identity_unchanged") is True,
        "writer_and_readback_connections_observed": all(
            _positive(connections.get(scope)) for scope in ("writer", "readback")
        ),
        "logical_writer_writes_observed": any(
            _positive(cell.get("vfs_x_write_success_bytes")) for cell in writer_cells
        ),
        "logical_writer_syncs_observed": any(_positive(cell.get("vfs_x_sync_calls")) for cell in writer_cells),
        "queue_admission_ages_observed": _positive(admission.get("measured")),
        "queue_tracking_complete": queue.get("tracking_complete") is True
        and queue.get("age_coverage_complete") is True
        and queue.get("capacity_covers_admission_and_inflight") is True
        and all(_zero(queue.get(key)) for key in ("tracking_invalidations", "attachment_conflicts")),
        "queue_lifetime_closed": queue.get("attached") is False
        and all(_zero(queue.get(key)) for key in ("tracked_pending", "untracked_pending", "detached_pending")),
        "physical_io_not_inferred": receipts.get("sqlite_fsync_calls") is None
        and receipts.get("sqlite_written_bytes") is None
        and receipts.get("full_persistence_metric_coverage") is False,
    }
