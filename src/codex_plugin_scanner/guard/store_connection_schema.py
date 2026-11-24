"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, ClassVar, cast
from uuid import uuid4

from . import (
    store_connection_scope,
    store_native_decision_receipts,
    store_review_event_outbox_schema,
    store_storage_gate,
)
from .advisory_lock_handoff import hold_advisory_file_lock
from .cloud_sync_busy import GuardCloudSyncBusyError
from .fork_safety import forget_in_child
from .mcp.policy_store import ensure_mcp_policy_request_schema
from .sqlite_connection_cache import close_idle_store_connections, open_store_connection, release_store_connection
from .sqlite_deadline_connection import DeadlineConnection
from .sqlite_errors import sqlite_error_is_fatal, sqlite_error_is_io
from .sqlite_profile import (
    SQLiteMigrationGateReport,
    SQLiteProfiler,
    SQLiteProfileSnapshot,
    sqlite_error_is_busy_locked,
)
from .sqlite_quarantine_forensics import (
    quarantine_file_stats,
    update_quarantine_forensics_outcome,
    write_quarantine_forensics,
)
from .sqlite_recovery import (
    restore_readable_sqlite_store,
    salvage_quarantined_state,
    sqlite_store_probe_detail,
)
from .sqlite_tuning import sqlite_operation_deadline_monotonic
from .store_base import *

# ruff: noqa: F403,F405
from .store_base_schema import base_schema_statements
from .store_bash_operation_schema import (
    BASH_INVOCATION_MIGRATION_VERSION,
    BASH_OPERATION_MIGRATION_VERSION,
    BASH_REVIEW_MIGRATION_VERSION,
    ensure_bash_operation_schema,
)
from .store_command_activity_api_schema import ensure_command_activity_api_schema
from .store_command_activity_display_schema import (
    COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,
    ensure_command_activity_display_schema,
)
from .store_command_activity_health_schema import ensure_command_activity_health_schema
from .store_command_activity_maintenance_schema import ensure_command_activity_maintenance_schema
from .store_command_activity_schema import ensure_command_activity_schema
from .store_command_shadow_schema import ensure_command_shadow_schema
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_local_cli_schema import ensure_local_cli_schema, local_cli_schema_is_current
from .store_receipt_rollup_schema import request_receipt_rollup_rebuild
from .store_resume import ensure_resume_schema
from .store_review_event_outbox_schema import ensure_review_event_outbox_schema
from .store_schema_columns import (
    APPROVAL_COLUMNS,
    ATTACHMENT_COLUMNS,
    LOCAL_ONCE_COLUMNS,
    LOCAL_ONCE_INDEX_STATEMENT,
    POLICY_COLUMNS,
    POLICY_INDEX_STATEMENTS,
    RECEIPT_COLUMNS,
    ensure_columns,
)
from .store_secret_policy_integrity import _POLICY_INTEGRITY_LOOKUP_UNSET
from .store_storage_maintenance import (
    STORAGE_MAINTENANCE_MIGRATION_VERSION,
    STORAGE_QUERY_INDEX_MIGRATION_VERSION,
    storage_maintenance_schema_statements,
)
from .store_watch_only_approval_schema import WATCH_ONLY_APPROVAL_MIGRATION_VERSION, ensure_watch_only_approval_schema
from .store_workflow_capabilities_schema import (
    WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION,
    ensure_workflow_capability_schema,
)
from .store_workspace_assessment_schema import (
    WORKSPACE_ASSESSMENT_MIGRATION_VERSION,
    WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION,
    ensure_workspace_assessment_schema,
    ensure_workspace_fix_proposal_schema,
)

if TYPE_CHECKING:
    from .store import GuardStore


def _facade_store_attr(name: str, fallback: object) -> object:
    store_module = sys.modules.get("codex_plugin_scanner.guard.store")
    if store_module is None:
        return fallback
    return getattr(store_module, name, fallback)


def _backfill_approval_queue_columns_compat(connection: sqlite3.Connection) -> None:
    backfill = _facade_store_attr("backfill_approval_queue_columns", backfill_approval_queue_columns)
    if not callable(backfill):
        backfill_approval_queue_columns(connection)
        return
    backfill(connection)


def _slow_query_threshold_ms_compat() -> int:
    value = _facade_store_attr("_SLOW_QUERY_THRESHOLD_MS", _SLOW_QUERY_THRESHOLD_MS)
    return value if isinstance(value, int) and not isinstance(value, bool) else _SLOW_QUERY_THRESHOLD_MS


def _sqlite_lock_retry_delay_seconds_compat() -> float:
    value = _facade_store_attr("_SQLITE_LOCK_RETRY_DELAY_SECONDS", _SQLITE_LOCK_RETRY_DELAY_SECONDS)
    return (
        value if isinstance(value, (int, float)) and not isinstance(value, bool) else _SQLITE_LOCK_RETRY_DELAY_SECONDS
    )


def _sleep_compat(seconds: float) -> None:
    time_module = _facade_store_attr("time", time)
    sleep = getattr(time_module, "sleep", time.sleep)
    sleep(seconds)


_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION = 16
_REQUIRED_SCHEMA_MIGRATION_VERSIONS = (  # Keep retired-index databases on the path that reaps the index.
    *range(2, STORAGE_QUERY_INDEX_MIGRATION_VERSION + 1),
    WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION,
    WATCH_ONLY_APPROVAL_MIGRATION_VERSION,
    store_review_event_outbox_schema.REVIEW_EVENT_OUTBOX_MIGRATION_VERSION,
    COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,
    *store_native_decision_receipts.native_decision_receipt_migration_versions(),
    BASH_OPERATION_MIGRATION_VERSION,
    BASH_REVIEW_MIGRATION_VERSION,
    BASH_INVOCATION_MIGRATION_VERSION,
    WORKSPACE_ASSESSMENT_MIGRATION_VERSION,
    WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION,
)


@dataclass
class _SchemaInitializationState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    references: int = 0
    last_run_succeeded: bool = False


class StoreConnectionSchemaMixin:
    _sqlite_profiler_init_lock = threading.Lock()
    _schema_initialization_locks_guard: ClassVar[threading.Lock] = threading.Lock()
    _schema_initialization_states: ClassVar[dict[str, _SchemaInitializationState]] = {}
    _startup_prefetched_policy_integrity_secret_material: object | tuple[bytes | None, str | None] = (
        _POLICY_INTEGRITY_LOOKUP_UNSET
    )
    _startup_prefetched_policy_integrity_trusted_state: object | dict[str, object] | None = (
        _POLICY_INTEGRITY_LOOKUP_UNSET
    )
    _startup_prefetched_policy_integrity_repair_failed = False
    _storage_recovery_local: ClassVar[threading.local] = threading.local()
    _policy_integrity_generation_lock_local: ClassVar[threading.local] = threading.local()
    _last_sqlite_recovery = "skipped"
    _last_sqlite_recovery_details: dict[str, bool] | None = None

    def _current_thread_owns_storage_recovery(self) -> bool:
        return getattr(self._storage_recovery_local, "owner", None) == id(self)

    @staticmethod
    def _is_fatal_sqlite_error(error: BaseException) -> bool:
        return sqlite_error_is_fatal(error)

    @contextmanager
    def _hold_storage_gate(self, *, exclusive: bool) -> Iterator[None]:
        with store_storage_gate.hold_storage_gate(self.guard_home, exclusive=exclusive):
            yield

    @contextmanager
    def _try_hold_storage_gate(self, *, exclusive: bool) -> Iterator[bool]:
        """Attempt the storage gate once without blocking; yields the result.

        Callers that must never stall on storage (the runtime heartbeat) use
        this to fail fast and retry on their own cadence.
        """

        with store_storage_gate.try_hold_storage_gate(self.guard_home, exclusive=exclusive) as held:
            yield held

    def _store_is_proven_unusable(self, error: BaseException) -> bool:
        detail = sqlite_store_probe_detail(
            path=self.path,
            guard_home=self.guard_home,
            error=error,
            fatal_error=self._is_fatal_sqlite_error(error),
        )
        self._storage_recovery_local.last_probe_detail = detail
        return detail.proven_unusable

    def _recover_fatal_sqlite_store(
        self,
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        self._last_sqlite_recovery = "skipped"
        self._last_sqlite_recovery_details = None
        is_io_error = sqlite_error_is_io(error)
        if (
            not isinstance(error, sqlite3.DatabaseError)
            or (not self._is_fatal_sqlite_error(error) and not is_io_error)
            or self._current_thread_owns_storage_recovery()
            or self.path.is_symlink()
        ):
            return False
        if failed_identity is None:
            try:
                failed_stat = self.path.stat()
                failed_identity = failed_stat.st_dev, failed_stat.st_ino
            except OSError:
                failed_identity = None
        with self._hold_storage_gate(exclusive=True):
            # Kept connections still hold the failed file open.
            close_idle_store_connections()
            # Another process may already have replaced the failed store.
            try:
                current_stat = self.path.stat()
                current_identity = current_stat.st_dev, current_stat.st_ino
            except OSError:
                current_identity = None
            if current_identity != failed_identity:
                self._last_sqlite_recovery = "replaced"
                return True

            if not self._store_is_proven_unusable(error):
                self._storage_recovery_local.last_probe_detail = None
                return False

            # The decision above already ran the probe; reuse its detail for
            # forensics so recovery holds the exclusive gate for one probe
            # sequence, not two. A monkeypatched decision leaves this None.
            probe_detail = getattr(self._storage_recovery_local, "last_probe_detail", None)
            self._storage_recovery_local.last_probe_detail = None
            quarantined_at = datetime.now(timezone.utc)
            stamp = quarantined_at.strftime("%Y%m%dT%H%M%S%fZ")
            quarantine_id = f"{stamp}-{uuid4().hex[:8]}"
            quarantined = self.guard_home / f"guard.db.corrupt-{quarantine_id}"
            try:
                write_quarantine_forensics(
                    guard_home=self.guard_home,
                    quarantine_id=quarantine_id,
                    quarantined_at=quarantined_at,
                    error=error,
                    probe=probe_detail,
                    files=quarantine_file_stats(self.path),
                    store_path=self.path,
                )
            except Exception as forensics_error:
                _store_logger.warning(
                    "Guard could not record quarantine forensics %s: %s",
                    quarantine_id,
                    forensics_error,
                )
            for suffix in ("", "-wal", "-shm"):
                source = Path(f"{self.path}{suffix}")
                if not source.exists() or source.is_symlink():
                    continue
                source.replace(self.guard_home / f"{quarantined.name}{suffix}")
            _store_logger.error(
                "Guard quarantined an unusable SQLite store after a fatal storage error (quarantine %s): %s",
                quarantine_id,
                type(error).__name__,
            )
            self._storage_recovery_local.owner = id(self)
            try:
                if restore_readable_sqlite_store(destination=self.path, quarantined=quarantined):
                    self._last_sqlite_recovery = "restored"
                    _store_logger.error(
                        "Guard restored the quarantined SQLite store %s after it still opened cleanly.",
                        quarantine_id,
                    )
                else:
                    self._initialize_schema()
                    cloud_restored, cli_restored = salvage_quarantined_state(source=quarantined, destination=self.path)
                    # These independent stores recover atomically within their own
                    # authority boundary; a CLI failure must not discard Review.
                    self._last_sqlite_recovery_details = {"cloud_review": cloud_restored, "local_cli": cli_restored}
                    if cloud_restored or cli_restored:
                        self._last_sqlite_recovery = "reinitialized_salvaged"
                    else:
                        self._last_sqlite_recovery = "reinitialized"
            finally:
                self._storage_recovery_local.owner = None
            try:
                update_quarantine_forensics_outcome(
                    self.guard_home,
                    quarantine_id,
                    outcome=self._last_sqlite_recovery,
                    salvage=self._last_sqlite_recovery_details,
                )
            except Exception as forensics_error:
                _store_logger.warning(
                    "Guard could not update quarantine forensics %s: %s",
                    quarantine_id,
                    forensics_error,
                )
            return True

    def _sqlite_profiler(self) -> SQLiteProfiler:
        profiler = self.__dict__.get("_guard_sqlite_profiler")
        if not isinstance(profiler, SQLiteProfiler):
            with self._sqlite_profiler_init_lock:
                profiler = self.__dict__.get("_guard_sqlite_profiler")
                if not isinstance(profiler, SQLiteProfiler):
                    profiler = SQLiteProfiler()
                    self.__dict__["_guard_sqlite_profiler"] = profiler
        return profiler

    def sqlite_profile(self) -> SQLiteProfileSnapshot:
        return self._sqlite_profiler().snapshot()

    def sqlite_migration_gate_report(
        self,
        *,
        end_to_end_p95_ms: float | None = None,
    ) -> SQLiteMigrationGateReport:
        return self._sqlite_profiler().migration_gate_report(end_to_end_p95_ms=end_to_end_p95_ms)

    @contextmanager
    def connection_scope(self) -> Iterator[None]:
        """Share a connection for one operation, preserving method transactions."""
        with store_connection_scope.connection_scope(cast("GuardStore", self)):
            yield

    @contextmanager
    def _connect(self, *, connection_only: bool = False) -> Iterator[sqlite3.Connection]:
        if store_connection_scope.owns_scope(cast("GuardStore", self)):
            with store_connection_scope.scoped_connection(cast("GuardStore", self)) as connection:
                yield connection
            return
        if self._current_thread_owns_storage_recovery():
            with self._connect_once() as connection:
                yield connection
            return
        yielded = False
        fatal_error: sqlite3.DatabaseError | None = None
        failed_identity: tuple[int, int] | None = None
        with self._hold_storage_gate(exclusive=False):
            try:
                opener = (
                    store_connection_scope.open_connection(cast("GuardStore", self))
                    if connection_only
                    else self._connect_once()
                )
                with opener as connection:
                    yielded = True
                    yield connection
                return
            except sqlite3.DatabaseError as error:
                fatal_error = error
                try:
                    failed_stat = self.path.stat()
                    failed_identity = failed_stat.st_dev, failed_stat.st_ino
                except OSError:
                    failed_identity = None
                if yielded:
                    error.guard_failed_sqlite_identity = failed_identity
        if fatal_error is None:
            return
        try:
            recovered = self._recover_fatal_sqlite_store(fatal_error, failed_identity=failed_identity)
        except Exception as recovery_error:
            raise recovery_error from fatal_error
        if yielded:
            # The caller already ran SQL on the failed connection, so this
            # operation still raises. Recovery makes the next connect usable.
            raise fatal_error
        if not recovered and not sqlite_error_is_busy_locked(fatal_error):
            raise fatal_error
        opener = (
            store_connection_scope.open_connection(cast("GuardStore", self))
            if connection_only
            else self._connect_once()
        )
        with self._hold_storage_gate(exclusive=False), opener as connection:
            yield connection

    @contextmanager
    def _connect_once(self) -> Iterator[sqlite3.Connection]:
        connect_timeout_seconds = sqlite_connect_timeout_seconds()
        if connect_timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
        profiler = self._sqlite_profiler()
        connect_started = time.monotonic()
        try:
            connection, cache_key = open_store_connection(
                self.path,
                timeout=connect_timeout_seconds,
                factory=sqlite3.Connection if sqlite_operation_deadline_monotonic() is None else DeadlineConnection,
            )
        except sqlite3.OperationalError as error:
            profiler.record_connect((time.monotonic() - connect_started) * 1000)
            if sqlite_error_is_busy_locked(error):
                profiler.record_busy_locked()
            raise
        profiler.record_connect((time.monotonic() - connect_started) * 1000)
        connection.row_factory = sqlite3.Row
        start = time.monotonic()
        notification: dict[str, object] | None = None
        completed = False
        try:
            connection.execute(f"pragma busy_timeout={int(connect_timeout_seconds * 1000)}")
            # WAL can use synchronous=NORMAL; rollback-journal and schema-init stay FULL.
            journal_mode_row = connection.execute("pragma journal_mode").fetchone()
            if journal_mode_row is not None and str(journal_mode_row[0]).lower() == "wal":
                connection.execute("pragma synchronous=NORMAL")
            # Enlarge the page cache and mmap window so multi-GB stores don't
            # thrash the default 2 MiB cache.
            connection.execute(f"pragma cache_size=-{SQLITE_CACHE_SIZE_KIB}")
            connection.execute(f"pragma mmap_size={SQLITE_MMAP_SIZE_BYTES}")
            initial_changes = connection.total_changes
            yield connection
            store_review_event_outbox_schema.finalize_review_event_payload_hashes(connection)
            outbox_generation = store_review_event_outbox_schema.commit_review_event_transaction(
                connection, initial_changes, profiler.record_commit
            )
            notification = self._take_policy_integrity_state_notification(connection)
            completed = True
        except sqlite3.OperationalError as error:
            if sqlite_error_is_busy_locked(error):
                profiler.record_busy_locked()
            raise
        finally:
            profiler.record_transaction((time.monotonic() - start) * 1000)
            if notification is None:
                # A failed transaction must drop the queued notice. Leaving it
                # keyed by id(connection) lets a later connection publish it.
                self._take_policy_integrity_state_notification(connection)
            release_store_connection(connection, cache_key, reusable=completed)
            elapsed_ms = (time.monotonic() - start) * 1000
            self._repair_store_permissions()
            if elapsed_ms >= _slow_query_threshold_ms_compat():
                log = _store_logger.warning if _should_warn_on_slow_store_transactions() else _store_logger.debug
                log(
                    "Guard store slow transaction (%.0fms); consider indexing hot query paths.",
                    elapsed_ms,
                )
        store_review_event_outbox_schema.notify_review_event_wake(self.path, outbox_generation)
        if notification is not None:
            self._publish_policy_integrity_state_notification(notification)

    @contextmanager
    def _connection_transaction(self, connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        with store_connection_scope.transaction(cast("GuardStore", self), connection) as method_connection:
            yield method_connection

    @contextmanager
    def hold_oauth_refresh_lock(
        self,
        *,
        timeout_seconds: float = _OAUTH_REFRESH_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "oauth-refresh.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_OAUTH_REFRESH_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard OAuth refresh lock.",
        ):
            yield

    @contextmanager
    def hold_cloud_sync_lock(
        self,
        *,
        timeout_seconds: float = _CLOUD_SYNC_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "cloud-sync.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_CLOUD_SYNC_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard Cloud sync lock.",
            timeout_error=GuardCloudSyncBusyError,
        ):
            yield

    @contextmanager
    def hold_aibom_items_lock(
        self,
        *,
        timeout_seconds: float = _CLOUD_SYNC_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "aibom-items.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_CLOUD_SYNC_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard AIBOM items lock.",
        ):
            yield

    @contextmanager
    def hold_oauth_credential_lock(
        self,
        *,
        timeout_seconds: float = _OAUTH_CREDENTIAL_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "oauth-credentials.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_OAUTH_CREDENTIAL_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard OAuth credential lock.",
        ):
            yield

    @contextmanager
    def hold_policy_integrity_generation_lock(
        self, *, timeout_seconds: float = _POLICY_INTEGRITY_GENERATION_LOCK_TIMEOUT_SECONDS
    ) -> Iterator[None]:
        """Serialize one policy integrity generation advance against the rest.

        The advance reads the trusted control state, marks the next generation
        pending and signs the rows. Those writes no longer share a single SQLite
        transaction, so without this lock a second advance can read the same
        generation and stamp its pending record over a finalized one, leaving
        saved decisions signed above the generation the store trusts.

        Acquire this lock before opening a store connection. A connection
        scope shares a connection without a transaction. Advancing under that
        scope would race the generation writer and invert the lock order.
        """

        if store_connection_scope.owns_scope(cast("GuardStore", self)):
            raise RuntimeError("Guard policy integrity generation cannot advance inside an open connection scope.")
        with suppress(OSError):
            self.guard_home.mkdir(mode=_GUARD_STORE_PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        lock_path = self.guard_home / "policy-integrity-generation.lock"
        held = getattr(self._policy_integrity_generation_lock_local, "held", None)
        if held is None:
            held = set()
            self._policy_integrity_generation_lock_local.held = held
        key = str(lock_path)
        if key in held:
            # One advance reaches several routes that each take the lock; flock
            # would not block this thread anyway, so re-entry is explicit.
            yield
            return
        with self._hold_advisory_file_lock(
            path=lock_path,
            timeout_seconds=timeout_seconds,
            poll_seconds=_POLICY_INTEGRITY_GENERATION_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for the Guard policy integrity generation lock.",
        ):
            held.add(key)
            try:
                yield
            finally:
                held.discard(key)

    @contextmanager
    def hold_workflow_capability_authority_lock(self) -> Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "workflow-capability-authority.lock",
            timeout_seconds=30.0,
            poll_seconds=0.05,
            timeout_message="Timed out waiting for the workflow capability authority lock.",
        ):
            yield

    @contextmanager
    def _hold_advisory_file_lock(
        self,
        *,
        path: Path,
        timeout_seconds: float,
        poll_seconds: float,
        timeout_message: str,
        timeout_error: type[TimeoutError] = TimeoutError,
    ) -> Iterator[None]:
        with hold_advisory_file_lock(
            path=path,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
            timeout_message=timeout_message,
            timeout_error=timeout_error,
        ):
            yield

    def cloud_sync_in_progress(self) -> bool:
        lock_path = self.guard_home / "cloud-sync.lock"
        with lock_path.open("a+b") as handle:
            try:
                # This is an advisory probe, not a reservation: callers must still
                # acquire hold_cloud_sync_lock() for the actual sync critical section.
                _acquire_advisory_file_lock(handle)
            except BlockingIOError:
                return True
            try:
                return False
            finally:
                with suppress(OSError):
                    _release_advisory_file_lock(handle)

    def _initialize_serialized(self) -> None:
        try:
            self._initialize_serialized_once()
        except sqlite3.DatabaseError as error:
            schema_current = self._schema_is_current()
            fatal = self._is_fatal_sqlite_error(error) or sqlite_error_is_io(error)
            # Recovery declining after a transient means the store is healthy.
            # Re-raise only when the schema is not already current.
            if (fatal or not schema_current) and not self._recover_fatal_sqlite_store(error) and not schema_current:
                raise
            self._initialize_policy_integrity()

    def _initialize_serialized_once(self) -> None:
        daemon_managed = getattr(self, "_daemon_managed_schema", False)
        if daemon_managed and self._schema_is_current():
            self._initialize_policy_integrity()
            return
        timeout_seconds = sqlite_connect_timeout_seconds()
        deadline = time.monotonic() + timeout_seconds
        path_key = str(self.path.absolute())
        with self._schema_initialization_locks_guard:
            state = self._schema_initialization_states.setdefault(path_key, _SchemaInitializationState())
            state.references += 1
        process_contended = not state.lock.acquire(blocking=False)
        acquired = not process_contended or state.lock.acquire(timeout=timeout_seconds)
        if not acquired:
            with self._schema_initialization_locks_guard:
                state.references -= 1
                if state.references == 0:
                    del self._schema_initialization_states[path_key]
            raise TimeoutError("Timed out waiting for the Guard schema migration lock.")
        schema_ready = False
        try:
            if process_contended and state.last_run_succeeded and self._schema_is_current():
                schema_ready = True
            else:
                state.last_run_succeeded = False
                remaining_seconds = max(0.0, deadline - time.monotonic())
                with self._hold_advisory_file_lock(
                    path=self.guard_home / "schema-migration.lock",
                    timeout_seconds=remaining_seconds,
                    poll_seconds=min(0.05, max(remaining_seconds, 0.001)),
                    timeout_message="Timed out waiting for the Guard schema migration lock.",
                ):
                    if daemon_managed and self._schema_is_current():
                        schema_ready = True
                    else:
                        self._initialize_schema()
                        schema_ready = True
                    state.last_run_succeeded = True
        finally:
            state.lock.release()
            with self._schema_initialization_locks_guard:
                state.references -= 1
                if state.references == 0:
                    del self._schema_initialization_states[path_key]
        if schema_ready:
            self._initialize_policy_integrity()

    def _initialize_schema(self) -> None:
        initialize_incremental_vacuum = not self.path.exists()
        statements = base_schema_statements()
        with self._connect() as connection:
            if initialize_incremental_vacuum:
                connection.execute("pragma auto_vacuum=incremental")
            # WAL must be enabled before schema DML starts a transaction. SQLite
            # cannot change journal modes from inside an active transaction, and
            # leaving an existing store in rollback-journal mode lets dashboard
            # readers exhaust the bounded hook write deadline.
            self._enable_wal_mode(connection)
            for statement in statements:
                connection.execute(statement)
            store_native_decision_receipts.ensure_native_command_receipt_binding_schema(connection, applied_at=_now())
            ensure_resume_schema(connection)
            ensure_command_activity_schema(connection, applied_at=_now())
            ensure_command_activity_health_schema(connection, applied_at=_now())
            ensure_command_activity_maintenance_schema(connection, applied_at=_now())
            ensure_command_activity_api_schema(connection, applied_at=_now())
            ensure_command_activity_display_schema(connection, applied_at=_now())
            ensure_evidence_schema(connection)
            ensure_extension_control_authority_schema(connection, require_compatible=False)
            ensure_local_cli_schema(connection)
            ensure_bash_operation_schema(connection, applied_at=_now())
            ensure_workspace_assessment_schema(connection, applied_at=_now())
            ensure_workspace_fix_proposal_schema(connection, applied_at=_now())
            ensure_workflow_capability_schema(connection, applied_at=_now())
            ensure_command_shadow_schema(connection, applied_at=_now())
            ensure_mcp_policy_request_schema(connection)
            if not self._schema_version_applied(connection, version=4):
                self._record_schema_version(connection, version=4)
            for idx_stmt in supply_chain_index_statements():
                connection.execute(idx_stmt)
            for idx_stmt in threat_intel_index_statements():
                connection.execute(idx_stmt)
            ensure_columns(connection, "policy_decisions", POLICY_COLUMNS)
            for index_statement in POLICY_INDEX_STATEMENTS:
                connection.execute(index_statement)
            ensure_columns(connection, "guard_local_once_approvals", LOCAL_ONCE_COLUMNS)
            connection.execute(LOCAL_ONCE_INDEX_STATEMENT)
            ensure_columns(connection, "runtime_receipts", RECEIPT_COLUMNS)
            self._ensure_runtime_receipt_envelopes_table(connection)
            if not self._schema_version_applied(connection, version=5):
                self._migrate_v5_receipt_envelopes(connection)
                self._record_schema_version(connection, version=5)
            ensure_columns(connection, "approval_requests", APPROVAL_COLUMNS)
            ensure_watch_only_approval_schema(connection, schema=self)
            if not self._schema_version_applied(connection, version=3):
                _backfill_approval_queue_columns_compat(connection)
                self._record_schema_version(connection, version=3)
            if not self._schema_version_applied(connection, version=9):
                connection.execute("drop index if exists idx_approval_group_status")
            for idx_stmt in approval_index_statements():
                connection.execute(idx_stmt)
            ensure_review_event_outbox_schema(connection, datetime.now(timezone.utc).isoformat())
            if not self._schema_version_applied(connection, version=9):
                self._record_schema_version(connection, version=9)
            for idx_stmt in receipt_index_statements():
                connection.execute(idx_stmt)
            for statement in receipt_rollup_schema_statements():
                connection.execute(statement)
            for idx_stmt in receipt_rollup_index_statements():
                connection.execute(idx_stmt)
            if not self._schema_version_applied(connection, version=6):
                request_receipt_rollup_rebuild(connection, _now())
                self._record_schema_version(connection, version=6)
            if not self._schema_version_applied(
                connection,
                version=_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
            ):
                # P45 changes ``warn`` from the reviewed bucket to allowed.
                # Existing v6 rollups can have the right total while retaining
                # the old bucket semantics, so this migration requests a rebuild;
                # the resident runs it before the next incremental delta or
                # total read, keeping the archived-receipt totals it preserves.
                request_receipt_rollup_rebuild(connection, _now())
                self._record_schema_version(
                    connection,
                    version=_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
                )
            if not self._schema_version_applied(connection, version=7):
                self._record_schema_version(connection, version=7)
            if not self._schema_version_applied(connection, version=8):
                self._record_schema_version(connection, version=8)
            ensure_columns(connection, "guard_client_attachments", ATTACHMENT_COLUMNS)
            self._ensure_local_device(connection)
            for statement in storage_maintenance_schema_statements():
                connection.execute(statement)
            self._record_schema_version(
                connection,
                version=STORAGE_MAINTENANCE_MIGRATION_VERSION,
            )
            self._record_schema_version(
                connection,
                version=STORAGE_QUERY_INDEX_MIGRATION_VERSION,
            )
            if not self._schema_version_applied(connection, version=2):
                self._record_schema_version(connection, version=2)
            # Preserve the legacy wait-timeout recovery without reopening cards
            # deliberately superseded by a fresh, canonically bound request.
            # A reopened pending card must not retain a terminal expiry reason.
            connection.execute(
                """
                update approval_requests
                set status = 'pending', reason = null, resolved_at = null
                where status = 'expired' and reason = 'Expired after waiting for review.'
                """
            )
            self._repair_store_permissions()

    def _initialize_policy_integrity(self) -> None:
        if getattr(self, "_prime_policy_integrity_on_initialize", True):
            # Prime secrets outside the transaction so credential-store lookups
            # cannot stall other Guard processes while holding the writer lock.
            self._startup_prefetched_policy_integrity_secret_material = self._policy_integrity_secret_material(
                create=False
            )
            self._startup_prefetched_policy_integrity_trusted_state = self._load_policy_integrity_control_state(
                create=False
            )
            self._startup_prefetched_policy_integrity_repair_failed = False
            self._prepare_startup_prefetched_policy_integrity_state()
            try:
                with self._connect() as connection:
                    self._refresh_policy_integrity_state(connection, now=_now(), create_key=False)
            finally:
                self._startup_prefetched_policy_integrity_secret_material = _POLICY_INTEGRITY_LOOKUP_UNSET
                self._startup_prefetched_policy_integrity_trusted_state = _POLICY_INTEGRITY_LOOKUP_UNSET
                self._startup_prefetched_policy_integrity_repair_failed = False

    def _schema_is_current(self) -> bool:
        if not self.path.is_file():
            return False
        timeout_seconds = sqlite_connect_timeout_seconds()
        if timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
        try:
            with self._hold_storage_gate(exclusive=False):
                from .sqlite_deadline_connection import DeadlineConnection
                from .sqlite_tuning import sqlite_operation_deadline_monotonic

                factory = (
                    DeadlineConnection if sqlite_operation_deadline_monotonic() is not None else sqlite3.Connection
                )
                connection = sqlite3.connect(self.path, timeout=timeout_seconds, factory=factory)
                try:
                    connection.execute(f"pragma busy_timeout={int(timeout_seconds * 1000)}")
                    placeholders = ", ".join("?" for _ in _REQUIRED_SCHEMA_MIGRATION_VERSIONS)
                    row = connection.execute(
                        f"select count(*) from schema_migrations where version in ({placeholders})",
                        _REQUIRED_SCHEMA_MIGRATION_VERSIONS,
                    ).fetchone()
                    storage_row = connection.execute(
                        """
                        select 1 from sqlite_master
                        where type = 'table' and name = 'guard_storage_maintenance'
                        """
                    ).fetchone()
                    approval_columns = {
                        str(column[1]) for column in connection.execute("pragma table_info(approval_requests)")
                    }
                    required_approval_columns = {
                        "guard_version",
                        "first_seen_guard_version",
                        "last_seen_guard_version",
                        "watch_only_observation",
                        "continuation_snapshot_json",
                        "extension_allow_hint_json",
                    }
                    return (
                        row is not None
                        and int(row[0]) == len(_REQUIRED_SCHEMA_MIGRATION_VERSIONS)
                        and storage_row is not None
                        and "oauth_source" in approval_columns
                        and required_approval_columns <= approval_columns
                        and local_cli_schema_is_current(connection)
                    )
                finally:
                    connection.close()
        except sqlite3.DatabaseError:
            return False

    @staticmethod
    def _enable_wal_mode(connection: sqlite3.Connection) -> None:
        original_busy_timeout_row = connection.execute("pragma busy_timeout").fetchone()
        original_busy_timeout_ms = int(original_busy_timeout_row[0]) if original_busy_timeout_row else 0
        retry_deadline = time.monotonic() + (original_busy_timeout_ms / 1000)
        lock_error: sqlite3.OperationalError | None = None
        try:
            while True:
                remaining_timeout_ms = max(0, int((retry_deadline - time.monotonic()) * 1000))
                if lock_error is not None and remaining_timeout_ms <= 0:
                    raise lock_error
                wal_busy_timeout_ms = min(remaining_timeout_ms, SQLITE_WAL_BUSY_TIMEOUT_MS)
                connection.execute(f"pragma busy_timeout={wal_busy_timeout_ms}")
                try:
                    connection.execute("pragma journal_mode=WAL")
                    return
                except sqlite3.OperationalError as exc:
                    if "database is locked" not in str(exc).lower():
                        raise
                    lock_error = exc
                    remaining_seconds = retry_deadline - time.monotonic()
                    if remaining_seconds <= 0:
                        raise
                    _sleep_compat(min(_sqlite_lock_retry_delay_seconds_compat(), remaining_seconds))
        finally:
            connection.execute(f"pragma busy_timeout={original_busy_timeout_ms}")

    @staticmethod
    def _ensure_runtime_receipt_envelopes_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            create table if not exists runtime_receipt_envelopes (
              receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
              envelope_full_json text,
              envelope_redacted_json text not null
            )
            """
        )

    @staticmethod
    def _migrate_v5_receipt_envelopes(connection: sqlite3.Connection) -> None:
        rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if "action_envelope_json" not in existing:
            return
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            select receipt_id, action_envelope_json, '{}'
            from runtime_receipts
            where action_envelope_json is not null
              and not exists (
                select 1 from runtime_receipt_envelopes
                where runtime_receipt_envelopes.receipt_id = runtime_receipts.receipt_id
              )
            """
        )
        connection.execute("drop table if exists runtime_receipts_new")
        connection.execute(
            """
            create table runtime_receipts_new (
              receipt_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              policy_decision text not null,
              capabilities_summary text not null default '',
              changed_capabilities_json text not null,
              provenance_summary text not null,
              user_override text,
              artifact_name text,
              source_scope text,
              scanner_evidence_json text not null default '[]',
              timestamp text not null,
              diff_summary text,
              approval_source text,
              approval_request_id text,
              raw_command_text text
            )
            """
        )
        connection.execute(
            """
            insert into runtime_receipts_new (
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
              artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
              approval_source, approval_request_id, raw_command_text
            )
            select
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
              artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
              approval_source, null, null
            from runtime_receipts
            """
        )
        connection.execute("drop table runtime_receipts")
        connection.execute("alter table runtime_receipts_new rename to runtime_receipts")

    @staticmethod
    def _ensure_approval_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(approval_requests)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table approval_requests add column {column_name} {column_type}")

    @staticmethod
    def _record_schema_version(connection: sqlite3.Connection, *, version: int) -> None:
        connection.execute(
            """
            insert or ignore into schema_migrations (version, applied_at)
            values (?, ?)
            """,
            (version, _now()),
        )

    @staticmethod
    def _schema_version_applied(connection: sqlite3.Connection, *, version: int) -> bool:
        row = connection.execute(
            "select 1 from schema_migrations where version = ?",
            (version,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _ensure_local_device(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "select device_key from guard_devices where device_key = ?",
            (_DEVICE_ROW_KEY,),
        ).fetchone()
        if row is not None:
            return
        now = _now()
        connection.execute(
            """
            insert into guard_devices (device_key, installation_id, device_label, created_at, updated_at)
            values (?, ?, ?, ?, ?)
            """,
            (_DEVICE_ROW_KEY, uuid4().hex, "Local machine", now, now),
        )

    def list_table_names(self) -> list[str]:
        names = self._native_store_call("list_table_names", {})
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise RuntimeError("native list_table_names returned no answer")
        return sorted(cast("list[str]", names))


forget_in_child(StoreConnectionSchemaMixin._schema_initialization_states)
