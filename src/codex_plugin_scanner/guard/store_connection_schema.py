"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar
from uuid import uuid4

from . import store_review_event_outbox_schema
from .mcp.policy_store import ensure_mcp_policy_request_schema
from .sqlite_profile import (
    SQLiteMigrationGateReport,
    SQLiteProfiler,
    SQLiteProfileSnapshot,
    sqlite_error_is_busy_locked,
)
from .sqlite_recovery import (
    FATAL_SQLITE_ERROR_MARKERS,
    SQLITE_IO_ERROR_MARKER,
    sqlite_store_is_proven_unusable,
)

# ruff: noqa: F403,F405
from .store_base import *
from .store_command_activity_api_schema import ensure_command_activity_api_schema
from .store_command_activity_health_schema import ensure_command_activity_health_schema
from .store_command_activity_maintenance_schema import ensure_command_activity_maintenance_schema
from .store_command_activity_schema import ensure_command_activity_schema
from .store_command_shadow_schema import ensure_command_shadow_schema
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_local_cli_schema import ensure_local_cli_schema
from .store_resume import ensure_resume_schema
from .store_review_event_outbox_schema import ensure_review_event_outbox_schema
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


_POLICY_INDEX_STATEMENTS = (
    """
    create index if not exists idx_policy_decisions_reuse_artifact
    on policy_decisions (action, harness, artifact_id, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_reuse_hash
    on policy_decisions (action, harness, artifact_hash, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_reuse_publisher
    on policy_decisions (action, harness, publisher, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_lookup_artifact
    on policy_decisions (artifact_id, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'artifact'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_workspace
    on policy_decisions (workspace, harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'workspace'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_publisher
    on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'publisher'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_publisher_legacy
    on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'publisher' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_harness
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'harness'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_harness_legacy
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'harness' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_global
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'global'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_global_legacy
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'global' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_harness_broad
    on policy_decisions (harness, updated_at desc, decision_id desc)
    where scope = 'harness' and action = 'allow' and artifact_id is null
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_global_broad
    on policy_decisions (harness, updated_at desc, decision_id desc)
    where scope = 'global' and action = 'allow' and artifact_id is null
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_publisher
    on policy_decisions (harness, publisher, updated_at desc, decision_id desc)
    where scope = 'publisher' and action = 'allow'
    """,
)

_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION = 16
_REQUIRED_SCHEMA_MIGRATION_VERSIONS = (  # Keep retired-index databases on the path that reaps the index.
    *range(2, STORAGE_QUERY_INDEX_MIGRATION_VERSION + 1),
    WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION,
    WATCH_ONLY_APPROVAL_MIGRATION_VERSION,
    store_review_event_outbox_schema.REVIEW_EVENT_OUTBOX_MIGRATION_VERSION,
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
    _storage_gate_local: ClassVar[threading.local] = threading.local()

    def _current_thread_owns_storage_recovery(self) -> bool:
        return getattr(self._storage_recovery_local, "owner", None) == id(self)

    @staticmethod
    def _is_fatal_sqlite_error(error: BaseException) -> bool:
        return isinstance(error, sqlite3.DatabaseError) and any(
            marker in str(error).lower() for marker in FATAL_SQLITE_ERROR_MARKERS
        )

    @contextmanager
    def _hold_storage_gate(self, *, exclusive: bool) -> Iterator[None]:
        local = self._storage_gate_local
        if getattr(local, "owner", None) == id(self) and getattr(local, "depth", 0) > 0:
            if exclusive and getattr(local, "exclusive", False) is False:
                raise RuntimeError("Cannot upgrade an active Guard storage read gate.")
            local.depth += 1
            try:
                yield
            finally:
                local.depth -= 1
            return
        path = self.guard_home / "storage-access.lock"
        deadline = time.monotonic() + sqlite_connect_timeout_seconds()
        with path.open("a+b") as handle:
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        handle.seek(0)
                        if not handle.read(1):
                            handle.write(b"0")
                            handle.flush()
                        handle.seek(0)
                        mode = msvcrt.LK_NBLCK if exclusive else msvcrt.LK_NBRLCK
                        msvcrt.locking(handle.fileno(), mode, 1)
                    else:
                        import fcntl

                        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                        fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Timed out waiting for Guard storage access.") from None
                    time.sleep(0.01)
            local.owner = id(self)
            local.depth = 1
            local.exclusive = exclusive
            try:
                yield
            finally:
                local.owner = None
                local.depth = 0
                local.exclusive = False
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _store_is_proven_unusable(self, error: BaseException) -> bool:
        return sqlite_store_is_proven_unusable(
            path=self.path,
            guard_home=self.guard_home,
            error=error,
            fatal_error=self._is_fatal_sqlite_error(error),
        )

    def _recover_fatal_sqlite_store(
        self,
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        is_io_error = SQLITE_IO_ERROR_MARKER in str(error).lower()
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
            # Another process may already have replaced the failed store.
            try:
                current_stat = self.path.stat()
                current_identity = current_stat.st_dev, current_stat.st_ino
            except OSError:
                current_identity = None
            if current_identity != failed_identity:
                return True

            if not self._store_is_proven_unusable(error):
                return False

            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            quarantine_id = f"{stamp}-{uuid4().hex[:8]}"
            for suffix in ("", "-wal", "-shm"):
                source = Path(f"{self.path}{suffix}")
                if not source.exists() or source.is_symlink():
                    continue
                destination = self.guard_home / f"guard.db.corrupt-{quarantine_id}{suffix}"
                source.replace(destination)
            _store_logger.error(
                "Guard quarantined an unusable SQLite store after a fatal storage error: %s",
                type(error).__name__,
            )
            self._storage_recovery_local.owner = id(self)
            try:
                self._initialize_schema()
            finally:
                self._storage_recovery_local.owner = None
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
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._current_thread_owns_storage_recovery():
            with self._connect_once() as connection:
                yield connection
            return
        fatal_error: sqlite3.DatabaseError | None = None
        failed_identity: tuple[int, int] | None = None
        with self._hold_storage_gate(exclusive=False):
            try:
                with self._connect_once() as connection:
                    yield connection
            except sqlite3.DatabaseError as error:
                fatal_error = error
                try:
                    failed_stat = self.path.stat()
                    failed_identity = failed_stat.st_dev, failed_stat.st_ino
                except OSError:
                    failed_identity = None
        if fatal_error is not None:
            self._recover_fatal_sqlite_store(fatal_error, failed_identity=failed_identity)
            raise fatal_error

    @contextmanager
    def _connect_once(self) -> Iterator[sqlite3.Connection]:
        connect_timeout_seconds = sqlite_connect_timeout_seconds()
        profiler = self._sqlite_profiler()
        connect_started = time.monotonic()
        try:
            connection = sqlite3.connect(self.path, timeout=connect_timeout_seconds)
        except sqlite3.OperationalError as error:
            profiler.record_connect((time.monotonic() - connect_started) * 1000)
            if sqlite_error_is_busy_locked(error):
                profiler.record_busy_locked()
            raise
        profiler.record_connect((time.monotonic() - connect_started) * 1000)
        connection.row_factory = sqlite3.Row
        start = time.monotonic()
        notification: dict[str, object] | None = None
        database_failed = False
        try:
            connection.execute(f"pragma busy_timeout={int(connect_timeout_seconds * 1000)}")
            # Hot-path tuning: synchronous=NORMAL is only safe once the database
            # is in WAL mode (durability comes from checkpointing, not per-commit
            # fsync). Leave FULL for rollback-journal DBs and schema-init paths.
            journal_mode_row = connection.execute("pragma journal_mode").fetchone()
            if journal_mode_row is not None and str(journal_mode_row[0]).lower() == "wal":
                connection.execute("pragma synchronous=NORMAL")
            # Enlarge the page cache and mmap window so multi-GB stores don't
            # thrash the default 2 MiB cache.
            connection.execute(f"pragma cache_size=-{SQLITE_CACHE_SIZE_KIB}")
            connection.execute(f"pragma mmap_size={SQLITE_MMAP_SIZE_BYTES}")
            yield connection
            store_review_event_outbox_schema.finalize_review_event_payload_hashes(connection)
            commit_started = time.monotonic()
            try:
                connection.commit()
            finally:
                profiler.record_commit((time.monotonic() - commit_started) * 1000)
            notification = self._take_policy_integrity_state_notification(connection)
        except sqlite3.OperationalError as error:
            database_failed = True
            if sqlite_error_is_busy_locked(error):
                profiler.record_busy_locked()
            raise
        except sqlite3.DatabaseError:
            database_failed = True
            raise
        finally:
            profiler.record_transaction((time.monotonic() - start) * 1000)
            if notification is None and not database_failed:
                self._take_policy_integrity_state_notification(connection)
            connection.close()
            elapsed_ms = (time.monotonic() - start) * 1000
            self._repair_store_permissions()
            if elapsed_ms >= _slow_query_threshold_ms_compat():
                log = _store_logger.warning if _should_warn_on_slow_store_transactions() else _store_logger.debug
                log(
                    "Guard store slow transaction (%.0fms); consider indexing hot query paths.",
                    elapsed_ms,
                )
        if notification is not None:
            self._publish_policy_integrity_state_notification(notification)

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
    ) -> Iterator[None]:
        deadline = time.monotonic() + max(timeout_seconds, 0.0)
        with path.open("a+b") as handle:
            while True:
                try:
                    _acquire_advisory_file_lock(handle)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(timeout_message) from None
                    time.sleep(poll_seconds)
            try:
                yield
            finally:
                with suppress(OSError):
                    _release_advisory_file_lock(handle)

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
            if self._schema_is_current():
                self._initialize_policy_integrity()
                return
            if not self._recover_fatal_sqlite_store(error):
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
        statements = (
            """
            create table if not exists harness_installations (
              harness text primary key,
              active integer not null,
              workspace text,
              config_path text,
              metadata_json text not null default '{}',
              updated_at text not null
            )
            """,
            """
            create table if not exists artifact_snapshots (
              artifact_id text not null,
              harness text not null,
              snapshot_json text not null,
              artifact_hash text not null,
              recorded_at text not null,
              primary key (artifact_id, harness)
            )
            """,
            """
            create table if not exists artifact_hashes (
              artifact_id text not null,
              harness text not null,
              artifact_hash text not null,
              recorded_at text not null
            )
            """,
            """
            create table if not exists artifact_diffs (
              diff_id integer primary key autoincrement,
              artifact_id text not null,
              harness text not null,
              changed_fields_json text not null,
              previous_hash text,
              current_hash text not null,
              recorded_at text not null
            )
            """,
            """
            create table if not exists artifact_capabilities (
              artifact_id text not null,
              harness text not null,
              capability_json text not null,
              updated_at text not null,
              primary key (artifact_id, harness)
            )
            """,
            """
            create table if not exists provenance_cache (
              artifact_hash text primary key,
              payload_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists artifact_inventory (
              artifact_id text not null,
              harness text not null,
              artifact_name text not null,
              artifact_type text not null,
              source_scope text not null,
              config_path text not null,
              publisher text,
              origin_url text,
              launch_command text,
              transport text,
              first_seen_at text not null,
              last_seen_at text not null,
              last_changed_at text,
              last_approved_at text,
              removed_at text,
              present integer not null default 1,
              last_policy_action text not null,
              artifact_hash text not null,
              primary key (artifact_id, harness)
            )
            """,
            """
            create table if not exists policy_decisions (
              decision_id integer primary key autoincrement,
              harness text not null,
              scope text not null,
              artifact_id text,
              artifact_hash text,
              workspace text,
              publisher text,
              action text not null,
              reason text,
              owner text,
              source text not null default 'local',
              expires_at text,
              policy_document_schema_version text,
              policy_document_id text,
              policy_document_digest text,
              policy_rule_id text,
              policy_provenance_json text,
              updated_at text not null
            )
            """,
            """
            create table if not exists runtime_receipts (
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
              raw_command_text text
            )
            """,
            """
            create table if not exists runtime_receipt_envelopes (
              receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
              envelope_full_json text,
              envelope_redacted_json text not null
            )
            """,
            """
            create table if not exists publisher_cache (
              publisher_key text primary key,
              payload_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists sync_state (
              state_key text primary key,
              payload_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists guard_devices (
              device_key text primary key,
              installation_id text not null,
              device_label text not null,
              created_at text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists schema_migrations (
              version integer primary key,
              applied_at text not null
            )
            """,
            """
            create table if not exists guard_events (
              event_id integer primary key autoincrement,
              event_name text not null,
              payload_json text not null,
              occurred_at text not null
            )
            """,
            """
            create index if not exists idx_guard_events_recent
            on guard_events (occurred_at desc, event_id desc)
            """,
            """
            create index if not exists idx_guard_events_name_recent
            on guard_events (event_name, occurred_at desc, event_id desc)
            """,
            """
            create table if not exists guard_exact_cloud_review_receipts (
              receipt_id text primary key,
              request_id text not null,
              claimed_at text not null
            )
            """,
            """
            create table if not exists guard_local_once_approvals (
              approval_id text primary key,
              request_id text not null,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              workspace text,
              publisher text,
              action text not null,
              created_at text not null,
              expires_at text not null,
              claimed_at text,
              integrity_version integer,
              payload_hash text,
              payload_mac text,
              integrity_key_id text,
              signed_at text
            )
            """,
            """
            create index if not exists idx_guard_local_once_approvals_lookup
            on guard_local_once_approvals (claimed_at, harness, artifact_id, artifact_hash, expires_at)
            """,
            """
            create index if not exists idx_guard_local_once_reuse_artifact
            on guard_local_once_approvals (action, harness, artifact_id, created_at desc, approval_id desc)
            """,
            """
            create index if not exists idx_guard_local_once_reuse_hash
            on guard_local_once_approvals (action, harness, artifact_hash, created_at desc, approval_id desc)
            """,
            """
            create index if not exists idx_guard_local_once_diagnostic_artifact
            on guard_local_once_approvals (harness, artifact_id, created_at desc, approval_id desc)
            where claimed_at is null and action = 'allow'
            """,
            """
            create index if not exists idx_guard_local_once_diagnostic_hash
            on guard_local_once_approvals (harness, artifact_hash, created_at desc, approval_id desc)
            where claimed_at is null and action = 'allow'
            """,
            """
            create table if not exists guard_approval_authority_revision (
              singleton integer primary key check (singleton = 1),
              revision integer not null
            )
            """,
            """
            insert or ignore into guard_approval_authority_revision (singleton, revision)
            values (1, 0)
            """,
            """
            create trigger if not exists trg_policy_decisions_authority_insert
            after insert on policy_decisions begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create trigger if not exists trg_policy_decisions_authority_update
            after update on policy_decisions begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create trigger if not exists trg_policy_decisions_authority_delete
            after delete on policy_decisions begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create trigger if not exists trg_local_once_authority_insert
            after insert on guard_local_once_approvals begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create trigger if not exists trg_local_once_authority_update
            after update on guard_local_once_approvals begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create trigger if not exists trg_local_once_authority_delete
            after delete on guard_local_once_approvals begin
              update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
            end
            """,
            """
            create table if not exists guard_cloud_events (
              event_id text primary key,
              idempotency_key text not null unique,
              event_type text not null,
              payload_json text not null,
              occurred_at text not null,
              uploaded_at text
            )
            """,
            """
            create index if not exists idx_guard_cloud_events_sync
            on guard_cloud_events (uploaded_at, occurred_at)
            """,
            """
            create table if not exists guard_runtime_state (
              state_key text primary key,
              session_id text not null,
              daemon_host text not null,
              daemon_port integer not null,
              started_at text not null,
              last_heartbeat_at text not null
            )
            """,
            """
            create table if not exists scanner_cache (
              scanner_name text not null,
              target_id text not null,
              cache_key text not null,
              input_content_hash text not null,
              scanner_version text not null,
              payload_json text not null,
              updated_at text not null,
              primary key (scanner_name, target_id)
            )
            """,
            """
            create index if not exists idx_scanner_cache_key
            on scanner_cache (cache_key)
            """,
            """
            create table if not exists managed_installs (
              harness text primary key,
              active integer not null,
              workspace text,
              manifest_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists guard_sessions (
              session_id text primary key,
              harness text not null,
              surface text not null,
              status text not null,
              client_name text not null,
              client_title text,
              client_version text,
              workspace text,
              capabilities_json text not null default '[]',
              created_at text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists guard_operations (
              operation_id text primary key,
              session_id text not null,
              harness text not null,
              operation_type text not null,
              status text not null,
              approval_request_ids_json text not null default '[]',
              resume_token text,
              metadata_json text not null default '{}',
              created_at text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists guard_operation_items (
              item_id text primary key,
              operation_id text not null,
              item_type text not null,
              lifecycle text not null,
              payload_json text not null default '{}',
              created_at text not null
            )
            """,
            """
            create table if not exists guard_client_attachments (
              client_id text primary key,
              surface text not null,
              session_id text,
              metadata_json text not null default '{}',
              lease_id text not null default '',
              lease_expires_at text,
              attached_at text not null,
              last_seen_at text not null
            )
            """,
            """
            create table if not exists guard_surface_opens (
              surface text not null,
              open_key text not null,
              opened_at text not null,
              primary key (surface, open_key)
            )
            """,
            """
            create table if not exists guard_request_read_state (
              request_id text primary key,
              read_at text not null
            )
            """,
            """
            create index if not exists idx_guard_request_read_state_read_at
            on guard_request_read_state (read_at desc)
            """,
            resume_schema_statement(),
            connect_state_schema_statement(),
            connect_request_schema_statement(),
            connect_state_schema_statement(),
            approval_schema_statement(),
            supply_chain_bundle_schema_statement(),
            supply_chain_eval_cache_schema_statement(),
            threat_intel_bundle_schema_statement(),
            threat_intel_matches_schema_statement(),
        )
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
            ensure_resume_schema(connection)
            ensure_command_activity_schema(connection, applied_at=_now())
            ensure_command_activity_health_schema(connection, applied_at=_now())
            ensure_command_activity_maintenance_schema(connection, applied_at=_now())
            ensure_command_activity_api_schema(connection, applied_at=_now())
            ensure_evidence_schema(connection)
            ensure_extension_control_authority_schema(connection, require_compatible=False)
            ensure_local_cli_schema(connection)
            ensure_workflow_capability_schema(connection, applied_at=_now())
            ensure_command_shadow_schema(connection, applied_at=_now())
            ensure_mcp_policy_request_schema(connection)
            if not self._schema_version_applied(connection, version=4):
                self._record_schema_version(connection, version=4)
            for idx_stmt in supply_chain_index_statements():
                connection.execute(idx_stmt)
            for idx_stmt in threat_intel_index_statements():
                connection.execute(idx_stmt)
            self._ensure_policy_column(connection, "publisher", "text")
            self._ensure_policy_column(connection, "artifact_hash", "text")
            self._ensure_policy_column(connection, "owner", "text")
            self._ensure_policy_column(connection, "source", "text not null default 'local'")
            self._ensure_policy_column(connection, "expires_at", "text")
            self._ensure_policy_column(connection, "integrity_version", "integer")
            self._ensure_policy_column(connection, "integrity_generation", "integer")
            self._ensure_policy_column(connection, "payload_hash", "text")
            self._ensure_policy_column(connection, "payload_mac", "text")
            self._ensure_policy_column(connection, "integrity_key_id", "text")
            self._ensure_policy_column(connection, "signed_at", "text")
            self._ensure_policy_column(connection, "policy_document_schema_version", "text")
            self._ensure_policy_column(connection, "policy_document_id", "text")
            self._ensure_policy_column(connection, "policy_document_digest", "text")
            self._ensure_policy_column(connection, "policy_rule_id", "text")
            self._ensure_policy_column(connection, "policy_provenance_json", "text")
            for index_statement in _POLICY_INDEX_STATEMENTS:
                connection.execute(index_statement)
            self._ensure_column(connection, "guard_local_once_approvals", "integrity_version", "integer")
            self._ensure_column(connection, "guard_local_once_approvals", "payload_hash", "text")
            self._ensure_column(connection, "guard_local_once_approvals", "payload_mac", "text")
            self._ensure_column(connection, "guard_local_once_approvals", "integrity_key_id", "text")
            self._ensure_column(connection, "guard_local_once_approvals", "signed_at", "text")
            self._ensure_runtime_receipts_column(connection, "capabilities_summary", "text not null default ''")
            self._ensure_runtime_receipts_column(connection, "scanner_evidence_json", "text not null default '[]'")
            self._ensure_runtime_receipts_column(connection, "diff_summary", "text")
            self._ensure_runtime_receipts_column(connection, "approval_source", "text")
            self._ensure_runtime_receipts_column(connection, "approval_request_id", "text")
            self._ensure_runtime_receipts_column(connection, "raw_command_text", "text")
            self._ensure_runtime_receipt_envelopes_table(connection)
            if not self._schema_version_applied(connection, version=5):
                self._migrate_v5_receipt_envelopes(connection)
                self._record_schema_version(connection, version=5)
            self._ensure_approval_column(connection, "artifact_type", "text not null default 'artifact'")
            self._ensure_approval_column(connection, "launch_target", "text")
            self._ensure_approval_column(connection, "transport", "text")
            self._ensure_approval_column(connection, "risk_summary", "text")
            self._ensure_approval_column(connection, "risk_signals_json", "text not null default '[]'")
            self._ensure_approval_column(connection, "artifact_label", "text")
            self._ensure_approval_column(connection, "source_label", "text")
            self._ensure_approval_column(connection, "trigger_summary", "text")
            self._ensure_approval_column(connection, "why_now", "text")
            self._ensure_approval_column(connection, "launch_summary", "text")
            self._ensure_approval_column(connection, "risk_headline", "text")
            self._ensure_approval_column(connection, "action_envelope_json", "text")
            self._ensure_approval_column(connection, "decision_v2_json", "text")
            self._ensure_approval_column(connection, "workspace", "text")
            self._ensure_approval_column(connection, "normalized_identity_key", "text")
            self._ensure_approval_column(connection, "action_identity", "text")
            self._ensure_approval_column(connection, "queue_group_id", "text")
            self._ensure_approval_column(connection, "dedupe_count", "integer not null default 1")
            self._ensure_approval_column(connection, "last_seen_at", "text")
            self._ensure_approval_column(connection, "fallback_cli_command", "text")
            self._ensure_approval_column(connection, "scanner_evidence_json", "text not null default '[]'")
            self._ensure_approval_column(connection, "browser_intent_json", "text")
            self._ensure_approval_column(connection, "desktop_notified_at", "text")
            self._ensure_approval_column(connection, "raw_command_text", "text")
            self._ensure_approval_column(connection, "continuation_snapshot_json", "text")
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
                if receipt_rollups_need_backfill(connection):
                    backfill_receipt_rollups(connection)
                self._record_schema_version(connection, version=6)
            if not self._schema_version_applied(
                connection,
                version=_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
            ):
                # P45 changes ``warn`` from the reviewed bucket to allowed.
                # Existing v6 rollups can have the right total while retaining
                # the old bucket semantics, so this migration must rebuild them
                # unconditionally before incremental deltas are applied.
                backfill_receipt_rollups(connection)
                self._record_schema_version(
                    connection,
                    version=_RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
                )
            if not self._schema_version_applied(connection, version=7):
                self._record_schema_version(connection, version=7)
            if not self._schema_version_applied(connection, version=8):
                self._record_schema_version(connection, version=8)
            self._ensure_attachment_column(connection, "lease_id", "text not null default ''")
            self._ensure_attachment_column(connection, "lease_expires_at", "text")
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
            connection.execute(
                """
                update approval_requests
                set status = 'pending', reason = null, resolved_at = null
                where status = 'expired'
                """
            )
            self._repair_store_permissions()

    def _initialize_policy_integrity(self) -> None:
        if getattr(self, "_prime_policy_integrity_on_initialize", True):
            # Prime policy-integrity secrets outside the SQLite transaction. Some
            # credential-store lookups can block long enough to stall other Guard
            # processes if initialization still holds the writer lock.
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
        try:
            with self._hold_storage_gate(exclusive=False):
                connection = sqlite3.connect(self.path, timeout=timeout_seconds)
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
                    }
                    return (
                        row is not None
                        and int(row[0]) == len(_REQUIRED_SCHEMA_MIGRATION_VERSIONS)
                        and storage_row is not None
                        and required_approval_columns <= approval_columns
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
    def _ensure_policy_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(policy_decisions)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table policy_decisions add column {column_name} {column_type}")

    @staticmethod
    def _ensure_runtime_receipts_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table runtime_receipts add column {column_name} {column_type}")

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
    def _ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
        rows = connection.execute(f"pragma table_info({table_name})").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table {table_name} add column {column_name} {column_type}")

    @staticmethod
    def _ensure_attachment_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(guard_client_attachments)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table guard_client_attachments add column {column_name} {column_type}")

    @staticmethod
    def _ensure_evidence_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(guard_evidence)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table guard_evidence add column {column_name} {column_type}")

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
        with self._connect() as connection:
            rows = connection.execute("select name from sqlite_master where type = 'table'").fetchall()
        return sorted(str(row["name"]) for row in rows)
