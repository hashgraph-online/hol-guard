"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import threading
from contextlib import suppress as suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar
from uuid import uuid4

from . import store_native_decision_receipts, store_review_event_outbox_schema
from .mcp.policy_store import ensure_mcp_policy_request_schema as ensure_mcp_policy_request_schema
from .sqlite_profile import (
    SQLiteMigrationGateReport,
    SQLiteProfiler,
    SQLiteProfileSnapshot,
    sqlite_error_is_busy_locked,
)
from .sqlite_recovery import (
    FATAL_SQLITE_ERROR_MARKERS,
    SQLITE_IO_ERROR_MARKER,
    restore_readable_sqlite_store,
    salvage_local_cli_state,
    sqlite_store_is_proven_unusable,
)

# ruff: noqa: F403,F405
from .store_base import *
from .store_command_activity_api_schema import ensure_command_activity_api_schema as ensure_command_activity_api_schema
from .store_command_activity_display_schema import (
    COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,
)
from .store_command_activity_display_schema import (
    ensure_command_activity_display_schema as ensure_command_activity_display_schema,
)
from .store_command_activity_health_schema import (
    ensure_command_activity_health_schema as ensure_command_activity_health_schema,
)
from .store_command_activity_maintenance_schema import (
    ensure_command_activity_maintenance_schema as ensure_command_activity_maintenance_schema,
)
from .store_command_activity_schema import ensure_command_activity_schema as ensure_command_activity_schema
from .store_command_shadow_schema import ensure_command_shadow_schema as ensure_command_shadow_schema
from .store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema as ensure_extension_control_authority_schema,
)
from .store_local_cli_schema import ensure_local_cli_schema as ensure_local_cli_schema
from .store_resume import ensure_resume_schema as ensure_resume_schema
from .store_review_event_outbox_schema import ensure_review_event_outbox_schema as ensure_review_event_outbox_schema
from .store_secret_policy_integrity import _POLICY_INTEGRITY_LOOKUP_UNSET
from .store_storage_maintenance import (
    STORAGE_MAINTENANCE_MIGRATION_VERSION as STORAGE_MAINTENANCE_MIGRATION_VERSION,
)
from .store_storage_maintenance import (
    STORAGE_QUERY_INDEX_MIGRATION_VERSION,
)
from .store_storage_maintenance import (
    storage_maintenance_schema_statements as storage_maintenance_schema_statements,
)
from .store_watch_only_approval_schema import (
    WATCH_ONLY_APPROVAL_MIGRATION_VERSION,
)
from .store_watch_only_approval_schema import (
    ensure_watch_only_approval_schema as ensure_watch_only_approval_schema,
)
from .store_workflow_capabilities_schema import (
    WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION,
)
from .store_workflow_capabilities_schema import (
    ensure_workflow_capability_schema as ensure_workflow_capability_schema,
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
    COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,
    *store_native_decision_receipts.native_decision_receipt_migration_versions(),
)


@dataclass
class _SchemaInitializationState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    references: int = 0
    last_run_succeeded: bool = False


from .store_connection_columns import StoreConnectionColumnsMixin  # noqa: E402
from .store_connection_lifecycle import StoreConnectionLifecycleMixin  # noqa: E402
from .store_connection_statements import connection_schema_statements as connection_schema_statements  # noqa: E402


class StoreConnectionSchemaMixin(StoreConnectionLifecycleMixin, StoreConnectionColumnsMixin):
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
    _last_sqlite_recovery = "skipped"
    _last_sqlite_recovery_details: dict[str, bool] | None = None

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
                        from .native_command_control_windows_lock import try_lock_authority_file

                        handle.seek(0)
                        if not handle.read(1):
                            handle.write(b"0")
                            handle.flush()
                        handle.seek(0)
                        # CRT's read-lock flag is exclusive too. This gate
                        # must allow ordinary connections to share the lease.
                        try_lock_authority_file(handle.fileno(), shared=not exclusive)
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
                    from .native_command_control_windows_lock import unlock_authority_file

                    handle.seek(0)
                    unlock_authority_file(handle.fileno())
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
        self._last_sqlite_recovery = "skipped"
        self._last_sqlite_recovery_details = None
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
                self._last_sqlite_recovery = "replaced"
                return True

            if not self._store_is_proven_unusable(error):
                return False

            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            quarantine_id = f"{stamp}-{uuid4().hex[:8]}"
            quarantined = self.guard_home / f"guard.db.corrupt-{quarantine_id}"
            for suffix in ("", "-wal", "-shm"):
                source = Path(f"{self.path}{suffix}")
                if not source.exists() or source.is_symlink():
                    continue
                source.replace(self.guard_home / f"{quarantined.name}{suffix}")
            _store_logger.error(
                "Guard quarantined an unusable SQLite store after a fatal storage error: %s",
                type(error).__name__,
            )
            self._storage_recovery_local.owner = id(self)
            try:
                if restore_readable_sqlite_store(destination=self.path, quarantined=quarantined):
                    self._last_sqlite_recovery = "restored"
                    _store_logger.error("Guard restored the quarantined SQLite store after it still opened cleanly.")
                else:
                    self._initialize_schema()
                    from .sqlite_cloud_review_recovery import salvage_cloud_review_state

                    cloud_restored = salvage_cloud_review_state(source=quarantined, destination=self.path)
                    cli_restored = salvage_local_cli_state(source=quarantined, destination=self.path)
                    # These independent stores recover atomically within their own
                    # authority boundary; a CLI failure must not discard Review.
                    self._last_sqlite_recovery_details = {"cloud_review": cloud_restored, "local_cli": cli_restored}
                    if cloud_restored or cli_restored:
                        self._last_sqlite_recovery = "reinitialized_salvaged"
                    else:
                        self._last_sqlite_recovery = "reinitialized"
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
        yielded = False
        fatal_error: sqlite3.DatabaseError | None = None
        failed_identity: tuple[int, int] | None = None
        with self._hold_storage_gate(exclusive=False):
            try:
                with self._connect_once() as connection:
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
                    raise
        if fatal_error is None:
            return
        recovered = self._recover_fatal_sqlite_store(fatal_error, failed_identity=failed_identity)
        if not recovered and not sqlite_error_is_busy_locked(fatal_error):
            raise fatal_error
        with self._hold_storage_gate(exclusive=False), self._connect_once() as connection:
            yield connection

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
        store_review_event_outbox_schema.notify_review_event_wake(self.path, outbox_generation)
        if notification is not None:
            self._publish_policy_integrity_state_notification(notification)
