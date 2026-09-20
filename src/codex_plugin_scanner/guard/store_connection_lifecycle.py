"""Guard storage advisory locks and serialized schema lifecycle."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false
from contextlib import contextmanager
from typing import TYPE_CHECKING

from .store_base import (
    _CLOUD_SYNC_LOCK_TIMEOUT_SECONDS,
    _OAUTH_CREDENTIAL_LOCK_TIMEOUT_SECONDS,
    _OAUTH_REFRESH_LOCK_TIMEOUT_SECONDS,
)

if TYPE_CHECKING:
    from .store_connection_columns import StoreConnectionColumnsMixin


class StoreConnectionLifecycleMixin:
    if TYPE_CHECKING:
        # The composed facade owns these defaults and the column methods.
        _startup_prefetched_policy_integrity_secret_material: object = None
        _startup_prefetched_policy_integrity_trusted_state: object = None
        _startup_prefetched_policy_integrity_repair_failed: bool = False
        _ensure_approval_column = StoreConnectionColumnsMixin._ensure_approval_column
        _schema_version_applied = StoreConnectionColumnsMixin._schema_version_applied
        _record_schema_version = StoreConnectionColumnsMixin._record_schema_version

    @contextmanager
    def hold_oauth_refresh_lock(
        self,
        *,
        timeout_seconds: float = _OAUTH_REFRESH_LOCK_TIMEOUT_SECONDS,
    ) -> _schema.Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "oauth-refresh.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_schema._OAUTH_REFRESH_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard OAuth refresh lock.",
        ):
            yield

    @contextmanager
    def hold_cloud_sync_lock(
        self,
        *,
        timeout_seconds: float = _CLOUD_SYNC_LOCK_TIMEOUT_SECONDS,
    ) -> _schema.Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "cloud-sync.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_schema._CLOUD_SYNC_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard Cloud sync lock.",
        ):
            yield

    @contextmanager
    def hold_oauth_credential_lock(
        self,
        *,
        timeout_seconds: float = _OAUTH_CREDENTIAL_LOCK_TIMEOUT_SECONDS,
    ) -> _schema.Iterator[None]:
        with self._hold_advisory_file_lock(
            path=self.guard_home / "oauth-credentials.lock",
            timeout_seconds=timeout_seconds,
            poll_seconds=_schema._OAUTH_CREDENTIAL_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for Guard OAuth credential lock.",
        ):
            yield

    @contextmanager
    def hold_workflow_capability_authority_lock(self) -> _schema.Iterator[None]:
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
        path: _schema.Path,
        timeout_seconds: float,
        poll_seconds: float,
        timeout_message: str,
    ) -> _schema.Iterator[None]:
        deadline = _schema.time.monotonic() + max(timeout_seconds, 0.0)
        with path.open("a+b") as handle:
            while True:
                try:
                    _schema._acquire_advisory_file_lock(handle)
                    break
                except BlockingIOError:
                    if _schema.time.monotonic() >= deadline:
                        raise TimeoutError(timeout_message) from None
                    _schema.time.sleep(poll_seconds)
            try:
                yield
            finally:
                with _schema.suppress(OSError):
                    _schema._release_advisory_file_lock(handle)

    def cloud_sync_in_progress(self) -> bool:
        lock_path = self.guard_home / "cloud-sync.lock"
        with lock_path.open("a+b") as handle:
            try:
                # This is an advisory probe, not a reservation: callers must still
                # acquire hold_cloud_sync_lock() for the actual sync critical section.
                _schema._acquire_advisory_file_lock(handle)
            except BlockingIOError:
                return True
            try:
                return False
            finally:
                with _schema.suppress(OSError):
                    _schema._release_advisory_file_lock(handle)

    def _initialize_serialized(self) -> None:
        try:
            self._initialize_serialized_once()
        except _schema.sqlite3.DatabaseError as error:
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
        timeout_seconds = _schema.sqlite_connect_timeout_seconds()
        deadline = _schema.time.monotonic() + timeout_seconds
        path_key = str(self.path.absolute())
        with self._schema_initialization_locks_guard:
            state = self._schema_initialization_states.setdefault(path_key, _schema._SchemaInitializationState())
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
                remaining_seconds = max(0.0, deadline - _schema.time.monotonic())
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
        statements = _schema.connection_schema_statements()
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
            _schema.store_native_decision_receipts.ensure_native_command_receipt_binding_schema(
                connection, applied_at=_schema._now()
            )
            _schema.ensure_resume_schema(connection)
            _schema.ensure_command_activity_schema(connection, applied_at=_schema._now())
            _schema.ensure_command_activity_health_schema(connection, applied_at=_schema._now())
            _schema.ensure_command_activity_maintenance_schema(connection, applied_at=_schema._now())
            _schema.ensure_command_activity_api_schema(connection, applied_at=_schema._now())
            _schema.ensure_command_activity_display_schema(connection, applied_at=_schema._now())
            _schema.ensure_evidence_schema(connection)
            _schema.ensure_extension_control_authority_schema(connection, require_compatible=False)
            _schema.ensure_local_cli_schema(connection)
            _schema.ensure_workflow_capability_schema(connection, applied_at=_schema._now())
            _schema.ensure_command_shadow_schema(connection, applied_at=_schema._now())
            _schema.ensure_mcp_policy_request_schema(connection)
            if not self._schema_version_applied(connection, version=4):
                self._record_schema_version(connection, version=4)
            for idx_stmt in _schema.supply_chain_index_statements():
                connection.execute(idx_stmt)
            for idx_stmt in _schema.threat_intel_index_statements():
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
            for index_statement in _schema._POLICY_INDEX_STATEMENTS:
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
            _schema.ensure_watch_only_approval_schema(connection, schema=self)
            if not self._schema_version_applied(connection, version=3):
                _schema._backfill_approval_queue_columns_compat(connection)
                self._record_schema_version(connection, version=3)
            if not self._schema_version_applied(connection, version=9):
                connection.execute("drop index if exists idx_approval_group_status")
            for idx_stmt in _schema.approval_index_statements():
                connection.execute(idx_stmt)
            _schema.ensure_review_event_outbox_schema(
                connection, _schema.datetime.now(_schema.timezone.utc).isoformat()
            )
            if not self._schema_version_applied(connection, version=9):
                self._record_schema_version(connection, version=9)
            for idx_stmt in _schema.receipt_index_statements():
                connection.execute(idx_stmt)
            for statement in _schema.receipt_rollup_schema_statements():
                connection.execute(statement)
            for idx_stmt in _schema.receipt_rollup_index_statements():
                connection.execute(idx_stmt)
            if not self._schema_version_applied(connection, version=6):
                if _schema.receipt_rollups_need_backfill(connection):
                    _schema.backfill_receipt_rollups(connection)
                self._record_schema_version(connection, version=6)
            if not self._schema_version_applied(
                connection,
                version=_schema._RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
            ):
                # P45 changes ``warn`` from the reviewed bucket to allowed.
                # Existing v6 rollups can have the right total while retaining
                # the old bucket semantics, so this migration must rebuild them
                # unconditionally before incremental deltas are applied.
                _schema.backfill_receipt_rollups(connection)
                self._record_schema_version(
                    connection,
                    version=_schema._RECEIPT_WARN_ROLLUP_MIGRATION_VERSION,
                )
            if not self._schema_version_applied(connection, version=7):
                self._record_schema_version(connection, version=7)
            if not self._schema_version_applied(connection, version=8):
                self._record_schema_version(connection, version=8)
            self._ensure_attachment_column(connection, "lease_id", "text not null default ''")
            self._ensure_attachment_column(connection, "lease_expires_at", "text")
            self._ensure_local_device(connection)
            for statement in _schema.storage_maintenance_schema_statements():
                connection.execute(statement)
            self._record_schema_version(
                connection,
                version=_schema.STORAGE_MAINTENANCE_MIGRATION_VERSION,
            )
            self._record_schema_version(
                connection,
                version=_schema.STORAGE_QUERY_INDEX_MIGRATION_VERSION,
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
                    self._refresh_policy_integrity_state(connection, now=_schema._now(), create_key=False)
            finally:
                self._startup_prefetched_policy_integrity_secret_material = _schema._POLICY_INTEGRITY_LOOKUP_UNSET
                self._startup_prefetched_policy_integrity_trusted_state = _schema._POLICY_INTEGRITY_LOOKUP_UNSET
                self._startup_prefetched_policy_integrity_repair_failed = False

    def _schema_is_current(self) -> bool:
        if not self.path.is_file():
            return False
        timeout_seconds = _schema.sqlite_connect_timeout_seconds()
        try:
            with self._hold_storage_gate(exclusive=False):
                connection = _schema.sqlite3.connect(self.path, timeout=timeout_seconds)
                try:
                    connection.execute(f"pragma busy_timeout={int(timeout_seconds * 1000)}")
                    placeholders = ", ".join("?" for _ in _schema._REQUIRED_SCHEMA_MIGRATION_VERSIONS)
                    row = connection.execute(
                        f"select count(*) from schema_migrations where version in ({placeholders})",
                        _schema._REQUIRED_SCHEMA_MIGRATION_VERSIONS,
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
                        and int(row[0]) == len(_schema._REQUIRED_SCHEMA_MIGRATION_VERSIONS)
                        and storage_row is not None
                        and "oauth_source" in approval_columns
                        and required_approval_columns <= approval_columns
                    )
                finally:
                    connection.close()
        except _schema.sqlite3.DatabaseError:
            return False


# Defer facade access until these method bodies run, preserving live patch points.
from . import store_connection_schema as _schema  # noqa: E402
