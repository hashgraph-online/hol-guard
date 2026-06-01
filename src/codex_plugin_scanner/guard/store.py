"""SQLite-backed local Guard persistence."""

from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from .approval_gate import ApprovalGateGrant, require_policy_clear, require_policy_write, require_request_resolution
from .edge_events import build_receipt_event
from .models import GuardApprovalRequest, GuardArtifact, GuardReceipt, GuardRuntimeState, PolicyDecision
from .runtime.scanner_cache import scanner_cache_key
from .schemas.guard_event_v1 import GuardEventV1
from .store_approvals import (
    _json_object_list,
    approval_index_statements,
    approval_schema_statement,
    backfill_approval_queue_columns,
)
from .store_approvals import (
    add_approval_request as persist_approval_request,
)
from .store_approvals import (
    bulk_resolve_approval_requests as persist_bulk_resolution,
)
from .store_approvals import (
    count_approval_requests as count_pending_approval_requests,
)
from .store_approvals import (
    get_approval_request as load_approval_request,
)
from .store_approvals import (
    get_next_pending_request as load_next_pending_request,
)
from .store_approvals import (
    list_approval_request_page as load_approval_request_page,
)
from .store_approvals import (
    list_approval_requests as load_approval_requests,
)
from .store_approvals import (
    list_pending_approval_summaries as load_pending_approval_summaries,
)
from .store_approvals import (
    resolve_approval_request as persist_approval_resolution,
)
from .store_approvals import (
    resolve_matching_duplicate_requests as persist_duplicate_resolutions,
)
from .store_approvals import (
    resolve_one_request_only as persist_one_resolution,
)
from .store_approvals import (
    resolve_request_with_queue_result as persist_queue_resolution,
)
from .store_connect import (
    connect_request_schema_statement,
    connect_state_schema_statement,
    load_connect_state,
)
from .store_connect import (
    get_latest_connect_state as load_latest_connect_state,
)
from .store_connect import (
    mark_connect_result as persist_connect_result,
)
from .store_evidence import (
    EvidenceRecord,
    evidence_index_statements,
    evidence_schema_statement,
)
from .store_evidence import (
    list_evidence as _list_evidence_impl,
)
from .store_evidence import (
    store_evidence as _store_evidence_impl,
)
from .store_resume import (
    delete_request_resumes as purge_request_resumes,
)
from .store_resume import (
    get_latest_request_resume as load_latest_request_resume,
)
from .store_resume import (
    get_request_resume as load_request_resume,
)
from .store_resume import (
    resume_schema_statement,
)
from .store_resume import (
    seed_request_resume as persist_request_resume_seed,
)
from .store_resume import (
    update_request_resume as persist_request_resume_update,
)
from .store_supply_chain import (
    get_supply_chain_bundle as load_supply_chain_bundle,
)
from .store_supply_chain import (
    get_supply_chain_evaluation as load_supply_chain_evaluation,
)
from .store_supply_chain import (
    supply_chain_bundle_schema_statement,
    supply_chain_eval_cache_schema_statement,
    supply_chain_index_statements,
)
from .store_supply_chain import (
    upsert_supply_chain_bundle as persist_supply_chain_bundle,
)
from .store_supply_chain import (
    upsert_supply_chain_evaluation as persist_supply_chain_evaluation,
)
from .store_threat_intel import (
    threat_intel_bundle_schema_statement,
    threat_intel_index_statements,
    threat_intel_matches_schema_statement,
)
from .types import CapabilitySet

_SYNC_TOKEN_REF = "guard-cloud-token"
_OAUTH_REFRESH_TOKEN_REF = "guard-oauth-refresh-token"
_OAUTH_DPOP_PRIVATE_KEY_REF = "guard-oauth-dpop-private-key"
_SYNC_TOKEN_HASH_KEY = "token_sha256"
_OAUTH_LOCAL_CREDENTIALS_STATE_KEY = "oauth_local_credentials"
_DEVICE_ROW_KEY = "local-device"
_MAX_RESOLVED_SCOPE_IDS = 200
_SQLITE_ID_BATCH_SIZE = 500
_WORKSPACE_POLICY_KEY_PREFIX = "workspace:"
_SCOPED_HARNESS_FAMILIES = frozenset(
    {"file-read", "mcp-tool", "prompt", "prompt-env-read", "prompt-file", "tool-action"}
)
_POLICY_SCOPES = frozenset({"artifact", "workspace", "publisher", "harness", "global"})


def _token_sha256(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class SecretStore(Protocol):
    """Credential persistence contract for local Guard secrets."""

    def set_secret(self, secret_id: str, value: str) -> None:
        """Store a secret value."""

    def get_secret(self, secret_id: str) -> str | None:
        """Fetch a secret value."""


class KeychainSecretStore:
    """macOS keychain-backed secret store."""

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name

    @staticmethod
    def _is_available() -> bool:
        return os.name == "posix" and Path("/usr/bin/security").exists()

    def set_secret(self, secret_id: str, value: str) -> None:
        if not self._is_available():
            raise RuntimeError("macOS keychain command is not available")
        prompt_payload = f"{value}\n{value}\n"
        subprocess.run(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-a",
                secret_id,
                "-s",
                self.service_name,
                "-U",
                "-w",
            ],
            check=True,
            capture_output=True,
            text=True,
            input=prompt_payload,
        )

    def get_secret(self, secret_id: str) -> str | None:
        if not self._is_available():
            return None
        result = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a",
                secret_id,
                "-s",
                self.service_name,
                "-w",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None
        value = result.stdout.rstrip("\r\n")
        return value if value else None


class EncryptedFileSecretStore:
    """Encrypted file-based secret store for predictable cross-platform Guard credentials.

    This keeps sync tokens out of plaintext SQLite and avoids OS-specific keychain prompts
    during CLI flows. The Fernet key and encrypted payloads both live inside the same
    per-user Guard directory, so this is a portability and encrypted-at-rest improvement,
    not stronger isolation than an OS keychain against same-user local compromise.
    """

    def __init__(self, guard_home: Path) -> None:
        self.base_dir = guard_home / "secrets"
        self.key_path = self.base_dir / "key.bin"
        self._fernet: Fernet | None = None

    def _ensure_ready(self) -> None:
        if self._fernet is not None:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base_dir, 0o700)
        if not self.key_path.exists():
            self._atomic_write_bytes(self.key_path, Fernet.generate_key(), 0o600)
        self._fernet = Fernet(self._load_fernet_key())

    def set_secret(self, secret_id: str, value: str) -> None:
        self._ensure_ready()
        payload = self._encrypt_fernet(value)
        path = self._path_for(secret_id)
        self._atomic_write_text(path, json.dumps(payload), 0o600)

    def get_secret(self, secret_id: str) -> str | None:
        self._ensure_ready()
        path = self._path_for(secret_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        value = self._decrypt_fernet(payload)
        if value is not None:
            return value
        legacy_value = self._decrypt_legacy_payload(payload)
        if legacy_value is None:
            return None
        self.set_secret(secret_id, legacy_value)
        return legacy_value

    def _path_for(self, secret_id: str) -> Path:
        normalized = secret_id.replace("/", "_").replace(":", "_")
        return self.base_dir / f"{normalized}.enc"

    def _load_fernet_key(self) -> bytes:
        existing = self.key_path.read_bytes().strip()
        if not existing:
            key = Fernet.generate_key()
            self._atomic_write_bytes(self.key_path, key, 0o600)
            return key
        try:
            decoded = base64.urlsafe_b64decode(existing)
        except (ValueError, TypeError):
            decoded = b""
        if len(decoded) == 32:
            if len(existing) == 32:
                upgraded = base64.urlsafe_b64encode(existing)
                self._atomic_write_bytes(self.key_path, upgraded, 0o600)
                return upgraded
            return existing
        if len(existing) == 32:
            upgraded = base64.urlsafe_b64encode(existing)
            self._atomic_write_bytes(self.key_path, upgraded, 0o600)
            return upgraded
        key = Fernet.generate_key()
        self._atomic_write_bytes(self.key_path, key, 0o600)
        return key

    def _atomic_write_bytes(self, path: Path, payload: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with tmp_path.open("wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _atomic_write_text(self, path: Path, payload: str, mode: int) -> None:
        self._atomic_write_bytes(path, payload.encode("utf-8"), mode)

    def _encrypt_fernet(self, value: str) -> dict[str, str]:
        fernet = self._fernet
        if fernet is None:
            raise RuntimeError("secret store is not initialized")
        token = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return {
            "version": "fernet-v1",
            "ciphertext": token,
        }

    def _decrypt_fernet(self, payload: dict[str, object]) -> str | None:
        version = payload.get("version")
        ciphertext_value = payload.get("ciphertext")
        if version != "fernet-v1" or not isinstance(ciphertext_value, str):
            return None
        fernet = self._fernet
        if fernet is None:
            return None
        try:
            plaintext = fernet.decrypt(ciphertext_value.encode("ascii"))
        except (InvalidToken, ValueError, TypeError):
            return None
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _decrypt_legacy_payload(self, payload: dict[str, object]) -> str | None:
        nonce_value = payload.get("nonce")
        ciphertext_value = payload.get("ciphertext")
        if not isinstance(nonce_value, str) or not isinstance(ciphertext_value, str):
            return None
        try:
            nonce = base64.urlsafe_b64decode(nonce_value.encode("ascii"))
            ciphertext = base64.urlsafe_b64decode(ciphertext_value.encode("ascii"))
            key = base64.urlsafe_b64decode(self._load_fernet_key())
        except (ValueError, TypeError):
            return None
        keystream = _expand_keystream(key=key, nonce=nonce, length=len(ciphertext))
        plaintext = bytes(item ^ mask for item, mask in zip(ciphertext, keystream, strict=True))
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None


class FallbackSecretStore:
    """Fallback-capable secret store that tolerates primary backend failures."""

    def __init__(self, primary: SecretStore, fallback: SecretStore) -> None:
        self.primary = primary
        self.fallback = fallback

    def set_secret(self, secret_id: str, value: str) -> None:
        try:
            self.primary.set_secret(secret_id, value)
        except Exception:
            self.fallback.set_secret(secret_id, value)

    def get_secret(self, secret_id: str) -> str | None:
        try:
            primary_value = self.primary.get_secret(secret_id)
        except Exception:
            primary_value = None
        if primary_value is not None:
            return primary_value
        try:
            return self.fallback.get_secret(secret_id)
        except Exception:
            return None

    def promote_secret(self, secret_id: str, value: str) -> None:
        try:
            primary_value = self.primary.get_secret(secret_id)
        except Exception:
            primary_value = None
        if primary_value == value:
            return
        try:
            self.primary.set_secret(secret_id, value)
        except Exception:
            return


def _expand_keystream(*, key: bytes, nonce: bytes, length: int) -> bytes:
    chunks: list[bytes] = []
    generated = 0
    counter = 0
    while generated < length:
        counter_bytes = counter.to_bytes(4, byteorder="big", signed=False)
        digest = sha256(key + nonce + counter_bytes).digest()
        chunks.append(digest)
        generated += len(digest)
        counter += 1
    return b"".join(chunks)[:length]


def _build_secret_store(guard_home: Path) -> SecretStore:
    fallback_store = EncryptedFileSecretStore(guard_home)
    if KeychainSecretStore._is_available():
        return FallbackSecretStore(fallback_store, KeychainSecretStore(service_name="hol-guard.sync"))
    return fallback_store


def _build_oauth_secret_store(guard_home: Path) -> SecretStore:
    fallback_store = EncryptedFileSecretStore(guard_home)
    if KeychainSecretStore._is_available():
        return FallbackSecretStore(
            KeychainSecretStore(service_name="hol-guard.oauth"),
            fallback_store,
        )
    return fallback_store


def _secret_store_backend_name(secret_store: SecretStore) -> str:
    if isinstance(secret_store, KeychainSecretStore):
        return "keychain"
    if isinstance(secret_store, EncryptedFileSecretStore):
        return "encrypted-file"
    if isinstance(secret_store, FallbackSecretStore):
        return _secret_store_backend_name(secret_store.primary)
    return "unknown"


def _secret_store_fallback_backend_name(secret_store: SecretStore) -> str | None:
    if isinstance(secret_store, FallbackSecretStore):
        return _secret_store_backend_name(secret_store.fallback)
    return None


_SLOW_QUERY_THRESHOLD_MS: int = 200
_store_logger = logging.getLogger(__name__)


class GuardStore:
    """Local SQLite store for Guard state."""

    def __init__(self, guard_home: Path, *, guard_event_queue_limit: int = 1000) -> None:
        self.guard_home = guard_home
        self.guard_home.mkdir(parents=True, exist_ok=True)
        self._secret_store = _build_secret_store(self.guard_home)
        self._oauth_secret_store = _build_oauth_secret_store(self.guard_home)
        self._sync_token_ref = self._build_scoped_secret_ref(_SYNC_TOKEN_REF)
        self._oauth_refresh_token_ref = self._build_scoped_secret_ref(_OAUTH_REFRESH_TOKEN_REF)
        self._oauth_dpop_private_key_ref = self._build_scoped_secret_ref(_OAUTH_DPOP_PRIVATE_KEY_REF)
        self._guard_event_queue_limit = max(1, guard_event_queue_limit)
        self.path = self.guard_home / "guard.db"
        self._initialize()

    def _build_scoped_secret_ref(self, prefix: str) -> str:
        scoped_home = str(self.guard_home.expanduser().resolve())
        scoped_hash = sha256(scoped_home.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}:{scoped_hash}"

    @staticmethod
    def _versioned_secret_ref(base_ref: str, value_hash: str) -> str:
        return f"{base_ref}:{value_hash[:16]}"

    def _promote_secret_to_primary(self, secret_store: SecretStore, secret_id: str, value: str) -> None:
        if isinstance(secret_store, FallbackSecretStore):
            secret_store.promote_secret(secret_id, value)

    def _get_secret_from_store(self, store: SecretStore, secret_id: str) -> str | None:
        try:
            return store.get_secret(secret_id)
        except Exception:
            return None

    def _get_secret_candidates(
        self,
        secret_store: SecretStore,
        secret_id: str,
        expected_hash_value: str | None,
    ) -> list[str]:
        if isinstance(secret_store, FallbackSecretStore):
            primary_token = self._get_secret_from_store(secret_store.primary, secret_id)
            if primary_token is not None:
                if expected_hash_value is None or _token_sha256(primary_token) == expected_hash_value:
                    return [primary_token]
                fallback_token = self._get_secret_from_store(secret_store.fallback, secret_id)
                if fallback_token is None or fallback_token == primary_token:
                    return [primary_token]
                return [primary_token, fallback_token]
            fallback_token = self._get_secret_from_store(secret_store.fallback, secret_id)
            if fallback_token is None:
                return []
            return [fallback_token]
        token = secret_store.get_secret(secret_id)
        if token is None:
            return []
        return [token]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        start = time.monotonic()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()
            elapsed_ms = (time.monotonic() - start) * 1000
            if elapsed_ms >= _SLOW_QUERY_THRESHOLD_MS:
                _store_logger.warning(
                    "Guard store slow transaction (%.0fms); consider indexing hot query paths.",
                    elapsed_ms,
                )

    def _initialize(self) -> None:
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
              timestamp text not null
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
            resume_schema_statement(),
            connect_state_schema_statement(),
            connect_request_schema_statement(),
            connect_state_schema_statement(),
            approval_schema_statement(),
            evidence_schema_statement(),
            supply_chain_bundle_schema_statement(),
            supply_chain_eval_cache_schema_statement(),
            threat_intel_bundle_schema_statement(),
            threat_intel_matches_schema_statement(),
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)
            if not self._schema_version_applied(connection, version=4):
                self._ensure_column(connection, "guard_evidence", "action_identity", "text")
                self._record_schema_version(connection, version=4)
            for idx_stmt in evidence_index_statements():
                connection.execute(idx_stmt)
            for idx_stmt in supply_chain_index_statements():
                connection.execute(idx_stmt)
            for idx_stmt in threat_intel_index_statements():
                connection.execute(idx_stmt)
            self._ensure_policy_column(connection, "publisher", "text")
            self._ensure_policy_column(connection, "artifact_hash", "text")
            self._ensure_policy_column(connection, "owner", "text")
            self._ensure_policy_column(connection, "source", "text not null default 'local'")
            self._ensure_policy_column(connection, "expires_at", "text")
            self._ensure_runtime_receipts_column(connection, "capabilities_summary", "text not null default ''")
            self._ensure_runtime_receipts_column(connection, "scanner_evidence_json", "text not null default '[]'")
            self._ensure_runtime_receipts_column(connection, "diff_summary", "text")
            self._ensure_runtime_receipts_column(connection, "approval_source", "text")
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
            self._ensure_approval_column(connection, "desktop_notified_at", "text")
            if not self._schema_version_applied(connection, version=3):
                backfill_approval_queue_columns(connection)
                self._record_schema_version(connection, version=3)
            for idx_stmt in approval_index_statements():
                connection.execute(idx_stmt)
            self._ensure_attachment_column(connection, "lease_id", "text not null default ''")
            self._ensure_attachment_column(connection, "lease_expires_at", "text")
            self._ensure_local_device(connection)
            if not self._schema_version_applied(connection, version=2):
                self._record_schema_version(connection, version=2)

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

    def save_scanner_cache(
        self,
        *,
        scanner_name: str,
        target_id: str,
        input_content_hash: str,
        scanner_version: str,
        payload: dict[str, object],
        now: str,
    ) -> None:
        cache_key = scanner_cache_key(
            scanner_name=scanner_name,
            input_content_hash=input_content_hash,
            scanner_version=scanner_version,
        )
        with self._connect() as connection:
            connection.execute(
                """
                insert into scanner_cache (
                  scanner_name, target_id, cache_key, input_content_hash, scanner_version, payload_json, updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?)
                on conflict(scanner_name, target_id) do update set
                  cache_key = excluded.cache_key,
                  input_content_hash = excluded.input_content_hash,
                  scanner_version = excluded.scanner_version,
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (
                    scanner_name,
                    target_id,
                    cache_key,
                    input_content_hash,
                    scanner_version,
                    json.dumps(payload, sort_keys=True),
                    now,
                ),
            )

    def get_scanner_cache(
        self,
        *,
        scanner_name: str,
        target_id: str,
        input_content_hash: str,
        scanner_version: str,
    ) -> dict[str, object] | None:
        cache_key = scanner_cache_key(
            scanner_name=scanner_name,
            input_content_hash=input_content_hash,
            scanner_version=scanner_version,
        )
        with self._connect() as connection:
            row = connection.execute(
                """
                select payload_json from scanner_cache
                where scanner_name = ? and target_id = ? and cache_key = ?
                """,
                (scanner_name, target_id, cache_key),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        return payload if isinstance(payload, dict) else None

    def save_snapshot(
        self,
        harness: str,
        artifact_id: str,
        snapshot: dict[str, object],
        artifact_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_snapshots (artifact_id, harness, snapshot_json, artifact_hash, recorded_at)
                values (?, ?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  snapshot_json = excluded.snapshot_json,
                  artifact_hash = excluded.artifact_hash,
                  recorded_at = excluded.recorded_at
                """,
                (artifact_id, harness, json.dumps(snapshot), artifact_hash, now),
            )
            connection.execute(
                "insert into artifact_hashes (artifact_id, harness, artifact_hash, recorded_at) values (?, ?, ?, ?)",
                (artifact_id, harness, artifact_hash, now),
            )

    def get_snapshot(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select snapshot_json from artifact_snapshots where artifact_id = ? and harness = ?",
                (artifact_id, harness),
            ).fetchone()
        if row is None:
            return None
        return json.loads(str(row["snapshot_json"]))

    def list_snapshots(self, harness: str) -> dict[str, dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "select artifact_id, snapshot_json from artifact_snapshots where harness = ?",
                (harness,),
            ).fetchall()
        return {str(row["artifact_id"]): json.loads(str(row["snapshot_json"])) for row in rows}

    def delete_snapshot(self, harness: str, artifact_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "delete from artifact_snapshots where artifact_id = ? and harness = ?",
                (artifact_id, harness),
            )

    def record_diff(
        self,
        harness: str,
        artifact_id: str,
        changed_fields: list[str],
        previous_hash: str | None,
        current_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_diffs (
                  artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at
                )
                values (?, ?, ?, ?, ?, ?)
                """,
                (artifact_id, harness, json.dumps(changed_fields), previous_hash, current_hash, now),
            )

    def record_inventory_artifact(
        self,
        *,
        artifact: GuardArtifact,
        artifact_hash: str,
        policy_action: str,
        changed: bool,
        now: str,
        approved: bool,
    ) -> None:
        launch_command = None
        if artifact.command:
            launch_command = " ".join([artifact.command, *artifact.args]).strip()
        with self._connect() as connection:
            existing = connection.execute(
                """
                select first_seen_at from artifact_inventory where artifact_id = ? and harness = ?
                """,
                (artifact.artifact_id, artifact.harness),
            ).fetchone()
            first_seen_at = str(existing["first_seen_at"]) if existing is not None else now
            last_changed_at = now if changed else None
            last_approved_at = now if approved else None
            connection.execute(
                """
                insert into artifact_inventory (
                  artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                  origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                  last_approved_at, removed_at, present, last_policy_action, artifact_hash
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  artifact_name = excluded.artifact_name,
                  artifact_type = excluded.artifact_type,
                  source_scope = excluded.source_scope,
                  config_path = excluded.config_path,
                  publisher = excluded.publisher,
                  origin_url = excluded.origin_url,
                  launch_command = excluded.launch_command,
                  transport = excluded.transport,
                  last_seen_at = excluded.last_seen_at,
                  last_changed_at = coalesce(excluded.last_changed_at, artifact_inventory.last_changed_at),
                  last_approved_at = coalesce(excluded.last_approved_at, artifact_inventory.last_approved_at),
                  removed_at = null,
                  present = 1,
                  last_policy_action = excluded.last_policy_action,
                  artifact_hash = excluded.artifact_hash
                """,
                (
                    artifact.artifact_id,
                    artifact.harness,
                    artifact.name,
                    artifact.artifact_type,
                    artifact.source_scope,
                    artifact.config_path,
                    artifact.publisher,
                    artifact.url,
                    launch_command,
                    artifact.transport,
                    first_seen_at,
                    now,
                    last_changed_at,
                    last_approved_at,
                    None,
                    1,
                    policy_action,
                    artifact_hash,
                ),
            )

    def mark_inventory_removed(
        self,
        *,
        harness: str,
        artifact_id: str,
        policy_action: str,
        artifact_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update artifact_inventory
                set last_seen_at = ?, last_changed_at = ?, removed_at = ?, present = 0,
                    last_policy_action = ?, artifact_hash = ?
                where artifact_id = ? and harness = ?
                """,
                (now, now, now, policy_action, artifact_hash, artifact_id, harness),
            )

    def list_inventory(self, harness: str | None = None) -> list[dict[str, object]]:
        query = """
            select artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                   origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                   last_approved_at, removed_at, present, last_policy_action, artifact_hash
            from artifact_inventory
        """
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        query += " order by harness asc, artifact_name asc"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "artifact_id": str(row["artifact_id"]),
                "harness": str(row["harness"]),
                "artifact_name": str(row["artifact_name"]),
                "artifact_type": str(row["artifact_type"]),
                "source_scope": str(row["source_scope"]),
                "config_path": str(row["config_path"]),
                "publisher": row["publisher"],
                "origin_url": row["origin_url"],
                "launch_command": row["launch_command"],
                "transport": row["transport"],
                "first_seen_at": str(row["first_seen_at"]),
                "last_seen_at": str(row["last_seen_at"]),
                "last_changed_at": row["last_changed_at"],
                "last_approved_at": row["last_approved_at"],
                "removed_at": row["removed_at"],
                "present": bool(row["present"]),
                "last_policy_action": str(row["last_policy_action"]),
                "artifact_hash": str(row["artifact_hash"]),
            }
            for row in rows
        ]

    def find_inventory_item(self, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                       origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                       last_approved_at, removed_at, present, last_policy_action, artifact_hash
                from artifact_inventory
                where artifact_id = ?
                order by last_seen_at desc
                limit 1
                """,
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifact_id": str(row["artifact_id"]),
            "harness": str(row["harness"]),
            "artifact_name": str(row["artifact_name"]),
            "artifact_type": str(row["artifact_type"]),
            "source_scope": str(row["source_scope"]),
            "config_path": str(row["config_path"]),
            "publisher": row["publisher"],
            "origin_url": row["origin_url"],
            "launch_command": row["launch_command"],
            "transport": row["transport"],
            "first_seen_at": str(row["first_seen_at"]),
            "last_seen_at": str(row["last_seen_at"]),
            "last_changed_at": row["last_changed_at"],
            "last_approved_at": row["last_approved_at"],
            "removed_at": row["removed_at"],
            "present": bool(row["present"]),
            "last_policy_action": str(row["last_policy_action"]),
            "artifact_hash": str(row["artifact_hash"]),
        }

    def save_artifact_capability(
        self,
        *,
        harness: str,
        artifact_id: str,
        capability_snapshot: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_capabilities (artifact_id, harness, capability_json, updated_at)
                values (?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  capability_json = excluded.capability_json,
                  updated_at = excluded.updated_at
                """,
                (artifact_id, harness, json.dumps(capability_snapshot), now),
            )

    def get_artifact_capability(self, harness: str, artifact_id: str) -> CapabilitySet | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select capability_json
                from artifact_capabilities
                where artifact_id = ? and harness = ?
                """,
                (artifact_id, harness),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["capability_json"]))
        if not isinstance(payload, dict):
            return None
        return CapabilitySet(
            network_hosts=tuple(_string_list(payload.get("network_hosts"))),
            network_schemes=tuple(_string_list(payload.get("network_schemes"))),
            filesystem_paths=tuple(_string_list(payload.get("filesystem_paths"))),
            secret_classes=tuple(_string_list(payload.get("secret_classes"))),
            subprocess_invocation=bool(payload.get("subprocess_invocation")),
            interpreters=tuple(_string_list(payload.get("interpreters"))),
            shell_wrappers=tuple(_string_list(payload.get("shell_wrappers"))),
            publisher=payload.get("publisher") if isinstance(payload.get("publisher"), str) else None,
            transport=_transport_value(payload.get("transport")),
        )

    def upsert_provenance_cache(self, *, artifact_hash: str, payload: dict[str, object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into provenance_cache (artifact_hash, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(artifact_hash) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (artifact_hash, json.dumps(payload), now),
            )

    def get_provenance_cache(self, artifact_hash: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select payload_json from provenance_cache where artifact_hash = ?",
                (artifact_hash,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        return payload if isinstance(payload, dict) else None

    def get_or_create_installation_id(self) -> str:
        with self._connect() as connection:
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Guard local device row was not initialized.")
        return str(row["installation_id"])

    def set_device_label(self, label: str, now: str) -> dict[str, str]:
        normalized_label = label.strip() or "Local machine"
        with self._connect() as connection:
            self._ensure_local_device(connection)
            connection.execute(
                """
                update guard_devices
                set device_label = ?, updated_at = ?
                where device_key = ?
                """,
                (normalized_label, now, _DEVICE_ROW_KEY),
            )
        return self.get_device_metadata()

    def rotate_installation_id(self, now: str) -> dict[str, str]:
        new_installation_id = uuid4().hex
        with self._connect() as connection:
            self._ensure_local_device(connection)
            connection.execute(
                """
                update guard_devices
                set installation_id = ?, updated_at = ?
                where device_key = ?
                """,
                (new_installation_id, now, _DEVICE_ROW_KEY),
            )
        return self.get_device_metadata()

    def get_device_metadata(self) -> dict[str, str]:
        with self._connect() as connection:
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id, device_label from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Guard local device metadata is unavailable.")
        return {
            "installation_id": str(row["installation_id"]),
            "device_label": str(row["device_label"]),
        }

    def get_cloud_workspace_id(self) -> str | None:
        with self._connect() as connection:
            return self._cloud_workspace_id_from_connection(connection)

    def upsert_policy(
        self,
        decision: PolicyDecision,
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_policy_write(
            self.guard_home,
            decision=decision,
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
        with self._connect() as connection:
            connection.execute(
                """
                delete from policy_decisions
                where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
                  and coalesce(artifact_hash, '') = coalesce(?, '')
                  and coalesce(workspace, '') = coalesce(?, '')
                  and coalesce(publisher, '') = coalesce(?, '')
                """,
                (decision.harness, decision.scope, artifact_id, artifact_hash, workspace, publisher),
            )
            connection.execute(
                """
                insert into policy_decisions (
                  harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                  expires_at, updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    decision.expires_at,
                    now,
                ),
            )

    def replace_remote_policies(
        self,
        decisions: list[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        for decision in decisions:
            require_policy_write(
                self.guard_home,
                decision=decision,
                approval_gate_grant=approval_gate_grant,
                now=now,
            )
        with self._connect() as connection:
            connection.execute("delete from policy_decisions where source in ('cloud-sync', 'team-policy')")
            for decision in decisions:
                artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
                connection.execute(
                    """
                    insert into policy_decisions (
                      harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                      expires_at, updated_at
                    )
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.harness,
                        decision.scope,
                        artifact_id,
                        artifact_hash,
                        workspace,
                        publisher,
                        decision.action,
                        decision.reason,
                        decision.owner,
                        decision.source,
                        decision.expires_at,
                        now,
                    ),
                )

    def resolve_policy(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
    ) -> str | None:
        decision = self.resolve_policy_decision(
            harness,
            artifact_id,
            artifact_hash,
            workspace,
            publisher,
            now,
        )
        return str(decision["action"]) if decision is not None else None

    def resolve_policy_decision(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
    ) -> dict[str, str | None] | None:
        current_time = now or _now()
        workspace_key = _workspace_policy_key(workspace)
        action_family_key = _artifact_family_key(artifact_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                select harness, scope, artifact_id, action, artifact_hash, workspace, publisher, source
                from policy_decisions
                where (harness = ? or harness = '*') and (
                  (
                    scope = 'artifact' and artifact_id = ? and (
                      artifact_hash is null or (? is not null and artifact_hash = ?)
                    )
                  )
                  or (
                    scope = 'workspace' and (workspace = ? or workspace = ?) and (
                      artifact_id is null or (
                        artifact_id = ? and (
                          artifact_hash is null or (? is not null and artifact_hash = ?)
                        )
                      )
                    )
                  )
                  or (scope = 'publisher' and publisher = ?)
                  or (
                    scope = 'harness' and (
                      artifact_id is null or artifact_id = ?
                    )
                  )
                  or scope = 'global'
                )
                and (expires_at is null or expires_at > ?)
                order by case scope when 'artifact' then 0 when 'workspace' then 1 when 'publisher' then 2
                          when 'harness' then 3 else 4 end,
                         case when scope = 'workspace' and artifact_id is not null then 0 else 1 end,
                         updated_at desc
                """,
                (
                    harness,
                    artifact_id,
                    artifact_hash,
                    artifact_hash,
                    workspace_key,
                    workspace,
                    artifact_id,
                    artifact_hash,
                    artifact_hash,
                    publisher,
                    action_family_key,
                    current_time,
                ),
            ).fetchall()
        if not rows:
            return None
        row = rows[0]
        return {
            "harness": row["harness"],
            "scope": row["scope"],
            "artifact_id": row["artifact_id"],
            "artifact_hash": row["artifact_hash"],
            "workspace": row["workspace"],
            "publisher": row["publisher"],
            "action": row["action"],
            "source": row["source"],
        }

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
        if decision.scope == "harness":
            artifact_id = _artifact_family_key(decision.artifact_id)
        else:
            artifact_id = decision.artifact_id if decision.scope in {"artifact", "workspace"} else None
        artifact_hash = decision.artifact_hash if decision.scope in {"artifact", "workspace"} else None
        workspace = _workspace_policy_key(decision.workspace) if decision.scope == "workspace" else None
        publisher = decision.publisher if decision.scope == "publisher" else None
        return artifact_id, artifact_hash, workspace, publisher

    def add_receipt(self, receipt: GuardReceipt) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into runtime_receipts (
                  receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                  changed_capabilities_json,
                  provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                  diff_summary, approval_source, timestamp
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.harness,
                    receipt.artifact_id,
                    receipt.artifact_hash,
                    receipt.policy_decision,
                    receipt.capabilities_summary,
                    json.dumps(list(receipt.changed_capabilities)),
                    receipt.provenance_summary,
                    receipt.user_override,
                    receipt.artifact_name,
                    receipt.source_scope,
                    json.dumps(list(receipt.scanner_evidence), sort_keys=True),
                    receipt.diff_summary,
                    receipt.approval_source,
                    receipt.timestamp,
                ),
            )
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
            device_id = str(row["installation_id"]) if row is not None else None
            workspace_id = self._cloud_workspace_id_from_connection(connection)
            self._add_guard_event_v1(
                connection,
                build_receipt_event(
                    receipt,
                    device_id=device_id,
                    workspace_id=workspace_id,
                ),
            )

    def list_receipts(self, limit: int = 50, harness: str | None = None) -> list[dict[str, object]]:
        if harness is not None:
            query = """
                select rowid as receipt_rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
                       capabilities_summary,
                       changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                       diff_summary, approval_source, timestamp
                from runtime_receipts
                where harness = ?
                order by timestamp desc
                limit ?
                """
            params: tuple[object, ...] = (harness, limit)
        else:
            query = """
                select rowid as receipt_rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
                       capabilities_summary,
                       changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                       diff_summary, approval_source, timestamp
                from runtime_receipts
                order by timestamp desc
                limit ?
                """
            params = (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "receipt_rowid": int(row["receipt_rowid"]),
                "receipt_id": str(row["receipt_id"]),
                "harness": str(row["harness"]),
                "artifact_id": str(row["artifact_id"]),
                "artifact_hash": str(row["artifact_hash"]),
                "policy_decision": str(row["policy_decision"]),
                "capabilities_summary": str(row["capabilities_summary"]),
                "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
                "provenance_summary": str(row["provenance_summary"]),
                "user_override": row["user_override"],
                "artifact_name": row["artifact_name"],
                "source_scope": row["source_scope"],
                "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
                "diff_summary": row["diff_summary"],
                "approval_source": row["approval_source"],
                "timestamp": str(row["timestamp"]),
            }
            for row in rows
        ]

    def list_receipts_since_rowid(
        self,
        *,
        after_rowid: int | None,
        limit: int = 200,
        harness: str | None = None,
    ) -> list[dict[str, object]]:
        if harness is not None:
            query = """
                select rowid as receipt_rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
                       capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
                       artifact_name, source_scope, scanner_evidence_json, diff_summary, approval_source, timestamp
                from runtime_receipts
                where rowid > ? and harness = ?
                order by rowid asc
                limit ?
                """
            params: tuple[object, ...] = (
                after_rowid if after_rowid is not None else 0,
                harness,
                limit,
            )
        else:
            query = """
                select rowid as receipt_rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
                       capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
                       artifact_name, source_scope, scanner_evidence_json, diff_summary, approval_source, timestamp
                from runtime_receipts
                where rowid > ?
                order by rowid asc
                limit ?
                """
            params = (after_rowid if after_rowid is not None else 0, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "receipt_rowid": int(row["receipt_rowid"]),
                "receipt_id": str(row["receipt_id"]),
                "harness": str(row["harness"]),
                "artifact_id": str(row["artifact_id"]),
                "artifact_hash": str(row["artifact_hash"]),
                "policy_decision": str(row["policy_decision"]),
                "capabilities_summary": str(row["capabilities_summary"]),
                "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
                "provenance_summary": str(row["provenance_summary"]),
                "user_override": row["user_override"],
                "artifact_name": row["artifact_name"],
                "source_scope": row["source_scope"],
                "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
                "diff_summary": row["diff_summary"],
                "approval_source": row["approval_source"],
                "timestamp": str(row["timestamp"]),
            }
            for row in rows
        ]

    def latest_receipt_rowid(self, *, harness: str | None = None) -> int | None:
        query = "select max(rowid) as max_rowid from runtime_receipts"
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        if row is None:
            return None
        max_rowid = row["max_rowid"]
        if isinstance(max_rowid, int):
            return max_rowid
        if isinstance(max_rowid, str) and max_rowid.isdigit():
            return int(max_rowid)
        return None

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                        changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                       diff_summary, approval_source, timestamp
                from runtime_receipts
                where receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": str(row["receipt_id"]),
            "harness": str(row["harness"]),
            "artifact_id": str(row["artifact_id"]),
            "artifact_hash": str(row["artifact_hash"]),
            "policy_decision": str(row["policy_decision"]),
            "capabilities_summary": str(row["capabilities_summary"]),
            "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
            "provenance_summary": str(row["provenance_summary"]),
            "user_override": row["user_override"],
            "artifact_name": row["artifact_name"],
            "source_scope": row["source_scope"],
            "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
            "diff_summary": row["diff_summary"],
            "approval_source": row["approval_source"],
            "timestamp": str(row["timestamp"]),
        }

    def get_latest_receipt(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                        changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                       diff_summary, approval_source, timestamp
                from runtime_receipts
                where harness = ? and artifact_id = ?
                order by timestamp desc
                limit 1
                """,
                (harness, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": str(row["receipt_id"]),
            "harness": str(row["harness"]),
            "artifact_id": str(row["artifact_id"]),
            "artifact_hash": str(row["artifact_hash"]),
            "policy_decision": str(row["policy_decision"]),
            "capabilities_summary": str(row["capabilities_summary"]),
            "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
            "provenance_summary": str(row["provenance_summary"]),
            "user_override": row["user_override"],
            "artifact_name": row["artifact_name"],
            "source_scope": row["source_scope"],
            "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
            "diff_summary": row["diff_summary"],
            "approval_source": row["approval_source"],
            "timestamp": str(row["timestamp"]),
        }

    def count_receipts(self, harness: str | None = None) -> int:
        query = "select count(*) as total from runtime_receipts"
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row is not None else 0

    def receipt_decision_counts(self, harness: str, artifact_id: str) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select policy_decision, count(*) as total
                from runtime_receipts
                where harness = ? and artifact_id = ?
                group by policy_decision
                """,
                (harness, artifact_id),
            ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            counts[str(row["policy_decision"])] = int(row["total"])
        return counts

    def upsert_runtime_state(
        self,
        *,
        session_id: str,
        daemon_host: str,
        daemon_port: int,
        started_at: str,
        last_heartbeat_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_runtime_state (
                  state_key, session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                )
                values ('runtime', ?, ?, ?, ?, ?)
                on conflict(state_key) do update set
                  session_id = excluded.session_id,
                  daemon_host = excluded.daemon_host,
                  daemon_port = excluded.daemon_port,
                  started_at = excluded.started_at,
                  last_heartbeat_at = excluded.last_heartbeat_at
                """,
                (session_id, daemon_host, daemon_port, started_at, last_heartbeat_at),
            )

    def touch_runtime_state(self, *, session_id: str, last_heartbeat_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update guard_runtime_state
                set last_heartbeat_at = ?
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (last_heartbeat_at, session_id),
            )

    def get_runtime_state(self) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                from guard_runtime_state
                where state_key = 'runtime'
                """
            ).fetchone()
        if row is None:
            return None
        return GuardRuntimeState(
            session_id=str(row["session_id"]),
            daemon_host=str(row["daemon_host"]),
            daemon_port=int(row["daemon_port"]),
            started_at=str(row["started_at"]),
            last_heartbeat_at=str(row["last_heartbeat_at"]),
        ).to_dict()

    def clear_runtime_state(self, *, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                delete from guard_runtime_state
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (session_id,),
            )

    def add_approval_request(self, request: GuardApprovalRequest, now: str) -> str:
        with self._connect() as connection:
            return persist_approval_request(connection, request, now)

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            return load_approval_requests(
                connection,
                status=status,
                harness=harness,
                limit=limit,
                cursor=cursor,
                search=search,
            )

    def list_pending_approval_summaries(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_pending_approval_summaries(
                connection,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
            )

    def list_approval_request_page(
        self,
        *,
        status: str | None = "pending",
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_approval_request_page(
                connection,
                status=status,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
            )

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_approval_request(connection, request_id)

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select desktop_notified_at
                from approval_requests
                where request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        value = row["desktop_notified_at"]
        return str(value) if isinstance(value, str) and value else None

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update approval_requests
                set desktop_notified_at = ?
                where request_id = ?
                  and desktop_notified_at is null
                """,
                (notified_at, request_id),
            )

    def get_next_pending_request(self, *, exclude_ids: set[str] | None = None) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_next_pending_request(connection, exclude_ids=exclude_ids)

    def resolve_approval_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            persist_approval_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_one_request_only(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> bool:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            return persist_one_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_matching_duplicate_requests(
        self,
        *,
        queue_group_id: str | None,
        request_id: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            return persist_duplicate_resolutions(
                connection,
                queue_group_id=queue_group_id,
                request_id=request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_request_with_queue_result(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> dict[str, object]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            return persist_queue_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_matching_approval_requests(
        self,
        *,
        harness: str | None,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        if scope == "workspace":
            if harness is None or workspace is None:
                return []
            return self._resolve_workspace_matching_approval_requests(
                harness=harness,
                artifact_id=artifact_id,
                workspace=workspace,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
        conditions, params = self._approval_scope_conditions(
            harness=harness,
            scope=scope,
            artifact_id=artifact_id,
            workspace=workspace,
            publisher=publisher,
        )
        if conditions is None:
            return []
        where_clause = " and ".join(["status = 'pending'", *conditions])
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                select request_id
                from approval_requests
                where {where_clause}
                order by last_seen_at desc, request_id desc
                limit ?
                """,
                (*params, _MAX_RESOLVED_SCOPE_IDS),
            ).fetchall()
            connection.execute(
                f"""
                update approval_requests
                set status = 'resolved',
                    resolution_action = ?,
                    resolution_scope = ?,
                    reason = ?,
                    resolved_at = ?
                where {where_clause}
                """,
                (resolution_action, resolution_scope, reason, resolved_at, *params),
            )
        return [str(row["request_id"]) for row in rows]

    @staticmethod
    def _approval_scope_conditions(
        *,
        harness: str | None,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> tuple[list[str] | None, tuple[object, ...]]:
        if scope == "global":
            return [], ()
        if scope == "harness":
            if harness is None:
                return None, ()
            family_key = _artifact_family_key(artifact_id)
            if family_key is None:
                return ["harness = ?"], (harness,)
            return ["harness = ?", "artifact_id like ?"], (harness, f"%:{_family_key_value(family_key)}:%")
        if scope == "artifact":
            if harness is None or artifact_id is None:
                return None, ()
            return ["harness = ?", "artifact_id = ?"], (harness, artifact_id)
        if scope == "publisher":
            if harness is None or publisher is None:
                return None, ()
            return ["harness = ?", "publisher = ?"], (harness, publisher)
        if scope == "workspace":
            return None, ()
        return None, ()

    def _resolve_workspace_matching_approval_requests(
        self,
        *,
        harness: str,
        artifact_id: str | None,
        workspace: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> list[str]:
        with self._connect() as connection:
            connection.execute("begin immediate")
            rows = connection.execute(
                """
                select request_id, artifact_id, config_path
                from approval_requests
                where status = 'pending'
                  and harness = ?
                order by last_seen_at desc, request_id desc
                """,
                (harness,),
            ).fetchall()
            matching_ids = [
                str(row["request_id"])
                for row in rows
                if _path_within_workspace(str(row["config_path"]), workspace)
                and (artifact_id is None or row["artifact_id"] == artifact_id)
            ]
            for chunk in _chunks(matching_ids, _SQLITE_ID_BATCH_SIZE):
                placeholders = ", ".join("?" for _ in chunk)
                connection.execute(
                    f"""
                    update approval_requests
                    set status = 'resolved',
                        resolution_action = ?,
                        resolution_scope = ?,
                        reason = ?,
                        resolved_at = ?
                    where request_id in ({placeholders})
                    """,
                    (resolution_action, resolution_scope, reason, resolved_at, *chunk),
                )
        return matching_ids[:_MAX_RESOLVED_SCOPE_IDS]

    @staticmethod
    def _matches_scope(
        item: dict[str, object],
        *,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> bool:
        if scope == "global":
            return True
        if scope == "harness":
            return True
        if scope == "artifact":
            return str(item["artifact_id"]) == artifact_id
        if scope == "publisher":
            return isinstance(item.get("publisher"), str) and item.get("publisher") == publisher
        if scope == "workspace" and isinstance(workspace, str):
            config_path = str(item.get("config_path") or "")
            return _path_within_workspace(config_path, workspace)
        return False

    def bulk_resolve_approval_requests(
        self,
        request_ids: list[str],
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            persist_bulk_resolution(
                connection,
                request_ids,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def count_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        search: str | None = None,
    ) -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(connection, status=status, harness=harness, search=search)

    def count_pending_requests(self, *, harness: str | None = None, search: str | None = None) -> int:
        return self.count_approval_requests(status="pending", harness=harness, search=search)

    def clear_approval_requests(self, *, harness: str | None = None, status: str | None = None) -> int:
        conditions: list[str] = []
        params: list[object] = []
        if harness is not None:
            conditions.append("harness = ?")
            params.append(harness)
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        query = "delete from approval_requests"
        if conditions:
            query += " where " + " and ".join(conditions)
        with self._connect() as connection:
            request_rows = connection.execute(
                f"select request_id from approval_requests{' where ' + ' and '.join(conditions) if conditions else ''}",
                tuple(params),
            ).fetchall()
            request_ids = [str(row["request_id"]) for row in request_rows]
            purge_request_resumes(connection, request_ids)
            cursor = connection.execute(query, tuple(params))
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def expire_pending_approval_requests(self, *, older_than: str, now: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update approval_requests
                set status = 'expired',
                    reason = 'Expired after waiting for review.',
                    resolved_at = ?
                where status = 'pending'
                  and created_at < ?
                """,
                (now, older_than),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        query = """
            select harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                   expires_at, updated_at
            from policy_decisions
        """
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        query += " order by updated_at desc"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "scope": str(row["scope"]),
                "artifact_id": row["artifact_id"],
                "artifact_hash": row["artifact_hash"],
                "workspace": row["workspace"],
                "publisher": row["publisher"],
                "action": str(row["action"]),
                "reason": row["reason"],
                "owner": row["owner"],
                "source": str(row["source"]),
                "expires_at": row["expires_at"],
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def clear_policy_decisions(
        self,
        harness: str | None = None,
        source: str | None = None,
        *,
        scope: str | None = None,
        artifact_id: str | None = None,
        artifact_hash: str | None = None,
        artifact_id_is_null: bool = False,
        artifact_hash_is_null: bool = False,
        workspace: str | None = None,
        publisher: str | None = None,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> int:
        require_policy_clear(self.guard_home, approval_gate_grant=approval_gate_grant)
        conditions: list[str] = []
        params: list[object] = []
        if harness is not None:
            conditions.append("harness = ?")
            params.append(harness)
        if source is not None:
            conditions.append("source = ?")
            params.append(source)
        if scope is not None:
            if scope not in _POLICY_SCOPES:
                msg = f"Invalid policy scope: {scope}"
                raise ValueError(msg)
            conditions.append("scope = ?")
            params.append(scope)
        if artifact_id is not None:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        elif artifact_id_is_null:
            conditions.append("artifact_id is null")
        if artifact_hash is not None:
            conditions.append("artifact_hash = ?")
            params.append(artifact_hash)
        elif artifact_hash_is_null:
            conditions.append("artifact_hash is null")
        if workspace is not None:
            conditions.append("(workspace = ? or workspace = ?)")
            params.extend((_stored_workspace_policy_key(workspace), _normalized_workspace_path(workspace)))
        if publisher is not None:
            conditions.append("publisher = ?")
            params.append(publisher)
        query = "delete from policy_decisions"
        if conditions:
            query += " where " + " and ".join(conditions)
        with self._connect() as connection:
            cursor = connection.execute(query, tuple(params))
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def get_latest_diff(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at
                from artifact_diffs
                where harness = ? and artifact_id = ?
                order by diff_id desc
                limit 1
                """,
                (harness, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifact_id": str(row["artifact_id"]),
            "harness": str(row["harness"]),
            "changed_fields": json.loads(str(row["changed_fields_json"])),
            "previous_hash": row["previous_hash"],
            "current_hash": str(row["current_hash"]),
            "recorded_at": str(row["recorded_at"]),
        }

    def set_managed_install(
        self,
        harness: str,
        active: bool,
        workspace: str | None,
        manifest: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                values (?, ?, ?, ?, ?)
                on conflict(harness) do update set
                  active = excluded.active,
                  workspace = excluded.workspace,
                  manifest_json = excluded.manifest_json,
                  updated_at = excluded.updated_at
                """,
                (harness, 1 if active else 0, workspace, json.dumps(manifest), now),
            )

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select harness, active, workspace, manifest_json, updated_at from managed_installs where harness = ?",
                (harness,),
            ).fetchone()
        if row is None:
            return None
        return {
            "harness": str(row["harness"]),
            "active": bool(row["active"]),
            "workspace": row["workspace"],
            "manifest": json.loads(str(row["manifest_json"])),
            "updated_at": str(row["updated_at"]),
        }

    def list_managed_installs(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select harness, active, workspace, manifest_json, updated_at
                from managed_installs
                order by harness asc
                """
            ).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "active": bool(row["active"]),
                "workspace": row["workspace"],
                "manifest": json.loads(str(row["manifest_json"])),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def cache_advisories(self, advisories: list[dict[str, object]], now: str) -> int:
        stored = 0
        with self._connect() as connection:
            for advisory in advisories:
                cache_key = self._advisory_cache_key(advisory)
                connection.execute(
                    """
                    insert into publisher_cache (publisher_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(publisher_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (cache_key, json.dumps(advisory), now),
                )
                stored += 1
        return stored

    def list_cached_advisories(self, limit: int | None = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            if limit is None:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    limit ?
                    """,
                    (limit,),
                ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                continue
            items.append(
                {
                    "cache_key": str(row["publisher_key"]),
                    "updated_at": str(row["updated_at"]),
                    **payload,
                }
            )
        return items

    def cache_supply_chain_bundle(
        self,
        workspace_id: str,
        response: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_bundle(
                connection,
                workspace_id=workspace_id,
                response=response,
                cached_at=now,
            )

    def get_cached_supply_chain_bundle(self, workspace_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_bundle(connection, workspace_id=workspace_id)

    def cache_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
        decision: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
                decision=decision,
                updated_at=now,
            )

    def get_cached_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
    ) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
            )

    def set_sync_credentials(self, sync_url: str, token: str, now: str, workspace_id: str | None = None) -> None:
        with self._connect() as connection:
            self._set_sync_credentials_in_connection(connection, sync_url, token, now, workspace_id=workspace_id)

    def set_sync_payload(self, state_key: str, payload: dict[str, object] | list[object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (state_key, json.dumps(payload), now),
            )

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (state_key,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        if isinstance(payload, (dict, list)):
            return payload
        return None

    def delete_sync_payload(self, state_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "delete from sync_state where state_key = ?",
                (state_key,),
            )

    def delete_sync_payloads(self, state_keys: list[str]) -> int:
        if not state_keys:
            return 0
        placeholders = ",".join("?" for _ in state_keys)
        with self._connect() as connection:
            cursor = connection.execute(
                f"delete from sync_state where state_key in ({placeholders})",
                tuple(state_keys),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def add_guard_event_v1(self, event: GuardEventV1) -> None:
        with self._connect() as connection:
            self._add_guard_event_v1(connection, event)

    def _add_guard_event_v1(self, connection: sqlite3.Connection, event: GuardEventV1) -> None:
        payload = event.to_dict()
        existing = connection.execute(
            "select event_id from guard_cloud_events where idempotency_key = ?",
            (event.idempotency_key,),
        ).fetchone()
        if existing is None:
            pending_count = self._count_guard_events_v1_in_connection(connection, uploaded=False)
            if pending_count >= self._guard_event_queue_limit:
                drop_count = pending_count - self._guard_event_queue_limit + 1
                cursor = connection.execute(
                    """
                    delete from guard_cloud_events
                    where event_id in (
                        select event_id
                        from guard_cloud_events
                        where uploaded_at is null
                        order by occurred_at asc, event_id asc
                        limit ?
                    )
                    """,
                    (drop_count,),
                )
                dropped_count = int(cursor.rowcount) if cursor.rowcount is not None and cursor.rowcount > 0 else 0
                if dropped_count > 0:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (
                            "cloud_event_queue_overflow",
                            json.dumps(
                                {
                                    "dropped_count": dropped_count,
                                    "queue_limit": self._guard_event_queue_limit,
                                    "incoming_event_type": event.event_type,
                                }
                            ),
                            _now(),
                        ),
                    )
        connection.execute(
            """
            insert or ignore into guard_cloud_events (
              event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            )
            values (?, ?, ?, ?, ?, null)
            """,
            (
                event.event_id,
                event.idempotency_key,
                event.event_type,
                json.dumps(payload, sort_keys=True),
                event.occurred_at,
            ),
        )

    def list_guard_events_v1(self, *, uploaded: bool | None = None, limit: int = 200) -> list[dict[str, object]]:
        query = """
            select event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            from guard_cloud_events
        """
        params: list[object] = []
        if uploaded is True:
            query += " where uploaded_at is not null"
        elif uploaded is False:
            query += " where uploaded_at is null"
        query += " order by occurred_at asc, event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        events: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            events.append(
                {
                    "event_id": str(row["event_id"]),
                    "idempotency_key": str(row["idempotency_key"]),
                    "event_type": str(row["event_type"]),
                    "occurred_at": str(row["occurred_at"]),
                    "uploaded_at": row["uploaded_at"],
                    "payload": payload,
                }
            )
        return events

    def count_guard_events_v1(self, *, uploaded: bool | None = None) -> int:
        with self._connect() as connection:
            return self._count_guard_events_v1_in_connection(connection, uploaded=uploaded)

    @staticmethod
    def _count_guard_events_v1_in_connection(connection: sqlite3.Connection, *, uploaded: bool | None = None) -> int:
        query = "select count(*) as count from guard_cloud_events"
        if uploaded is True:
            query += " where uploaded_at is not null"
        elif uploaded is False:
            query += " where uploaded_at is null"
        row = connection.execute(query).fetchone()
        return int(row["count"]) if row is not None else 0

    def mark_guard_events_v1_uploaded(self, event_ids: list[str], uploaded_at: str) -> int:
        clean_ids = [event_id for event_id in event_ids if event_id.strip()]
        if not clean_ids:
            return 0
        placeholders = ", ".join("?" for _ in clean_ids)
        with self._connect() as connection:
            cursor = connection.execute(
                f"update guard_cloud_events set uploaded_at = ? where event_id in ({placeholders})",
                (uploaded_at, *clean_ids),
            )
            return int(cursor.rowcount)

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_events (event_name, payload_json, occurred_at)
                values (?, ?, ?)
                """,
                (event_name, json.dumps(payload), now),
            )

    def list_events(self, limit: int = 100, event_name: str | None = None) -> list[dict[str, object]]:
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
        """
        params: tuple[object, ...] = ()
        if event_name is not None:
            query += " where event_name = ?"
            params = (event_name,)
        query += " order by occurred_at desc, event_id desc limit ?"
        params = (*params, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items

    def list_events_after(
        self,
        event_id: int,
        *,
        limit: int = 100,
        event_names: tuple[str, ...] | None = None,
    ) -> list[dict[str, object]]:
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
            where event_id > ?
        """
        params: list[object] = [event_id]
        if event_names:
            placeholders = ", ".join("?" for _ in event_names)
            query += f" and event_name in ({placeholders})"
            params.extend(event_names)
        query += " order by event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items

    def get_sync_credentials(self) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        if not isinstance(payload, dict):
            return None
        sync_url = payload.get("sync_url")
        if not isinstance(sync_url, str):
            return None
        workspace_id = payload.get("workspace_id")
        normalized_workspace_id = workspace_id if isinstance(workspace_id, str) and workspace_id.strip() else None
        token_reference = payload.get("token_ref")
        if isinstance(token_reference, str) and token_reference:
            expected_hash = payload.get(_SYNC_TOKEN_HASH_KEY)
            expected_hash_value = expected_hash if isinstance(expected_hash, str) and expected_hash else None

            reference_candidates = [self._sync_token_ref]
            if token_reference != self._sync_token_ref:
                reference_candidates.append(token_reference)

            for secret_ref in reference_candidates:
                for token in self._get_secret_candidates(self._secret_store, secret_ref, expected_hash_value):
                    if expected_hash_value is not None and _token_sha256(token) != expected_hash_value:
                        continue
                    if token_reference != self._sync_token_ref:
                        now = _now()
                        with self._connect() as connection:
                            self._set_sync_credentials_in_connection(
                                connection,
                                sync_url,
                                token,
                                now,
                                workspace_id=normalized_workspace_id,
                            )
                    else:
                        self._promote_secret_to_primary(self._secret_store, secret_ref, token)
                    return {"sync_url": sync_url, "token": token}
            return None
        legacy_token = payload.get("token")
        if isinstance(legacy_token, str) and legacy_token:
            now = _now()
            with self._connect() as connection:
                self._set_sync_credentials_in_connection(
                    connection,
                    sync_url,
                    legacy_token,
                    now,
                    workspace_id=normalized_workspace_id,
                )
            return {"sync_url": sync_url, "token": legacy_token}
        return None

    def set_oauth_local_credentials(
        self,
        *,
        issuer: str,
        client_id: str,
        refresh_token: str,
        dpop_private_key_pem: str,
        dpop_public_jwk: dict[str, str],
        dpop_public_jwk_thumbprint: str,
        now: str,
        grant_id: str | None = None,
        machine_id: str | None = None,
        workspace_id: str | None = None,
    ) -> None:
        refresh_token_hash = _token_sha256(refresh_token)
        dpop_private_key_hash = _token_sha256(dpop_private_key_pem)
        refresh_token_ref = self._versioned_secret_ref(self._oauth_refresh_token_ref, refresh_token_hash)
        dpop_private_key_ref = self._versioned_secret_ref(self._oauth_dpop_private_key_ref, dpop_private_key_hash)
        payload: dict[str, object] = {
            "issuer": issuer,
            "client_id": client_id,
            "refresh_token_ref": refresh_token_ref,
            "refresh_token_sha256": refresh_token_hash,
            "dpop_private_key_ref": dpop_private_key_ref,
            "dpop_private_key_sha256": dpop_private_key_hash,
            "dpop_public_jwk": dpop_public_jwk,
            "dpop_public_jwk_thumbprint": dpop_public_jwk_thumbprint,
        }
        if grant_id:
            payload["grant_id"] = grant_id
        if machine_id:
            payload["machine_id"] = machine_id
        if workspace_id:
            payload["workspace_id"] = workspace_id
        self._oauth_secret_store.set_secret(refresh_token_ref, refresh_token)
        self._oauth_secret_store.set_secret(dpop_private_key_ref, dpop_private_key_pem)
        self.set_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY, payload, now)

    def get_oauth_local_credentials(self) -> dict[str, object] | None:
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if not isinstance(payload, dict):
            return None
        issuer = payload.get("issuer")
        client_id = payload.get("client_id")
        refresh_token_ref = payload.get("refresh_token_ref")
        refresh_token_hash = payload.get("refresh_token_sha256")
        dpop_private_key_ref = payload.get("dpop_private_key_ref")
        dpop_private_key_hash = payload.get("dpop_private_key_sha256")
        dpop_public_jwk = payload.get("dpop_public_jwk")
        dpop_public_jwk_thumbprint = payload.get("dpop_public_jwk_thumbprint")
        if not isinstance(issuer, str) or not issuer:
            return None
        if not isinstance(client_id, str) or not client_id:
            return None
        if not isinstance(refresh_token_ref, str) or not refresh_token_ref:
            return None
        if not isinstance(dpop_private_key_ref, str) or not dpop_private_key_ref:
            return None
        if not isinstance(refresh_token_hash, str) or not refresh_token_hash:
            return None
        if not isinstance(dpop_private_key_hash, str) or not dpop_private_key_hash:
            return None
        if not isinstance(dpop_public_jwk, dict):
            return None
        if not isinstance(dpop_public_jwk_thumbprint, str) or not dpop_public_jwk_thumbprint:
            return None
        refresh_token: str | None = None
        for candidate in self._get_secret_candidates(
            self._oauth_secret_store,
            refresh_token_ref,
            refresh_token_hash,
        ):
            if _token_sha256(candidate) != refresh_token_hash:
                continue
            refresh_token = candidate
            self._promote_secret_to_primary(self._oauth_secret_store, refresh_token_ref, candidate)
            break
        if refresh_token is None:
            return None
        dpop_private_key_pem: str | None = None
        for candidate in self._get_secret_candidates(
            self._oauth_secret_store,
            dpop_private_key_ref,
            dpop_private_key_hash,
        ):
            if _token_sha256(candidate) != dpop_private_key_hash:
                continue
            dpop_private_key_pem = candidate
            self._promote_secret_to_primary(self._oauth_secret_store, dpop_private_key_ref, candidate)
            break
        if dpop_private_key_pem is None:
            return None
        result: dict[str, object] = {
            "issuer": issuer,
            "client_id": client_id,
            "refresh_token": refresh_token,
            "dpop_private_key_pem": dpop_private_key_pem,
            "dpop_public_jwk": dpop_public_jwk,
            "dpop_public_jwk_thumbprint": dpop_public_jwk_thumbprint,
        }
        grant_id = payload.get("grant_id")
        machine_id = payload.get("machine_id")
        workspace_id = payload.get("workspace_id")
        if isinstance(grant_id, str) and grant_id:
            result["grant_id"] = grant_id
        if isinstance(machine_id, str) and machine_id:
            result["machine_id"] = machine_id
        if isinstance(workspace_id, str) and workspace_id:
            result["workspace_id"] = workspace_id
        return result

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        health: dict[str, object] = {
            "configured": isinstance(payload, dict),
            "state": "not_configured",
            "backend": _secret_store_backend_name(self._oauth_secret_store),
            "fallback_backend": _secret_store_fallback_backend_name(self._oauth_secret_store),
        }
        if not isinstance(payload, dict):
            return health

        credentials = self.get_oauth_local_credentials()
        if credentials is None:
            health["state"] = "degraded"
            return health

        health["state"] = "healthy"
        for key in ("issuer", "client_id", "grant_id", "machine_id", "workspace_id"):
            value = credentials.get(key)
            if isinstance(value, str) and value:
                health[key] = value
        return health

    def get_latest_guard_connect_state(self, *, now: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_latest_connect_state(connection, now=now)

    def record_latest_guard_connect_sync_success(
        self,
        *,
        sync_payload: dict[str, object],
        now: str,
    ) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select request_id
                from guard_connect_states
                where status = 'connected'
                  and milestone != 'first_sync_succeeded'
                order by updated_at desc
                limit 1
                """
            ).fetchone()
            if row is None:
                return None
            latest_state = load_connect_state(connection, str(row["request_id"]), now=now)
            if latest_state is None:
                return None
            if latest_state.get("status") != "connected":
                return latest_state
            return persist_connect_result(
                connection,
                request_id=str(latest_state["request_id"]),
                status="connected",
                milestone="first_sync_succeeded",
                updated_at=now,
                reason=None,
                sync_payload=sync_payload,
            )

    def _credential_payload_token_hash(self, payload: dict[str, object]) -> str | None:
        token_hash = payload.get(_SYNC_TOKEN_HASH_KEY)
        if isinstance(token_hash, str) and token_hash:
            return token_hash
        legacy_token = payload.get("token")
        if isinstance(legacy_token, str) and legacy_token:
            return _token_sha256(legacy_token)
        token_reference = payload.get("token_ref")
        if isinstance(token_reference, str) and token_reference:
            token = self._secret_store.get_secret(token_reference)
            if isinstance(token, str) and token:
                return _token_sha256(token)
        return None

    def _set_sync_credentials_in_connection(
        self,
        connection: sqlite3.Connection,
        sync_url: str,
        token: str,
        now: str,
        *,
        workspace_id: str | None = None,
    ) -> None:
        token_hash = _token_sha256(token)
        normalized_workspace_id = (
            workspace_id.strip() if isinstance(workspace_id, str) and workspace_id.strip() else None
        )
        previous_payload: dict[str, object] | None = None
        previous_row = connection.execute(
            "select payload_json from sync_state where state_key = 'credentials'"
        ).fetchone()
        if previous_row is not None:
            previous_payload_candidate = json.loads(str(previous_row["payload_json"]))
            if isinstance(previous_payload_candidate, dict):
                previous_payload = previous_payload_candidate
        previous_sync_url = previous_payload.get("sync_url") if previous_payload is not None else None
        previous_token_hash = (
            self._credential_payload_token_hash(previous_payload) if previous_payload is not None else None
        )
        previous_workspace_id = previous_payload.get("workspace_id") if previous_payload is not None else None
        previous_workspace = (
            previous_workspace_id.strip()
            if isinstance(previous_workspace_id, str) and previous_workspace_id.strip()
            else None
        )
        effective_workspace_id = normalized_workspace_id
        can_preserve_workspace = (
            previous_sync_url == sync_url
            and previous_token_hash is not None
            and previous_token_hash == token_hash
            and isinstance(previous_workspace_id, str)
            and previous_workspace_id.strip()
        )
        if effective_workspace_id is None and can_preserve_workspace:
            effective_workspace_id = previous_workspace_id.strip()
        workspace_changed = (
            previous_workspace is not None
            and effective_workspace_id is not None
            and previous_workspace != effective_workspace_id
        )
        payload = {
            "sync_url": sync_url,
            "token_ref": self._sync_token_ref,
            _SYNC_TOKEN_HASH_KEY: token_hash,
        }
        if effective_workspace_id is not None:
            payload["workspace_id"] = effective_workspace_id
        if previous_row is None or previous_payload is None:
            credentials_changed = True
        else:
            credentials_changed = (
                previous_sync_url != sync_url
                or previous_token_hash is None
                or previous_token_hash != token_hash
                or workspace_changed
            )
        self._secret_store.set_secret(self._sync_token_ref, token)
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values ('credentials', ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (json.dumps(payload), now),
        )
        if credentials_changed:
            connection.execute("delete from sync_state where state_key != 'credentials'")
            connection.execute("delete from guard_supply_chain_bundle_cache")
            connection.execute("delete from guard_supply_chain_eval_cache")
            connection.execute("delete from publisher_cache")
            connection.execute("delete from policy_decisions where source in ('cloud-sync', 'team-policy')")

    @staticmethod
    def _cloud_workspace_id_from_connection(connection: sqlite3.Connection) -> str | None:
        row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        if not isinstance(payload, dict):
            return None
        workspace_id = payload.get("workspace_id")
        if isinstance(workspace_id, str) and workspace_id.strip():
            return workspace_id
        return None

    def upsert_guard_session(
        self,
        *,
        session_id: str,
        harness: str,
        surface: str,
        status: str,
        client_name: str,
        client_title: str | None,
        client_version: str | None,
        workspace: str | None,
        capabilities: list[str],
        now: str,
    ) -> dict[str, object]:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_sessions (
                  session_id,
                  harness,
                  surface,
                  status,
                  client_name,
                  client_title,
                  client_version,
                  workspace,
                  capabilities_json,
                  created_at,
                  updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(session_id) do update set
                  harness = excluded.harness,
                  surface = excluded.surface,
                  status = excluded.status,
                  client_name = excluded.client_name,
                  client_title = excluded.client_title,
                  client_version = excluded.client_version,
                  workspace = excluded.workspace,
                  capabilities_json = excluded.capabilities_json,
                  updated_at = excluded.updated_at
                """,
                (
                    session_id,
                    harness,
                    surface,
                    status,
                    client_name,
                    client_title,
                    client_version,
                    workspace,
                    json.dumps(capabilities),
                    now,
                    now,
                ),
            )
        session = self.get_guard_session(session_id)
        if session is None:
            raise RuntimeError(f"Guard session {session_id} was not persisted.")
        return session

    def get_guard_session(self, session_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, harness, surface, status, client_name, client_title, client_version, workspace,
                       capabilities_json, created_at, updated_at
                from guard_sessions
                where session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": str(row["session_id"]),
            "harness": str(row["harness"]),
            "surface": str(row["surface"]),
            "status": str(row["status"]),
            "client_name": str(row["client_name"]),
            "client_title": str(row["client_title"]) if row["client_title"] is not None else None,
            "client_version": str(row["client_version"]) if row["client_version"] is not None else None,
            "workspace": str(row["workspace"]) if row["workspace"] is not None else None,
            "capabilities": json.loads(str(row["capabilities_json"])),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def list_guard_sessions(self, status: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        query = """
            select session_id, harness, surface, status, client_name, client_title, client_version, workspace,
                   capabilities_json, created_at, updated_at
            from guard_sessions
        """
        params: list[object] = []
        if status is not None:
            query += " where status = ?"
            params.append(status)
        query += " order by updated_at desc, session_id desc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "session_id": str(row["session_id"]),
                "harness": str(row["harness"]),
                "surface": str(row["surface"]),
                "status": str(row["status"]),
                "client_name": str(row["client_name"]),
                "client_title": str(row["client_title"]) if row["client_title"] is not None else None,
                "client_version": str(row["client_version"]) if row["client_version"] is not None else None,
                "workspace": str(row["workspace"]) if row["workspace"] is not None else None,
                "capabilities": json.loads(str(row["capabilities_json"])),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def upsert_guard_operation(
        self,
        *,
        operation_id: str,
        session_id: str,
        harness: str,
        operation_type: str,
        status: str,
        approval_request_ids: list[str],
        resume_token: str | None,
        metadata: dict[str, object],
        now: str,
    ) -> dict[str, object]:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_operations (
                  operation_id,
                  session_id,
                  harness,
                  operation_type,
                  status,
                  approval_request_ids_json,
                  resume_token,
                  metadata_json,
                  created_at,
                  updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(operation_id) do update set
                  session_id = excluded.session_id,
                  harness = excluded.harness,
                  operation_type = excluded.operation_type,
                  status = excluded.status,
                  approval_request_ids_json = excluded.approval_request_ids_json,
                  resume_token = excluded.resume_token,
                  metadata_json = excluded.metadata_json,
                  updated_at = excluded.updated_at
                """,
                (
                    operation_id,
                    session_id,
                    harness,
                    operation_type,
                    status,
                    json.dumps(approval_request_ids),
                    resume_token,
                    json.dumps(metadata),
                    now,
                    now,
                ),
            )
        operation = self.get_guard_operation(operation_id)
        if operation is None:
            raise RuntimeError(f"Guard operation {operation_id} was not persisted.")
        return operation

    def get_guard_operation(self, operation_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                       resume_token, metadata_json, created_at, updated_at
                from guard_operations
                where operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "operation_id": str(row["operation_id"]),
            "session_id": str(row["session_id"]),
            "harness": str(row["harness"]),
            "operation_type": str(row["operation_type"]),
            "status": str(row["status"]),
            "approval_request_ids": json.loads(str(row["approval_request_ids_json"])),
            "resume_token": str(row["resume_token"]) if row["resume_token"] is not None else None,
            "metadata": json.loads(str(row["metadata_json"])),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        query = """
            select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                   resume_token, metadata_json, created_at, updated_at
            from guard_operations
        """
        params: list[object] = []
        if session_id is not None:
            query += " where session_id = ?"
            params.append(session_id)
        query += " order by updated_at desc, operation_id desc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "operation_id": str(row["operation_id"]),
                "session_id": str(row["session_id"]),
                "harness": str(row["harness"]),
                "operation_type": str(row["operation_type"]),
                "status": str(row["status"]),
                "approval_request_ids": json.loads(str(row["approval_request_ids_json"])),
                "resume_token": str(row["resume_token"]) if row["resume_token"] is not None else None,
                "metadata": json.loads(str(row["metadata_json"])),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                       resume_token, metadata_json, created_at, updated_at
                from guard_operations
                where approval_request_ids_json like ?
                order by updated_at desc, operation_id desc
                """,
                (f"%{request_id}%",),
            ).fetchall()
        for row in rows:
            approval_request_ids = json.loads(str(row["approval_request_ids_json"]))
            if request_id not in {str(item) for item in approval_request_ids}:
                continue
            return {
                "operation_id": str(row["operation_id"]),
                "session_id": str(row["session_id"]),
                "harness": str(row["harness"]),
                "operation_type": str(row["operation_type"]),
                "status": str(row["status"]),
                "approval_request_ids": approval_request_ids,
                "resume_token": str(row["resume_token"]) if row["resume_token"] is not None else None,
                "metadata": json.loads(str(row["metadata_json"])),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
        return None

    def seed_request_resume(
        self,
        *,
        request_id: str,
        operation_id: str | None,
        harness: str,
        strategy: str,
        supported: bool,
        thread_id: str | None,
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_request_resume_seed(
                connection,
                request_id=request_id,
                operation_id=operation_id,
                harness=harness,
                strategy=strategy,
                supported=supported,
                thread_id=thread_id,
                now=now,
            )

    def get_request_resume(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_request_resume(connection, request_id)

    def get_latest_request_resume(self, *, harness: str | None = None) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_latest_request_resume(connection, harness=harness)

    def update_request_resume(
        self,
        *,
        request_id: str,
        resolution_action: str | None,
        strategy: str | None,
        supported: bool | None,
        status: str,
        reason: str | None,
        message: str | None,
        last_error: str | None,
        attempt_count: int,
        last_attempt_at: str | None,
        sent_at: str | None,
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_request_resume_update(
                connection,
                request_id=request_id,
                resolution_action=resolution_action,
                strategy=strategy,
                supported=supported,
                status=status,
                reason=reason,
                message=message,
                last_error=last_error,
                attempt_count=attempt_count,
                last_attempt_at=last_attempt_at,
                sent_at=sent_at,
                now=now,
            )

    def add_guard_operation_item(
        self,
        *,
        item_id: str,
        operation_id: str,
        item_type: str,
        lifecycle: str,
        payload: dict[str, object],
        now: str,
    ) -> dict[str, object]:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_operation_items (
                  item_id, operation_id, item_type, lifecycle, payload_json, created_at
                )
                values (?, ?, ?, ?, ?, ?)
                """,
                (item_id, operation_id, item_type, lifecycle, json.dumps(payload), now),
            )
        items = self.list_guard_operation_items(operation_id)
        for item in items:
            if item["item_id"] == item_id:
                return item
        raise RuntimeError(f"Guard operation item {item_id} was not persisted.")

    def list_guard_operation_items(self, operation_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select item_id, operation_id, item_type, lifecycle, payload_json, created_at
                from guard_operation_items
                where operation_id = ?
                order by created_at asc, item_id asc
                """,
                (operation_id,),
            ).fetchall()
        return [
            {
                "item_id": str(row["item_id"]),
                "operation_id": str(row["operation_id"]),
                "item_type": str(row["item_type"]),
                "lifecycle": str(row["lifecycle"]),
                "payload": json.loads(str(row["payload_json"])),
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def attach_guard_client(
        self,
        *,
        client_id: str,
        surface: str,
        session_id: str | None,
        metadata: dict[str, object],
        lease_seconds: int,
        now: str,
    ) -> dict[str, object]:
        lease_id = uuid4().hex
        lease_expires_at = _lease_expiry(now, lease_seconds)
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_client_attachments (
                  client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, attached_at, last_seen_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(client_id) do update set
                  surface = excluded.surface,
                  session_id = excluded.session_id,
                  metadata_json = excluded.metadata_json,
                  lease_id = excluded.lease_id,
                  lease_expires_at = excluded.lease_expires_at,
                  last_seen_at = excluded.last_seen_at
                """,
                (client_id, surface, session_id, json.dumps(metadata), lease_id, lease_expires_at, now, now),
            )
        item = self.get_guard_client_attachment(client_id)
        if item is not None:
            return item
        raise RuntimeError(f"Guard client attachment {client_id} was not persisted.")

    def renew_guard_client_attachment(
        self,
        *,
        client_id: str,
        lease_id: str,
        lease_seconds: int,
        now: str,
    ) -> dict[str, object] | None:
        lease_expires_at = _lease_expiry(now, lease_seconds)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update guard_client_attachments
                set last_seen_at = ?, lease_expires_at = ?
                where client_id = ? and lease_id = ?
                """,
                (now, lease_expires_at, client_id, lease_id),
            )
        if cursor.rowcount <= 0:
            return None
        return self.get_guard_client_attachment(client_id)

    def get_guard_client_attachment(self, client_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select
                  client_id, surface, session_id, metadata_json,
                  lease_id, lease_expires_at, attached_at, last_seen_at
                from guard_client_attachments
                where client_id = ?
                """,
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "client_id": str(row["client_id"]),
            "surface": str(row["surface"]),
            "session_id": str(row["session_id"]) if row["session_id"] is not None else None,
            "metadata": json.loads(str(row["metadata_json"])),
            "lease_id": str(row["lease_id"]),
            "lease_expires_at": str(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None,
            "attached_at": str(row["attached_at"]),
            "last_seen_at": str(row["last_seen_at"]),
        }

    def list_guard_client_attachments(
        self,
        *,
        surface: str | None = None,
        session_id: str | None = None,
        active_within_seconds: int = 60,
    ) -> list[dict[str, object]]:
        query = """
            select client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, attached_at, last_seen_at
            from guard_client_attachments
        """
        params: list[object] = []
        filters: list[str] = []
        if surface is not None:
            filters.append("surface = ?")
            params.append(surface)
        if session_id is not None:
            filters.append("session_id = ?")
            params.append(session_id)
        if filters:
            query += " where " + " and ".join(filters)
        query += " order by last_seen_at desc, client_id asc"
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        cutoff = datetime.now(timezone.utc).timestamp() - max(active_within_seconds, 0)
        items: list[dict[str, object]] = []
        for row in rows:
            lease_expires_at = row["lease_expires_at"]
            if lease_expires_at is not None:
                expires_at = datetime.fromisoformat(str(lease_expires_at)).timestamp()
                if expires_at < datetime.now(timezone.utc).timestamp():
                    continue
            else:
                last_seen = datetime.fromisoformat(str(row["last_seen_at"])).timestamp()
                if last_seen < cutoff:
                    continue
            items.append(
                {
                    "client_id": str(row["client_id"]),
                    "surface": str(row["surface"]),
                    "session_id": str(row["session_id"]) if row["session_id"] is not None else None,
                    "metadata": json.loads(str(row["metadata_json"])),
                    "lease_id": str(row["lease_id"]),
                    "lease_expires_at": str(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None,
                    "attached_at": str(row["attached_at"]),
                    "last_seen_at": str(row["last_seen_at"]),
                }
            )
        return items

    def record_guard_surface_open(self, *, surface: str, open_key: str, now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_surface_opens (surface, open_key, opened_at)
                values (?, ?, ?)
                on conflict(surface, open_key) do update set
                  opened_at = excluded.opened_at
                """,
                (surface, open_key, now),
            )

    def has_guard_surface_open(self, *, surface: str, open_key: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "select 1 from guard_surface_opens where surface = ? and open_key = ?",
                (surface, open_key),
            ).fetchone()
        return row is not None

    def list_evidence(
        self,
        *,
        harness: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        request_id: str | None = None,
        action_identity: str | None = None,
        before_cursor: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            records = _list_evidence_impl(
                connection,
                harness=harness,
                category=category,
                severity=severity,
                request_id=request_id,
                action_identity=action_identity,
                before_cursor=before_cursor,
                limit=limit,
            )
        return [
            {
                "evidence_id": r.evidence_id,
                "action_id": r.action_id,
                "request_id": r.request_id,
                "harness": r.harness,
                "workspace": r.workspace,
                "signal_id": r.signal_id,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "summary": r.summary,
                "details": r.details,
                "action_identity": r.action_identity,
                "created_at": r.created_at,
            }
            for r in records
        ]

    def add_evidence(self, record: EvidenceRecord) -> None:
        with self._connect() as connection:
            _store_evidence_impl(connection, record)

    @staticmethod
    def _advisory_cache_key(advisory: dict[str, object]) -> str:
        advisory_id = advisory.get("id")
        if isinstance(advisory_id, str) and advisory_id.strip():
            return advisory_id.strip()
        advisory_digest = sha256(
            json.dumps(advisory, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return f"anonymous:{advisory_digest}"


def _path_within_workspace(config_path: str, workspace: str) -> bool:
    normalized_config = _normalized_workspace_path(config_path)
    normalized_workspace = _normalized_workspace_path(workspace)
    if not normalized_config or not normalized_workspace:
        return False
    if normalized_workspace == "/":
        return normalized_config.startswith("/")
    return normalized_config == normalized_workspace or normalized_config.startswith(f"{normalized_workspace}/")


def _normalized_workspace_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized


def _workspace_policy_key(workspace: str | None) -> str | None:
    if workspace is None or not workspace.strip():
        return None
    normalized = _normalized_workspace_path(workspace)
    digest = sha256(normalized.encode("utf-8")).hexdigest()
    return f"{_WORKSPACE_POLICY_KEY_PREFIX}{digest}"


def _stored_workspace_policy_key(workspace: str) -> str:
    if workspace.startswith(_WORKSPACE_POLICY_KEY_PREFIX):
        return workspace
    policy_key = _workspace_policy_key(workspace)
    if policy_key is None:
        msg = "Workspace policy key cannot be empty"
        raise ValueError(msg)
    return policy_key


def _artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_HARNESS_FAMILIES:
        return None
    return f"family:{family}"


def _family_key_value(family_key: str) -> str:
    if family_key.startswith("family:"):
        return family_key.removeprefix("family:")
    return family_key


def _chunks(values: list[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lease_expiry(now: str, lease_seconds: int) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=max(lease_seconds, 1))).isoformat()


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _transport_value(value: object) -> str:
    if isinstance(value, str) and value in {"local", "remote", "hybrid"}:
        return value
    return "local"
