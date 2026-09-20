"""SQLite-backed local Guard persistence."""

from __future__ import annotations

from functools import partial

from .artifact_identity import artifact_family_key

# ruff: noqa: E402,F401,I001

import base64
import ctypes
import importlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from hashlib import scrypt, sha256
from pathlib import Path
from typing import Any, Protocol, TypedDict, TypeVar, cast
from urllib.parse import urlparse
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from .approval_gate import ApprovalGateGrant, require_policy_clear, require_policy_write, require_request_resolution
from .approval_resolution import require_resolvable_approval_request
from .cli.oauth_client import resolve_guard_oauth_client_config
from .edge_events import build_receipt_event
from .local_trust_contract import (
    POLICY_INTEGRITY_ENFORCEMENT_ENFORCE,
    POLICY_INTEGRITY_MODE_DEGRADED,
    POLICY_INTEGRITY_MODE_PROTECTED,
    POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE,
    POLICY_INTEGRITY_REASON_GUARD_DB_INACCESSIBLE,
    POLICY_INTEGRITY_REASON_GUARD_DB_PERMISSIONS,
    POLICY_INTEGRITY_REASON_GUARD_DB_SYMLINK,
    POLICY_INTEGRITY_REASON_GUARD_HOME_INACCESSIBLE,
    POLICY_INTEGRITY_REASON_GUARD_HOME_PERMISSIONS,
    POLICY_INTEGRITY_REASON_GUARD_HOME_SYMLINK,
    POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE,
    POLICY_INTEGRITY_REASON_SYSTEM_KEYRING_UNAVAILABLE,
    TrustStatus,
)
from .models import GuardApprovalRequest, GuardArtifact, GuardReceipt, GuardRuntimeState, PolicyDecision
from .policy_authority import validate_policy_write_authority
from .policy_integrity import (
    REMOTE_POLICY_SOURCES,
    PolicyIntegrityVerificationResult,
    is_remote_policy_source,
    sign_local_policy_row,
    verify_local_policy_row,
)
from .runtime.actions import GuardActionEnvelope
from .runtime.approval_context import parse_approval_context_token
from .runtime.scanner_cache import scanner_cache_key
from .schemas.guard_event_v1 import GuardEventV1
from .sqlite_tuning import (
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_CACHE_SIZE_KIB,
    SQLITE_MMAP_SIZE_BYTES,
    SQLITE_WAL_BUSY_TIMEOUT_MS,
    sqlite_connect_timeout_seconds,
)
from .store_approvals import (
    _json_object,
    _json_object_list,
    approval_request_surfaces_are_resolvable,
    approval_index_statements,
    approval_schema_statement,
    backfill_approval_queue_columns,
)
from .store_approval_writes import (
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
    build_connect_state_response,
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
from .store_review_event_outbox_binding import bind_review_events_for_request
from .store_evidence import (
    EvidenceRecord,
    ensure_evidence_schema,
)
from .store_evidence import (
    list_evidence as _list_evidence_impl,
)
from .store_evidence import (
    store_evidence as _store_evidence_impl,
)
from .store_policy_source_context import (
    PolicySourceContextIndex,
    build_policy_source_context_index,
    lookup_policy_source_context,
)
from .store_receipt_rollups import (
    backfill_receipt_rollups,
    count_receipts_from_rollups,
    load_receipt_analytics,
    receipt_rollup_index_statements,
    receipt_rollup_schema_statements,
    receipt_rollups_initialized,
    receipt_rollups_need_backfill,
    record_receipt_insert,
    record_receipt_policy_decision_change,
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
from .types import CapabilitySet, TransportKind


class _RecoveredOAuthLocalCredentialInputs(TypedDict):
    issuer: str
    client_id: str
    refresh_token: str
    dpop_private_key_pem: str
    dpop_public_jwk: dict[str, str]
    dpop_public_jwk_thumbprint: str
    device_id: str | None
    grant_id: str | None
    machine_id: str | None
    supply_chain_entitlement_expires_at: str | None
    supply_chain_firewall: bool | None
    supply_chain_plan_id: str | None
    workspace_id: str | None
    runtime_id: str | None
    runtime_label: str | None
    access_token: str | None
    access_token_expires_at: str | None


class PolicyDecisionLookupResult(TypedDict):
    decision: dict[str, object] | None
    ignored_local_integrity: dict[str, object] | None
    trust_status: dict[str, object]
    authority_revision: int


_POLICY_INTEGRITY_KEY_REF = "guard-policy-integrity-key"
_POLICY_INTEGRITY_CONTROL_REF = "guard-policy-integrity-control"
_POLICY_INTEGRITY_SERVICE_NAME = "hol-guard.policy-integrity"
_OAUTH_LOCAL_CREDENTIALS_REF = "guard-oauth-local-credentials"
_OAUTH_LOCAL_CREDENTIALS_STATE_KEY = "oauth_local_credentials"
_OAUTH_LOCAL_CREDENTIALS_HASH_KEY = "credentials_sha256"
_OAUTH_LOCAL_CREDENTIALS_REF_KEY = "credentials_ref"
_OAUTH_PRIMARY_SECRET_TIMEOUT_SECONDS = 2.0
_APPROVAL_GATE_POLICY_SOURCE = "approval-gate"
_GUARD_CLOUD_COMMAND_STATE_KEYS = (
    *("guard_command_queue_state", "guard_command_capability_v1"),
    *("guard_command_pending_approvals_v1", "guard_command_local_approvals_v1"),
    "guard_command_replay_state_v1",
    "guard_exact_cloud_review_capability",
    "guard_exact_cloud_review_revocation",
)
_GUARD_CLOUD_RESET_STATE_KEYS = (
    "sync_summary",
    "receipt_sync_cursor",
    "policy",
    "alert_preferences",
    "team_policy_pack",
    "guard_events_v1_summary",
    "aibom_guard_events_backoff",
    "aibom_sync_summary",
    "runtime_session_summary",
    "supply_chain_bundle_summary",
    "supply_chain_bundle_entitlement",
    "supply_chain_bundle_daemon",
    "headless_app_sync_summary",
    "managed_controls_active",
    "managed_controls_negotiated_capabilities",
    *_GUARD_CLOUD_COMMAND_STATE_KEYS,
)


from .store_base_values import _is_approval_gate_one_shot_policy


_DEVICE_ROW_KEY = "local-device"
_MAX_RESOLVED_SCOPE_IDS = 200
_SQLITE_ID_BATCH_SIZE = 500
_WORKSPACE_POLICY_KEY_PREFIX = "workspace:"
_POLICY_INTEGRITY_STATE_KEY = "policy_integrity"
_POLICY_INTEGRITY_CONTROL_VERSION = 1

_SOURCE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


from .store_base_values import _normalize_source_name


_POLICY_INTEGRITY_ENFORCEMENTS = frozenset({"warn", "enforce"})
_POLICY_INTEGRITY_STATUSES = (
    "valid",
    "missing_integrity",
    "tampered",
    "unknown_key",
    "rollback_detected",
    "degraded_mode",
)
_SCOPED_HARNESS_FAMILIES = frozenset(
    {
        "file-read",
        "mcp",
        "mcp-tool",
        "package-request",
        "prompt",
        "prompt-env-read",
        "prompt-file",
        "tool-action",
    }
)
_SCOPED_RUNTIME_EXACT_FAMILIES = frozenset(
    {
        "file-read",
        "mcp-tool",
        "package-request",
        "prompt",
        "tool-action",
    }
)
_RUNTIME_SCOPED_EXACT_MATCH_PREFIX = "runtime-exact:"
_REMOTE_POLICY_SOURCE_PARAMS = tuple(sorted(REMOTE_POLICY_SOURCES))
_REMOTE_POLICY_SOURCE_PLACEHOLDERS = "(" + ",".join("?" for _ in _REMOTE_POLICY_SOURCE_PARAMS) + ")"
_POLICY_SCOPES = frozenset({"artifact", "workspace", "publisher", "harness", "global"})
_SLOW_STORE_WARNING_ENV = "HOL_GUARD_WARN_SLOW_STORE"
_SQLITE_LOCK_RETRY_ATTEMPTS = 5
_SQLITE_LOCK_RETRY_DELAY_SECONDS = 0.1
_SECRET_FINGERPRINT_PREFIX = "scrypt$"
_SECRET_FINGERPRINT_SALT = b"hol-guard-secret-fingerprint:v1"
_SECRET_FINGERPRINT_N = 2**14
_SECRET_FINGERPRINT_R = 8
_SECRET_FINGERPRINT_P = 1
_SECRET_FINGERPRINT_DKLEN = 32
_OAUTH_REFRESH_LOCK_TIMEOUT_SECONDS = 30.0
_OAUTH_REFRESH_LOCK_POLL_SECONDS = 0.05
_OAUTH_CREDENTIAL_LOCK_TIMEOUT_SECONDS = 30.0
_OAUTH_CREDENTIAL_LOCK_POLL_SECONDS = 0.05
_CLOUD_SYNC_LOCK_TIMEOUT_SECONDS = 30.0
_CLOUD_SYNC_LOCK_POLL_SECONDS = 0.05
_GUARD_STORE_PRIVATE_DIR_MODE = 0o700
_GUARD_STORE_PRIVATE_FILE_MODE = 0o600
_SYSTEM_KEYRING_AVAILABILITY_CACHE_FILE = "system-keyring-availability.json"
_SYSTEM_KEYRING_AVAILABILITY_CACHE_TTL_SECONDS = 86_400.0
_POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES = frozenset({"missing_integrity", "unknown_key"})
_ENCRYPTED_SECRET_INIT_LOCKS_GUARD = threading.Lock()
_ENCRYPTED_SECRET_INIT_LOCKS: dict[str, threading.Lock] = {}


from .store_base_values import _oauth_sync_url_from_issuer
from .store_base_values import _allowed_origin_from_sync_url


from .store_base_values import _secret_fingerprint
from .store_base_values import _secret_matches_hash
from .store_base_secret_files import _acquire_advisory_file_lock
from .store_base_secret_files import _release_advisory_file_lock


class SecretStore(Protocol):
    """Credential persistence contract for local Guard secrets."""

    def set_secret(self, secret_id: str, value: str) -> None:
        """Store a secret value."""

    def get_secret(self, secret_id: str) -> str | None:
        """Fetch a secret value."""

    def delete_secret(self, secret_id: str) -> None:
        """Delete a secret value if it exists."""


from .store_base_keyring import SystemKeyringSecretStore
from .store_base_secret_files import EncryptedFileSecretStore
from .store_base_secret_files import UnavailableSecretStore
from .store_base_secret_backends import FallbackSecretStore
from .store_base_secret_backends import MigratingFallbackSecretStore
from .store_base_secret_files import _expand_keystream
from .store_base_secret_files import _set_private_mode
from .store_base_secret_backends import _system_keyring_availability_cache_path
from .store_base_secret_backends import _read_system_keyring_availability_cache
from .store_base_secret_backends import _write_system_keyring_availability_cache
from .store_base_secret_backends import _system_keyring_is_available
from .store_base_secret_backends import _build_oauth_secret_store
from .store_base_secret_backends import _build_policy_integrity_secret_store
from .store_base_secret_backends import _secret_store_backend_name
from .store_base_secret_backends import _secret_store_fallback_backend_name
from .store_base_values import _should_warn_on_slow_store_transactions


_SLOW_QUERY_THRESHOLD_MS: int = 200
_OAUTH_HEALTH_CACHE_TTL_SECONDS = 60.0
_OAUTH_HEALTH_DEGRADED_CACHE_TTL_SECONDS = 15.0
_OAUTH_STORAGE_REPAIR_MIN_INTERVAL_SECONDS = 3600.0
_OAUTH_KEYCHAIN_ACCESS_STATE_FILE = "oauth-keychain-access.json"
_POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS = 1.0
_POLICY_INTEGRITY_CACHE_TTL_SECONDS = 60.0
_store_logger = logging.getLogger("codex_plugin_scanner.guard.store")
_OAUTH_SECRET_PAYLOAD_PROCESS_CACHE: dict[tuple[str, str, str], str] = {}
_OAUTH_HEALTH_RESULT_PROCESS_CACHE: dict[tuple[str, str], tuple[float, dict[str, object]]] = {}


from .store_base_values import receipt_index_statements
from .store_base_policy_matching import _path_within_workspace
from .store_base_policy_matching import _normalized_workspace_path
from .store_base_policy_matching import _workspace_policy_key
from .store_base_policy_matching import _stored_workspace_policy_key
from .store_base_policy_matching import _validate_scoped_policy_artifact_target


_artifact_family_key = partial(
    artifact_family_key,
    allowed_families=_SCOPED_HARNESS_FAMILIES,
)


from .store_base_policy_matching import _runtime_scoped_exact_match_key
from .store_base_policy_matching import _global_runtime_scoped_exact_match_key
from .store_base_policy_matching import runtime_tool_action_policy_artifact_id
from .store_base_policy_matching import runtime_tool_action_exact_match_context
from .store_base_policy_matching import runtime_tool_action_portable_match_context
from .store_base_policy_matching import browser_mcp_exact_match_context
from .store_base_policy_matching import _is_runtime_scoped_exact_match_key
from .store_base_policy_matching import _is_approval_context_token
from .store_base_policy_matching import _scoped_runtime_row_requires_exact_match
from .store_base_policy_matching import _warn_only_policy_integrity_status
from .store_base_policy_matching import _policy_integrity_ready_for_local_write
from .store_base_policy_matching import _policy_integrity_setup_safe_for_local_write
from .store_base_policy_matching import _family_key_value
from .store_base_values import _row_mapping
from .store_base_values import _string_value
from .store_base_values import _int_value
from .store_base_values import _mapping_int


_ChunkT = TypeVar("_ChunkT")


from .store_base_chunks import _chunks
from .store_base_values import _parse_utc_timestamp
from .store_base_values import _canonical_utc_timestamp
from .store_base_values import _timestamp_has_expired
from .store_base_values import _now
from .store_base_values import _lease_expiry
from .store_base_values import _string_list
from .store_base_values import _transport_value


__all__ = tuple(name for name in globals() if not (name.startswith("__") and name.endswith("__")))
