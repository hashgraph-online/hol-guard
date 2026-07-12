"""SQLite-backed local Guard persistence."""

from __future__ import annotations

# ruff: noqa: F401,I001

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
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from hashlib import pbkdf2_hmac, scrypt, sha256
from pathlib import Path
from typing import Any, Protocol, TypedDict, TypeVar, cast
from urllib.parse import urlparse
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from .approval_gate import ApprovalGateGrant, require_policy_clear, require_policy_write, require_request_resolution
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
from .runtime.scanner_cache import scanner_cache_key
from .schemas.guard_event_v1 import GuardEventV1
from .sqlite_tuning import SQLITE_BUSY_TIMEOUT_MS, SQLITE_CONNECT_TIMEOUT_SECONDS, SQLITE_WAL_BUSY_TIMEOUT_MS
from .store_approvals import (
    _json_object,
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


_POLICY_INTEGRITY_KEY_REF = "guard-policy-integrity-key"
_POLICY_INTEGRITY_CONTROL_REF = "guard-policy-integrity-control"
_POLICY_INTEGRITY_SERVICE_NAME = "hol-guard.policy-integrity"
_OAUTH_LOCAL_CREDENTIALS_REF = "guard-oauth-local-credentials"
_OAUTH_LOCAL_CREDENTIALS_STATE_KEY = "oauth_local_credentials"
_OAUTH_LOCAL_CREDENTIALS_HASH_KEY = "credentials_sha256"
_OAUTH_LOCAL_CREDENTIALS_REF_KEY = "credentials_ref"
_OAUTH_PRIMARY_SECRET_TIMEOUT_SECONDS = 2.0
_APPROVAL_GATE_POLICY_SOURCE = "approval-gate"
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
)


def _is_approval_gate_one_shot_policy(row: sqlite3.Row) -> bool:
    return str(row["source"]) == _APPROVAL_GATE_POLICY_SOURCE and row["expires_at"] is not None


_DEVICE_ROW_KEY = "local-device"
_MAX_RESOLVED_SCOPE_IDS = 200
_SQLITE_ID_BATCH_SIZE = 500
_WORKSPACE_POLICY_KEY_PREFIX = "workspace:"
_POLICY_INTEGRITY_STATE_KEY = "policy_integrity"
_POLICY_INTEGRITY_CONTROL_VERSION = 1

_SOURCE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def _normalize_source_name(source: str | None) -> str:
    """Normalize a connection source name.

    The default source is 'default'. Source names are used to namespace
    OAuth credentials in the local store, allowing multiple simultaneous
    connections (e.g. production + staging).
    """
    if source is None:
        return "default"
    normalized = source.strip().lower()
    if not normalized:
        return "default"
    if not _SOURCE_NAME_PATTERN.match(normalized):
        raise ValueError(f"Invalid source name: {source!r}. Source names must match [a-zA-Z0-9][a-zA-Z0-9_-]*")
    if len(normalized) > 64:
        raise ValueError(f"Invalid source name: {source!r}. Source names must be 64 characters or fewer.")
    return normalized


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
_LEGACY_SECRET_FINGERPRINT_PREFIX = "pbkdf2-sha256$"
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


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


def _allowed_origin_from_sync_url(sync_url: str) -> str | None:
    parsed = urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


_SECRET_FINGERPRINT_ITERATIONS = 200_000


def _secret_fingerprint(value: str) -> str:
    digest = scrypt(
        value.encode("utf-8"),
        salt=_SECRET_FINGERPRINT_SALT,
        n=_SECRET_FINGERPRINT_N,
        r=_SECRET_FINGERPRINT_R,
        p=_SECRET_FINGERPRINT_P,
        dklen=_SECRET_FINGERPRINT_DKLEN,
    ).hex()
    return f"{_SECRET_FINGERPRINT_PREFIX}{digest}"


def _legacy_secret_fingerprint(value: str) -> str:
    digest = pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        _SECRET_FINGERPRINT_SALT,
        _SECRET_FINGERPRINT_ITERATIONS,
    ).hex()
    return f"{_LEGACY_SECRET_FINGERPRINT_PREFIX}{digest}"


def _legacy_secret_sha256(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()  # codeql[py/weak-sensitive-data-hashing]


def _secret_matches_hash(value: str, expected_hash: str) -> bool:
    if expected_hash.startswith(_SECRET_FINGERPRINT_PREFIX):
        return _secret_fingerprint(value) == expected_hash
    if expected_hash.startswith(_LEGACY_SECRET_FINGERPRINT_PREFIX):
        return _legacy_secret_fingerprint(value) == expected_hash
    return _legacy_secret_sha256(value) == expected_hash


def _acquire_advisory_file_lock(handle) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            handle.seek(0)
            if not handle.read(1):
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise BlockingIOError from error
        return

    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise BlockingIOError from error


def _release_advisory_file_lock(handle) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class SecretStore(Protocol):
    """Credential persistence contract for local Guard secrets."""

    def set_secret(self, secret_id: str, value: str) -> None:
        """Store a secret value."""

    def get_secret(self, secret_id: str) -> str | None:
        """Fetch a secret value."""

    def delete_secret(self, secret_id: str) -> None:
        """Delete a secret value if it exists."""


class SystemKeyringSecretStore:
    """Cross-platform OS credential store backed by the Python keyring library."""

    _MACOS_KEYCHAIN_HEALTH_CACHE_TTL_SECONDS = 5.0
    _macos_keychain_health_cache: tuple[float, bool] | None = None
    _native_macos_security_reads_cache: tuple[tuple[int, int], bool] | None = None

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name

    @staticmethod
    def _load_keyring_module():
        """Load the optional keyring package.

        Returns None when the top-level package is genuinely absent. A keyring
        install that is present but fails to import (broken transitive import,
        backend init error, etc.) is allowed to propagate so callers can surface
        it rather than silently degrading credential storage.
        """
        test_keyring = SystemKeyringSecretStore._test_keyring_module()
        if test_keyring is not None:
            return test_keyring
        try:
            return importlib.import_module("keyring")
        except ModuleNotFoundError as exc:
            if exc.name == "keyring":
                return None
            raise

    @classmethod
    def _load_keyring_module_or_none(cls):
        """Return the keyring module, or None when it is absent or unusable.

        Any failure to initialize an installed-but-broken keyring is logged so
        the fallback to the encrypted-file store is never silent. Used by the
        availability probe and secret access, which must not let a keyring
        failure escape and crash the host harness.
        """
        try:
            return cls._load_keyring_module()
        except Exception:
            _store_logger.warning(
                "Guard system keyring backend could not be initialized; using encrypted-file fallback.",
                exc_info=True,
            )
            return None

    @staticmethod
    def _test_keyring_module():
        if not os.environ.get("PYTEST_CURRENT_TEST"):
            return None
        store_path_raw = os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
        if not store_path_raw:
            return None

        class _TestKeyringModule:
            @staticmethod
            def _store_path() -> Path:
                return Path(store_path_raw)

            @classmethod
            def _load(cls) -> dict[tuple[str, str], str]:
                store_path = cls._store_path()
                if not store_path.is_file():
                    return {}
                payload = json.loads(store_path.read_text(encoding="utf-8"))
                return {
                    (str(service_name), str(secret_id)): str(secret_value)
                    for service_name, secrets in payload.items()
                    if isinstance(service_name, str) and isinstance(secrets, dict)
                    for secret_id, secret_value in secrets.items()
                    if isinstance(secret_id, str) and isinstance(secret_value, str)
                }

            @classmethod
            def _persist(cls, secrets: dict[tuple[str, str], str]) -> None:
                payload: dict[str, dict[str, str]] = {}
                for (service_name, secret_id), secret_value in secrets.items():
                    payload.setdefault(service_name, {})[secret_id] = secret_value
                store_path = cls._store_path()
                store_path.parent.mkdir(parents=True, exist_ok=True)
                store_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

            @staticmethod
            def get_keyring():
                class _Backend:
                    priority = 1

                return _Backend()

            @classmethod
            def set_password(cls, service_name: str, secret_id: str, value: str) -> None:
                secrets = cls._load()
                secrets[(service_name, secret_id)] = value
                cls._persist(secrets)

            @classmethod
            def get_password(cls, service_name: str, secret_id: str) -> str | None:
                return cls._load().get((service_name, secret_id))

            @classmethod
            def delete_password(cls, service_name: str, secret_id: str) -> None:
                secrets = cls._load()
                secrets.pop((service_name, secret_id), None)
                cls._persist(secrets)

        return _TestKeyringModule

    @staticmethod
    def _load_macos_keyring_api_module():
        from keyring.backends.macOS import api as macos_keyring_api

        return macos_keyring_api

    @staticmethod
    def _macos_default_keychain_path() -> Path | None:
        result = SystemKeyringSecretStore._run_macos_security_command("default-keychain", "-d", "user")
        if result is None:
            return None
        raw_path = result.stdout.strip().strip('"').strip("'")
        if not raw_path:
            return None
        return Path(raw_path).expanduser()

    @staticmethod
    def _run_macos_security_command(*args: str) -> subprocess.CompletedProcess[str] | None:
        if sys.platform != "darwin":
            return None
        security_path = Path("/usr/bin/security")
        if not security_path.exists():
            return None
        try:
            result = subprocess.run(
                [str(security_path), *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            return None
        return result if result.returncode == 0 else None

    @classmethod
    def _macos_user_keychain_paths(cls) -> tuple[Path, ...]:
        result = cls._run_macos_security_command("list-keychains", "-d", "user")
        if result is None:
            return ()
        paths: list[Path] = []
        for line in result.stdout.splitlines():
            raw_path = line.strip().strip('"').strip("'")
            if raw_path:
                paths.append(Path(raw_path).expanduser())
        return tuple(paths)

    @classmethod
    def _macos_keychain_path_is_usable(cls, path: Path | None) -> bool:
        if path is None:
            return False
        expanded = path.expanduser()
        if not expanded.exists():
            return False
        return cls._run_macos_security_command("show-keychain-info", str(expanded)) is not None

    @staticmethod
    def _normalized_macos_keychain_path(path: Path) -> str:
        return os.path.realpath(os.fspath(path.expanduser()))

    @classmethod
    def _clear_macos_keychain_health_cache(cls) -> None:
        cls._macos_keychain_health_cache = None

    @classmethod
    def _macos_default_keychain_is_usable_uncached(cls) -> bool:
        path = cls._macos_default_keychain_path()
        if path is None:
            return False
        user_keychain_paths = cls._macos_user_keychain_paths()
        if not user_keychain_paths:
            return False
        normalized_default = cls._normalized_macos_keychain_path(path)
        normalized_user_paths: dict[str, Path] = {}
        for item in user_keychain_paths:
            normalized_user_paths.setdefault(cls._normalized_macos_keychain_path(item), item)
        if normalized_default not in normalized_user_paths:
            return False
        return all(cls._macos_keychain_path_is_usable(item) for item in normalized_user_paths.values())

    @classmethod
    def _macos_default_keychain_is_usable(cls) -> bool:
        if sys.platform != "darwin":
            return False
        cached = cls._macos_keychain_health_cache
        now = time.monotonic()
        if cached is not None and (now - cached[0]) < cls._MACOS_KEYCHAIN_HEALTH_CACHE_TTL_SECONDS:
            return cached[1]
        result = cls._macos_default_keychain_is_usable_uncached()
        cls._macos_keychain_health_cache = (now, result)
        return result

    @classmethod
    def _backend_is_available(cls) -> bool:
        keyring_module = cls._load_keyring_module_or_none()
        if keyring_module is None:
            return False
        try:
            backend = keyring_module.get_keyring()
        except Exception:
            return False
        backend_name = type(backend).__name__.lower()
        if backend_name == "failkeyring":
            return False
        priority = getattr(backend, "priority", None)
        return not (isinstance(priority, (int, float)) and priority <= 0)

    @classmethod
    def _is_available(cls) -> bool:
        if cls._test_keyring_module() is not None:
            return True
        if not cls._backend_is_available():
            return False
        if sys.platform == "darwin" and not cls._macos_default_keychain_is_usable():
            return False
        return True

    def set_secret(self, secret_id: str, value: str) -> None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            raise RuntimeError(
                "Guard system keyring backend is unavailable; the Python 'keyring' "
                "package could not be imported. Reinstall hol-guard to restore it."
            )
        keyring_module.set_password(self.service_name, secret_id, value)

    def get_secret(self, secret_id: str) -> str | None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            return None
        value = keyring_module.get_password(self.service_name, secret_id)
        return value if isinstance(value, str) and value else None

    @classmethod
    def _supports_native_macos_security_reads(cls) -> bool:
        if sys.platform != "darwin":
            return False
        loader_ref = cls._load_keyring_module
        api_loader_ref = cls._load_macos_keyring_api_module
        cache_key = (id(loader_ref), id(api_loader_ref))
        cached = cls._native_macos_security_reads_cache
        if cached is not None and cached[0] == cache_key:
            return cached[1]
        try:
            keyring_module = loader_ref()
        except Exception:
            keyring_module = None
        if keyring_module is None:
            cls._native_macos_security_reads_cache = (cache_key, False)
            return False
        try:
            api_loader_ref()
        except Exception:
            supported = False
        else:
            supported = True
        cls._native_macos_security_reads_cache = (cache_key, supported)
        return supported

    def _get_secret_without_macos_ui(self, secret_id: str) -> str | None:
        if not self._supports_native_macos_security_reads():
            return None
        set_interaction_allowed = None
        interaction_state = None
        data = None
        try:
            from ctypes import byref, c_ubyte

            macos_keyring_api = self._load_macos_keyring_api_module()
            # The macOS keyring backend returns password bytes here but exposes
            # its decoder under the historical cfstr_to_str name.
            cfstr_to_str = getattr(macos_keyring_api, "cfstr_to_str", None)
            cf_release = getattr(macos_keyring_api, "CFRelease", None)
            security_library = getattr(macos_keyring_api, "_sec", None)
            get_interaction_allowed = (
                getattr(security_library, "SecKeychainGetUserInteractionAllowed", None)
                if security_library is not None
                else None
            )
            set_interaction_allowed = (
                getattr(security_library, "SecKeychainSetUserInteractionAllowed", None)
                if security_library is not None
                else None
            )
            interaction_state: c_ubyte | None = None
            if get_interaction_allowed is not None:
                get_interaction_allowed.restype = macos_keyring_api.OS_status
                get_interaction_allowed.argtypes = [ctypes.POINTER(c_ubyte)]
                interaction_state = c_ubyte(1)
                status = get_interaction_allowed(byref(interaction_state))
                if status != 0:
                    interaction_state = None
            if set_interaction_allowed is not None:
                set_interaction_allowed.restype = macos_keyring_api.OS_status
                set_interaction_allowed.argtypes = [c_ubyte]
                set_interaction_allowed(0)
            query = macos_keyring_api.create_query(
                kSecClass=macos_keyring_api.k_("kSecClassGenericPassword"),
                kSecMatchLimit=macos_keyring_api.k_("kSecMatchLimitOne"),
                kSecAttrService=self.service_name,
                kSecAttrAccount=secret_id,
                kSecReturnData=True,
                kSecUseAuthenticationUI=macos_keyring_api.k_("kSecUseAuthenticationUIFail"),
            )
            data = macos_keyring_api.c_void_p()
            status = macos_keyring_api.SecItemCopyMatching(query, byref(data))
        except Exception:
            return None
        finally:
            if set_interaction_allowed is not None:
                restore_value = interaction_state.value if interaction_state is not None else 1
                with suppress(Exception):
                    set_interaction_allowed(restore_value)
        if status == 0:
            if not callable(cfstr_to_str):
                return None
            try:
                value = cfstr_to_str(data)
            except Exception:
                value = None
            finally:
                if data is not None and callable(cf_release):
                    with suppress(Exception):
                        cf_release(data)
            return value if isinstance(value, str) and value else None
        interaction_blocked_statuses = {
            macos_keyring_api.error.item_not_found,
            macos_keyring_api.error.keychain_denied,
            macos_keyring_api.error.sec_auth_failed,
            macos_keyring_api.error.plist_missing,
            macos_keyring_api.error.sec_interaction_not_allowed,
        }
        if status in interaction_blocked_statuses:
            return None
        return None  # unknown non-zero status

    def get_secret_with_timeout(self, secret_id: str, *, timeout_seconds: float = 0.0) -> str | None:
        _ = timeout_seconds
        if sys.platform != "darwin" and self._test_keyring_module() is not None:
            return self.get_secret(secret_id)
        if sys.platform == "darwin":
            if (
                self._test_keyring_module() is not None
                and getattr(type(self)._get_secret_without_macos_ui, "__name__", "") == "_get_secret_without_macos_ui"
            ):
                return self.get_secret(secret_id)
            if self._supports_native_macos_security_reads():
                return self._get_secret_without_macos_ui(secret_id)
            if self._test_keyring_module() is not None:
                return self.get_secret(secret_id)
            if self.service_name == _POLICY_INTEGRITY_SERVICE_NAME:
                # Passive policy-integrity reads must fail closed when native
                # no-UI access is unavailable.
                return None
            return None
        if self._supports_native_macos_security_reads():
            return self._get_secret_without_macos_ui(secret_id)
        return self.get_secret(secret_id)

    def delete_secret(self, secret_id: str) -> None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            return
        try:
            keyring_module.delete_password(self.service_name, secret_id)
        except Exception:
            return


class EncryptedFileSecretStore:
    """Encrypted file-based secret store for Guard credentials.

    The Fernet key and encrypted payloads both live inside the same per-user Guard
    directory, so this is encrypted-at-rest fallback storage rather than a substitute
    for an OS credential manager.
    """

    def __init__(self, guard_home: Path) -> None:
        self.base_dir = guard_home / "secrets"
        self.key_path = self.base_dir / "key.bin"
        self._fernet: Fernet | None = None

    def _ensure_ready(self) -> None:
        if self._fernet is not None:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Owner-only directory access is required for encrypted secret material.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
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

    def delete_secret(self, secret_id: str) -> None:
        self._ensure_ready()
        path = self._path_for(secret_id)
        if path.exists():
            path.unlink()

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


class UnavailableSecretStore:
    """Secret store placeholder for platforms without safe credential storage."""

    def __init__(self, guard_home: Path | None = None) -> None:
        self._legacy_fallback = EncryptedFileSecretStore(guard_home) if guard_home is not None else None

    def set_secret(self, secret_id: str, value: str) -> None:
        _ = (secret_id, value)
        raise RuntimeError(
            "Guard local credentials require an available OS credential store. "
            "Fix the system credential store, then sign in again."
        )

    def get_secret(self, secret_id: str) -> str | None:
        _ = secret_id
        return None

    def delete_secret(self, secret_id: str) -> None:
        if self._legacy_fallback is None:
            return
        legacy_path = self._legacy_fallback._path_for(secret_id)
        with suppress(OSError):
            legacy_path.unlink()


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

    def delete_secret(self, secret_id: str) -> None:
        for store in (self.primary, self.fallback):
            try:
                store.delete_secret(secret_id)
            except Exception:
                _store_logger.warning(
                    "Failed to delete Guard secret from %s",
                    type(store).__name__,
                )
                continue


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


def _set_private_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError as exc:
        _store_logger.debug("Could not set private mode %o on %s: %s", mode, path, exc)
        return


def _system_keyring_availability_cache_path(guard_home: Path) -> Path:
    return guard_home / _SYSTEM_KEYRING_AVAILABILITY_CACHE_FILE


def _read_system_keyring_availability_cache(guard_home: Path) -> bool | None:
    if sys.platform != "darwin":
        return None
    path = _system_keyring_availability_cache_path(guard_home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    checked_at = payload.get("checked_at")
    available = payload.get("available")
    if isinstance(checked_at, bool) or not isinstance(checked_at, (int, float)):
        return None
    if not isinstance(available, bool):
        return None
    if (time.time() - float(checked_at)) >= _SYSTEM_KEYRING_AVAILABILITY_CACHE_TTL_SECONDS:
        return None
    return available


def _write_system_keyring_availability_cache(guard_home: Path, *, available: bool) -> None:
    if sys.platform != "darwin":
        return
    path = _system_keyring_availability_cache_path(guard_home)
    tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    payload = {
        "available": available,
        "checked_at": time.time(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        _set_private_mode(tmp_path, _GUARD_STORE_PRIVATE_FILE_MODE)
        tmp_path.replace(path)
    except OSError:
        return
    finally:
        with suppress(OSError):
            tmp_path.unlink()


def _system_keyring_is_available(guard_home: Path, *, use_cache: bool = True) -> bool:
    cached = _read_system_keyring_availability_cache(guard_home) if use_cache else None
    if cached is not None:
        return cached
    if not use_cache and sys.platform == "darwin":
        SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    available = SystemKeyringSecretStore._is_available()
    _write_system_keyring_availability_cache(guard_home, available=available)
    return available


def _build_oauth_secret_store(guard_home: Path) -> SecretStore:
    fallback_store = EncryptedFileSecretStore(guard_home)
    if sys.platform == "darwin":
        cached_availability = _read_system_keyring_availability_cache(guard_home)
        if cached_availability is True:
            return FallbackSecretStore(
                SystemKeyringSecretStore(service_name="hol-guard.oauth"),
                fallback_store,
            )
        if _system_keyring_is_available(guard_home, use_cache=False):
            return FallbackSecretStore(
                SystemKeyringSecretStore(service_name="hol-guard.oauth"),
                fallback_store,
            )
        return UnavailableSecretStore(guard_home)
    if _system_keyring_is_available(guard_home):
        return FallbackSecretStore(
            SystemKeyringSecretStore(service_name="hol-guard.oauth"),
            fallback_store,
        )
    return fallback_store


def _build_policy_integrity_secret_store() -> SystemKeyringSecretStore | None:
    if sys.platform == "darwin":
        if SystemKeyringSecretStore._test_keyring_module() is not None:
            return SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME)
        if not SystemKeyringSecretStore._backend_is_available():
            return None
        if not SystemKeyringSecretStore._supports_native_macos_security_reads():
            return None
        return SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME)
    if SystemKeyringSecretStore._backend_is_available():
        return SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME)
    return None


def _secret_store_backend_name(secret_store: SecretStore) -> str:
    if isinstance(secret_store, SystemKeyringSecretStore):
        return "system-keyring"
    if isinstance(secret_store, EncryptedFileSecretStore):
        return "encrypted-file"
    if isinstance(secret_store, UnavailableSecretStore):
        return "unavailable"
    if isinstance(secret_store, FallbackSecretStore):
        return _secret_store_backend_name(secret_store.primary)
    return "unknown"


def _secret_store_fallback_backend_name(secret_store: SecretStore) -> str | None:
    if isinstance(secret_store, FallbackSecretStore):
        return _secret_store_backend_name(secret_store.fallback)
    return None


def _should_warn_on_slow_store_transactions() -> bool:
    value = os.environ.get(_SLOW_STORE_WARNING_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


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


def receipt_index_statements() -> list[str]:
    return [
        ("create index if not exists idx_receipts_harness_artifact on runtime_receipts(harness, artifact_id)"),
        ("create index if not exists idx_receipts_timestamp_harness on runtime_receipts(timestamp, harness)"),
        ("create index if not exists idx_receipts_timestamp_desc on runtime_receipts(timestamp desc)"),
        ("create index if not exists idx_receipts_harness_timestamp_desc on runtime_receipts(harness, timestamp desc)"),
        (
            "create index if not exists idx_receipts_harness_artifact_timestamp_desc "
            "on runtime_receipts(harness, artifact_id, timestamp desc)"
        ),
        (
            "create index if not exists idx_receipts_approval_request_decision "
            "on runtime_receipts(approval_request_id, policy_decision)"
        ),
    ]


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


def _validate_scoped_policy_artifact_target(scope: str, artifact_id: str | None) -> None:
    if scope not in {"harness", "global"}:
        return
    if artifact_id is None or not artifact_id.strip():
        return
    if not artifact_id.startswith("family:"):
        return
    family = artifact_id.removeprefix("family:").strip().lower()
    if family not in _SCOPED_HARNESS_FAMILIES:
        msg = "unsupported_scoped_policy_family"
        raise ValueError(msg)


def _artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return artifact_id if family in _SCOPED_HARNESS_FAMILIES else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_HARNESS_FAMILIES:
        return None
    return f"family:{family}"


def _runtime_scoped_exact_match_key(
    artifact_id: str | None,
    runtime_exact_match_context: str | None = None,
) -> str | None:
    if artifact_id is None or not artifact_id.strip() or artifact_id.startswith("family:"):
        return None
    family_key = _artifact_family_key(artifact_id)
    if family_key is None or _family_key_value(family_key) not in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    if runtime_exact_match_context is None:
        digest = sha256(artifact_id.encode("utf-8")).hexdigest()
    else:
        digest = sha256(
            json.dumps(
                {
                    "artifact_id": artifact_id,
                    "context": runtime_exact_match_context,
                    "version": 2,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return f"{_RUNTIME_SCOPED_EXACT_MATCH_PREFIX}{digest}"


def runtime_tool_action_exact_match_context(
    *,
    config_path: str | None,
    source_scope: str | None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
) -> str | None:
    if not config_path and not source_scope and not raw_command_text and not wrapper_chain:
        return None
    payload: dict[str, object] = {
        "config_path": str(Path(config_path).expanduser()) if config_path else None,
        "source_scope": source_scope,
        "raw_command_text": raw_command_text,
        "wrapper_chain": [item for item in wrapper_chain or () if isinstance(item, str) and item],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def browser_mcp_exact_match_context(
    *,
    intent: str | None,
    operation: str | None,
    target_origin: str | None,
    target_path_prefix: str | None,
    profile_mode: str | None,
    mcp_server_identity_hash: str | None,
    mcp_tool_identity_hash: str | None,
    mcp_schema_hash: str | None,
    sensitive_surface_flags: Sequence[object] | None = None,
) -> str | None:
    """Build a browser MCP exact-match context for stable identity dedup.

    The context captures security-relevant fields (intent, origin, path,
    profile, sensitive surfaces) while volatile fields are already stripped
    by the browser intent normalizer.
    """
    if not intent and not operation and not target_origin:
        return None
    flags: list[str] = []
    if sensitive_surface_flags is not None:
        flags = sorted(str(f) for f in sensitive_surface_flags if isinstance(f, str) and f)
    payload: dict[str, object] = {
        "intent": intent,
        "operation": operation,
        "target_origin": target_origin,
        "target_path_prefix": target_path_prefix,
        "profile_mode": profile_mode,
        "server_identity_hash": mcp_server_identity_hash,
        "tool_identity_hash": mcp_tool_identity_hash,
        "schema_hash": mcp_schema_hash,
        "sensitive_surface_flags": flags,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _is_runtime_scoped_exact_match_key(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(_RUNTIME_SCOPED_EXACT_MATCH_PREFIX)


def _scoped_runtime_row_requires_exact_match(
    *,
    scope: str,
    stored_artifact_id: str | None,
    stored_artifact_hash: str | None,
    source: str,
    requested_artifact_id: str | None,
    requested_runtime_exact_match_key: str | None = None,
) -> bool:
    if scope not in {"harness", "global"}:
        return False
    if source in REMOTE_POLICY_SOURCES:
        return False
    family_key = _artifact_family_key(stored_artifact_id)
    if family_key is None or _family_key_value(family_key) not in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return False
    expected_exact_keys = {
        key
        for key in (
            _runtime_scoped_exact_match_key(requested_artifact_id),
            requested_runtime_exact_match_key,
        )
        if key is not None
    }
    if not expected_exact_keys:
        return True
    return stored_artifact_hash not in expected_exact_keys


def _warn_only_policy_integrity_status(status: str, state: Mapping[str, object], *, source: str = "local") -> bool:
    if state.get("enforcement") != "warn":
        return False
    if source != "approval-gate":
        return False
    if status == "missing_integrity":
        return True
    if status != "degraded_mode":
        return False
    reasons = state.get("degraded_reasons")
    if not isinstance(reasons, list):
        return False
    if not reasons:
        return False
    allowed_reasons = {
        "system_keyring_unavailable",
        "policy_integrity_key_unavailable",
        "policy_integrity_control_unavailable",
    }
    return all(isinstance(reason, str) and reason in allowed_reasons for reason in reasons)


def _policy_integrity_ready_for_local_write(payload: Mapping[str, object]) -> bool:
    trust = payload.get("trust_status")
    if not isinstance(trust, Mapping):
        return False
    counts = payload.get("counts")
    if not isinstance(counts, Mapping):
        return False
    invalid_rows = 0
    for status in _POLICY_INTEGRITY_STATUSES:
        if status == "valid":
            continue
        count = counts.get(status)
        if isinstance(count, int) and count > 0:
            invalid_rows += count
    return payload.get("mode") == "protected" and trust.get("remembered_rules") == "enforced" and invalid_rows == 0


def _policy_integrity_setup_safe_for_local_write(payload: Mapping[str, object]) -> bool:
    counts = payload.get("counts")
    if not isinstance(counts, Mapping):
        return False
    eligible_invalid_rows = 0
    for status in _POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES:
        count = counts.get(status)
        if isinstance(count, int) and count > 0:
            eligible_invalid_rows += count
    return eligible_invalid_rows > 0


def _family_key_value(family_key: str) -> str:
    if family_key.startswith("family:"):
        return family_key.removeprefix("family:")
    return family_key


def _row_mapping(row: sqlite3.Row) -> dict[str, object]:
    keys = row.keys()
    return {key: row[key] for key in keys}


def _string_value(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _int_value(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _mapping_int(payload: Mapping[str, object], key: str) -> int | None:
    return _int_value(payload.get(key))


_ChunkT = TypeVar("_ChunkT")


def _chunks(values: Sequence[_ChunkT], size: int) -> Iterator[list[_ChunkT]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lease_expiry(now: str, lease_seconds: int) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=max(lease_seconds, 1))).isoformat()


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _transport_value(value: object) -> TransportKind:
    if value == "local":
        return "local"
    if value == "remote":
        return "remote"
    if value == "hybrid":
        return "hybrid"
    return "local"


__all__ = tuple(name for name in globals() if not (name.startswith("__") and name.endswith("__")))
