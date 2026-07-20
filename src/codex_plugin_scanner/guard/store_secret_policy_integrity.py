"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .policy_integrity import POLICY_INTEGRITY_VERSION

# ruff: noqa: F403,F405
from .store_base import *


def _facade_store_attr(name: str, fallback: object) -> object:
    store_module = sys.modules.get("codex_plugin_scanner.guard.store")
    if store_module is None:
        return fallback
    return getattr(store_module, name, fallback)


def _set_private_mode_compat(path: Path, mode: int) -> None:
    setter = _facade_store_attr("_set_private_mode", _set_private_mode)
    if not callable(setter):
        _set_private_mode(path, mode)
        return
    setter(path, mode)


def _build_oauth_secret_store_compat(guard_home: Path) -> SecretStore:
    builder = _facade_store_attr("_build_oauth_secret_store", _build_oauth_secret_store)
    if not callable(builder):
        return _build_oauth_secret_store(guard_home)
    return cast(SecretStore, builder(guard_home))


def _build_policy_integrity_secret_store_compat() -> SystemKeyringSecretStore | None:
    builder = _facade_store_attr(
        "_build_policy_integrity_secret_store",
        _build_policy_integrity_secret_store,
    )
    if not callable(builder):
        return _build_policy_integrity_secret_store()
    secret_store = builder()
    if secret_store is None or isinstance(secret_store, SystemKeyringSecretStore):
        return secret_store
    return cast(SystemKeyringSecretStore, secret_store)


_POLICY_INTEGRITY_LOOKUP_UNSET = object()
_OAUTH_SECRET_STORE_UNSET = object()
_POLICY_INTEGRITY_SECRET_STORE_UNSET = object()


class StoreSecretPolicyIntegrityMixin:
    def __init__(
        self,
        guard_home: Path,
        *,
        guard_event_queue_limit: int = 1000,
        prime_policy_integrity: bool = True,
        source: str = "default",
    ) -> None:
        self.guard_home = guard_home
        self.guard_home.mkdir(parents=True, exist_ok=True)
        _set_private_mode_compat(self.guard_home, _GUARD_STORE_PRIVATE_DIR_MODE)
        self.__oauth_secret_store = _OAUTH_SECRET_STORE_UNSET
        self.__policy_integrity_secret_store = _POLICY_INTEGRITY_SECRET_STORE_UNSET
        self._cached_oauth_secret_payload: tuple[str, str, str] | None = None
        self._cached_policy_integrity_secret_material: tuple[str | None, float, tuple[bytes, str]] | None = None
        self._cached_policy_integrity_control_state: tuple[str | None, float, dict[str, object]] | None = None
        self._startup_prefetched_policy_integrity_secret_material: object | tuple[bytes | None, str | None] = (
            _POLICY_INTEGRITY_LOOKUP_UNSET
        )
        self._startup_prefetched_policy_integrity_trusted_state: object | dict[str, object] | None = (
            _POLICY_INTEGRITY_LOOKUP_UNSET
        )
        self._startup_prefetched_policy_integrity_repair_failed = False
        self._policy_integrity_key_ref = self._build_scoped_secret_ref(_POLICY_INTEGRITY_KEY_REF)
        self._policy_integrity_control_ref = self._build_scoped_secret_ref(_POLICY_INTEGRITY_CONTROL_REF)
        self._guard_source = _normalize_source_name(source)
        if self._guard_source == "default":
            oauth_ref_prefix = _OAUTH_LOCAL_CREDENTIALS_REF
            oauth_state_key = _OAUTH_LOCAL_CREDENTIALS_STATE_KEY
        else:
            oauth_ref_prefix = f"{_OAUTH_LOCAL_CREDENTIALS_REF}:{self._guard_source}"
            oauth_state_key = f"{_OAUTH_LOCAL_CREDENTIALS_STATE_KEY}:{self._guard_source}"
        self._oauth_local_credentials_ref = self._build_scoped_secret_ref(oauth_ref_prefix)
        self._oauth_local_credentials_state_key = oauth_state_key
        self._guard_event_queue_limit = max(1, guard_event_queue_limit)
        self._prime_policy_integrity_on_initialize = prime_policy_integrity
        self.path = self.guard_home / "guard.db"
        self._initialize()

    @property
    def guard_source(self) -> str:
        """Return the normalized connection source bound to this store view."""
        return self._guard_source

    @property
    def _oauth_secret_store(self) -> SecretStore:
        secret_store = getattr(self, "_StoreSecretPolicyIntegrityMixin__oauth_secret_store", _OAUTH_SECRET_STORE_UNSET)
        if secret_store is _OAUTH_SECRET_STORE_UNSET:
            secret_store = _build_oauth_secret_store_compat(self.guard_home)
            self.__oauth_secret_store = secret_store
        return cast(SecretStore, secret_store)

    @_oauth_secret_store.setter
    def _oauth_secret_store(self, value: SecretStore | object) -> None:
        self.__oauth_secret_store = value

    @property
    def _policy_integrity_secret_store(self) -> SystemKeyringSecretStore | None:
        secret_store = getattr(
            self,
            "_StoreSecretPolicyIntegrityMixin__policy_integrity_secret_store",
            _POLICY_INTEGRITY_SECRET_STORE_UNSET,
        )
        if secret_store is _POLICY_INTEGRITY_SECRET_STORE_UNSET:
            secret_store = _build_policy_integrity_secret_store_compat()
            self.__policy_integrity_secret_store = secret_store
        return cast(SystemKeyringSecretStore | None, secret_store)

    @_policy_integrity_secret_store.setter
    def _policy_integrity_secret_store(self, value: SystemKeyringSecretStore | None | object) -> None:
        self.__policy_integrity_secret_store = value

    def _build_scoped_secret_ref(self, prefix: str) -> str:
        scoped_home = str(self.guard_home.expanduser().resolve())
        scoped_hash = sha256(scoped_home.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}:{scoped_hash}"

    @staticmethod
    def _versioned_secret_ref(base_ref: str, value_hash: str) -> str:
        return f"{base_ref}:{value_hash[:16]}"

    def _mirror_oauth_secret_to_fallback(self, secret_id: str, value: str) -> None:
        secret_store = self._oauth_secret_store
        if not isinstance(secret_store, FallbackSecretStore):
            return
        if not isinstance(secret_store.fallback, EncryptedFileSecretStore):
            return
        fallback_value = self._get_secret_from_store(secret_store.fallback, secret_id)
        if fallback_value == value:
            return
        try:
            secret_store.fallback.set_secret(secret_id, value)
        except Exception:
            _store_logger.warning(
                "Failed to mirror OAuth credentials into encrypted fallback store; "
                "headless environments may not be able to read credentials."
            )
            return

    def _assert_oauth_secret_persisted(self, secret_id: str, value: str) -> None:
        secret_store = self._oauth_secret_store
        if sys.platform == "darwin" and isinstance(secret_store, SystemKeyringSecretStore):
            persisted_value = self._get_secret_from_primary_store(secret_store, secret_id)
            if persisted_value == value:
                return
            if self._oauth_primary_direct_test_reads_are_safe() and secret_store.get_secret(secret_id) == value:
                return
            raise RuntimeError("Guard could not persist local Guard Cloud authorization securely.")
        if sys.platform == "darwin" and isinstance(secret_store, FallbackSecretStore):
            primary = secret_store.primary
            if isinstance(primary, SystemKeyringSecretStore):
                persisted_value = self._get_secret_from_primary_store(primary, secret_id)
                if persisted_value == value:
                    return
                if self._oauth_primary_direct_test_reads_are_safe() and primary.get_secret(secret_id) == value:
                    return
                if isinstance(secret_store.fallback, EncryptedFileSecretStore):
                    fallback_value = self._get_secret_from_store(secret_store.fallback, secret_id)
                    if fallback_value == value:
                        return
                raise RuntimeError("Guard could not persist local Guard Cloud authorization securely.")
        if isinstance(secret_store, UnavailableSecretStore):
            raise RuntimeError(
                "Guard local credentials require an available OS credential store. "
                "Fix the system credential store, then sign in again."
            )
        if isinstance(secret_store, FallbackSecretStore) and isinstance(
            secret_store.fallback,
            EncryptedFileSecretStore,
        ):
            fallback_value = self._get_secret_from_store(secret_store.fallback, secret_id)
            if fallback_value == value:
                return
            raise RuntimeError(
                "Guard could not persist local Guard Cloud authorization into the encrypted local store."
            )
        persisted_value = self._get_secret_from_store(secret_store, secret_id)
        if persisted_value == value:
            return
        raise RuntimeError("Guard could not persist local Guard Cloud authorization securely.")

    def _get_secret_from_store(self, store: SecretStore, secret_id: str) -> str | None:
        try:
            return store.get_secret(secret_id)
        except Exception:
            return None

    def _get_secret_from_primary_store(self, store: SecretStore, secret_id: str) -> str | None:
        if isinstance(store, SystemKeyringSecretStore):
            return store.get_secret_with_timeout(
                secret_id,
                timeout_seconds=_OAUTH_PRIMARY_SECRET_TIMEOUT_SECONDS,
            )
        return self._get_secret_from_store(store, secret_id)

    def _get_policy_integrity_secret_from_store(self, secret_id: str) -> str | None:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None:
            return None
        if isinstance(secret_store, SystemKeyringSecretStore):
            return secret_store.get_secret_with_timeout(
                secret_id,
                timeout_seconds=_POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS,
            )
        return self._get_secret_from_store(secret_store, secret_id)

    @staticmethod
    def _should_skip_policy_integrity_keychain_access(secret_store: SecretStore) -> bool:
        return (
            isinstance(secret_store, SystemKeyringSecretStore)
            and sys.platform == "darwin"
            and secret_store._test_keyring_module() is None
            and not secret_store._supports_native_macos_security_reads()
        )

    def _clear_policy_integrity_cache(self) -> None:
        self._cached_policy_integrity_secret_material = None
        self._cached_policy_integrity_control_state = None

    def _oauth_primary_reads_are_no_ui_safe(self) -> bool:
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            secret_store = secret_store.primary
        if not isinstance(secret_store, SystemKeyringSecretStore):
            return False
        if sys.platform != "darwin":
            return False
        return secret_store._supports_native_macos_security_reads() or self._oauth_primary_reads_are_test_safe()

    def _oauth_primary_reads_are_repair_safe(self) -> bool:
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            secret_store = secret_store.primary
        if not isinstance(secret_store, SystemKeyringSecretStore):
            return False
        if sys.platform != "darwin":
            return True
        return secret_store._supports_native_macos_security_reads() or self._oauth_primary_reads_are_test_safe()

    def _oauth_primary_reads_are_test_safe(self) -> bool:
        if os.environ.get("PYTEST_CURRENT_TEST", "").strip() == "":
            return False
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            secret_store = secret_store.primary
        if not isinstance(secret_store, SystemKeyringSecretStore):
            return False
        return secret_store._load_keyring_module_or_none() is not None

    def _oauth_primary_direct_test_reads_are_safe(self) -> bool:
        if os.environ.get("PYTEST_CURRENT_TEST", "").strip() == "":
            return False
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            secret_store = secret_store.primary
        if not isinstance(secret_store, SystemKeyringSecretStore):
            return False
        test_keyring = SystemKeyringSecretStore._test_keyring_module()
        if test_keyring is None:
            return False
        return secret_store._load_keyring_module_or_none() is test_keyring

    def _oauth_primary_secret_definitely_missing(self, secret_ref: str) -> bool:
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            secret_store = secret_store.primary
        if not isinstance(secret_store, SystemKeyringSecretStore):
            return False
        if not self._oauth_primary_reads_are_repair_safe():
            return False
        return secret_store.get_secret(secret_ref) is None

    def _oauth_fallback_recovery_allowed(self) -> bool:
        return sys.platform != "darwin"

    def _get_secret_candidates(
        self,
        secret_store: SecretStore,
        secret_id: str,
        expected_hash_value: str | None,
        *,
        prefer_fallback_first: bool = False,
        fallback_token_hint: str | None = None,
    ) -> list[str]:
        if isinstance(secret_store, FallbackSecretStore):
            if prefer_fallback_first and isinstance(secret_store.fallback, EncryptedFileSecretStore):
                fallback_token = fallback_token_hint
                if fallback_token is None:
                    fallback_token = self._get_secret_from_store(secret_store.fallback, secret_id)
                if fallback_token is not None and (
                    expected_hash_value is None or _secret_matches_hash(fallback_token, expected_hash_value)
                ):
                    return [fallback_token]
                primary_token = self._get_secret_from_primary_store(secret_store.primary, secret_id)
                if primary_token is not None and (
                    expected_hash_value is None or _secret_matches_hash(primary_token, expected_hash_value)
                ):
                    return [primary_token]
                if fallback_token is not None and expected_hash_value is not None:
                    return []
            primary_token = self._get_secret_from_primary_store(secret_store.primary, secret_id)
            if primary_token is not None:
                if expected_hash_value is None or _secret_matches_hash(primary_token, expected_hash_value):
                    return [primary_token]
                fallback_token = self._get_secret_from_store(secret_store.fallback, secret_id)
                if fallback_token is None or fallback_token == primary_token:
                    return [primary_token]
                return [primary_token, fallback_token]
            fallback_token = self._get_secret_from_store(secret_store.fallback, secret_id)
            if fallback_token is None:
                return []
            return [fallback_token]
        token = self._get_secret_from_primary_store(secret_store, secret_id)
        if token is None:
            return []
        return [token]

    def _policy_integrity_backend_name(self) -> str:
        if self._policy_integrity_secret_store is None:
            return "unavailable"
        return _secret_store_backend_name(self._policy_integrity_secret_store)

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        cached = self._cached_policy_integrity_secret_material
        marker = self._policy_integrity_cache_marker()
        now = time.monotonic()
        if cached is not None and cached[0] == marker and (now - cached[1]) < _POLICY_INTEGRITY_CACHE_TTL_SECONDS:
            return cached[2]
        secret_store = self._policy_integrity_secret_store
        if secret_store is None:
            return None, None
        if self._should_skip_policy_integrity_keychain_access(secret_store):
            return None, None
        encoded_key = self._get_policy_integrity_secret_from_store(self._policy_integrity_key_ref)
        if encoded_key is None and create:
            generated_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
            try:
                secret_store.set_secret(self._policy_integrity_key_ref, generated_key)
            except Exception:
                return None, None
            encoded_key = self._get_policy_integrity_secret_from_store(self._policy_integrity_key_ref)
        if encoded_key is None:
            return None, None
        try:
            raw_key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
        except Exception:
            return None, None
        if len(raw_key) != 32:
            return None, None
        key_id = self._versioned_secret_ref(self._policy_integrity_key_ref, sha256(raw_key).hexdigest())
        self._cached_policy_integrity_secret_material = (marker, now, (raw_key, key_id))
        return raw_key, key_id

    @staticmethod
    def _default_policy_integrity_control_state() -> dict[str, object]:
        return {
            "cutover_complete": False,
            "generation": 0,
            "pending_generation": None,
            "version": _POLICY_INTEGRITY_CONTROL_VERSION,
        }

    @staticmethod
    def _normalize_policy_integrity_control_state(payload: object) -> dict[str, object] | None:
        if not isinstance(payload, dict):
            return None
        version = payload.get("version")
        generation = payload.get("generation")
        pending_generation = payload.get("pending_generation")
        cutover_complete = payload.get("cutover_complete")
        if version != _POLICY_INTEGRITY_CONTROL_VERSION:
            return None
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            return None
        if pending_generation is not None and (
            isinstance(pending_generation, bool)
            or not isinstance(pending_generation, int)
            or pending_generation <= generation
        ):
            return None
        if not isinstance(cutover_complete, bool):
            return None
        return {
            "cutover_complete": cutover_complete,
            "generation": generation,
            "pending_generation": pending_generation,
            "version": version,
        }

    def _load_policy_integrity_control_state(self, *, create: bool) -> dict[str, object] | None:
        cached = self._cached_policy_integrity_control_state
        marker = self._policy_integrity_cache_marker()
        now = time.monotonic()
        if cached is not None and cached[0] == marker and (now - cached[1]) < _POLICY_INTEGRITY_CACHE_TTL_SECONDS:
            return dict(cached[2])
        secret_store = self._policy_integrity_secret_store
        if secret_store is None:
            return None
        if self._should_skip_policy_integrity_keychain_access(secret_store):
            return None
        payload_json = self._get_policy_integrity_secret_from_store(self._policy_integrity_control_ref)
        payload: dict[str, object] | None = None
        if payload_json is not None:
            try:
                payload = self._normalize_policy_integrity_control_state(json.loads(payload_json))
            except json.JSONDecodeError:
                payload = None
        if payload is not None:
            self._cached_policy_integrity_control_state = (marker, now, dict(payload))
        if payload is not None or not create:
            return payload
        payload = self._default_policy_integrity_control_state()
        if not self._store_policy_integrity_control_state(payload):
            return None
        return self._load_policy_integrity_control_state(create=False)

    def _store_policy_integrity_control_state(self, payload: Mapping[str, object]) -> bool:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None:
            return False
        normalized = self._normalize_policy_integrity_control_state(payload)
        if normalized is None:
            return False
        self._cached_policy_integrity_control_state = None
        try:
            secret_store.set_secret(
                self._policy_integrity_control_ref,
                json.dumps(normalized, sort_keys=True, separators=(",", ":")),
            )
        except Exception:
            return False
        self._cached_policy_integrity_control_state = (
            self._policy_integrity_cache_marker(),
            time.monotonic(),
            dict(normalized),
        )
        return True

    def _finalize_policy_integrity_control_state(self, payload: Mapping[str, object]) -> None:
        self._store_policy_integrity_control_state(payload)

    def _load_workflow_capability_control(self) -> str | None:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None or self._should_skip_policy_integrity_keychain_access(secret_store):
            return None
        reference = self._build_scoped_secret_ref("guard-workflow-capability-control")
        return self._get_policy_integrity_secret_from_store(reference)

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None or self._should_skip_policy_integrity_keychain_access(secret_store):
            return False
        reference = self._build_scoped_secret_ref("guard-workflow-capability-control")
        try:
            secret_store.set_secret(reference, encoded)
        except Exception:
            return False
        return self._get_policy_integrity_secret_from_store(reference) == encoded

    def _policy_integrity_path_warnings(self) -> list[str]:
        warnings: list[str] = []
        if self.guard_home.is_symlink():
            warnings.append(POLICY_INTEGRITY_REASON_GUARD_HOME_SYMLINK)
        if self.path.exists() and self.path.is_symlink():
            warnings.append(POLICY_INTEGRITY_REASON_GUARD_DB_SYMLINK)
        if os.name == "nt":
            return warnings
        try:
            if self.guard_home.stat().st_mode & 0o077:
                warnings.append(POLICY_INTEGRITY_REASON_GUARD_HOME_PERMISSIONS)
        except OSError:
            warnings.append(POLICY_INTEGRITY_REASON_GUARD_HOME_INACCESSIBLE)
        if not self.path.exists():
            return warnings
        try:
            if self.path.stat().st_mode & 0o077:
                warnings.append(POLICY_INTEGRITY_REASON_GUARD_DB_PERMISSIONS)
        except OSError:
            warnings.append(POLICY_INTEGRITY_REASON_GUARD_DB_INACCESSIBLE)
        return warnings

    @staticmethod
    def _load_policy_integrity_state(connection: sqlite3.Connection) -> dict[str, object] | None:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (_POLICY_INTEGRITY_STATE_KEY,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row["payload_json"]))
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _load_policy_integrity_state_cache_marker(connection: sqlite3.Connection) -> str | None:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (_POLICY_INTEGRITY_STATE_KEY,),
        ).fetchone()
        if row is None:
            return None
        payload_json = row["payload_json"]
        return str(payload_json) if isinstance(payload_json, str) and payload_json else None

    def _policy_integrity_cache_marker(self) -> str | None:
        with self._connect() as connection:
            return self._load_policy_integrity_state_cache_marker(connection)

    @staticmethod
    def _store_policy_integrity_state(
        connection: sqlite3.Connection,
        payload: Mapping[str, object],
        *,
        now: str,
    ) -> None:
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values (?, ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (
                _POLICY_INTEGRITY_STATE_KEY,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                now,
            ),
        )

    @staticmethod
    def _count_legacy_local_policy_rows(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            f"""
            select count(*) as total
            from policy_decisions
            where source not in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}
              and (
                integrity_version is null
                or integrity_version != {POLICY_INTEGRITY_VERSION}
                or payload_hash is null
                or payload_mac is null
                or integrity_key_id is null
                or signed_at is null
              )
            """,
            _REMOTE_POLICY_SOURCE_PARAMS,
        ).fetchone()
        return int(row["total"]) if row is not None else 0

    @staticmethod
    def _count_local_policy_rows(
        connection: sqlite3.Connection,
        *,
        harness: str | None = None,
    ) -> int:
        query = f"""
            select count(*) as total
            from policy_decisions
            where source not in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}
        """
        params: tuple[object, ...] = _REMOTE_POLICY_SOURCE_PARAMS
        if harness is not None:
            query += " and harness = ?"
            params = (*params, harness)
        row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row is not None else 0

    def _advance_policy_integrity_generation(
        self,
        connection: sqlite3.Connection,
        *,
        now: str,
        key: bytes,
        key_id: str,
        trusted_state: dict[str, object],
        force_sign_decision_ids: set[int] | None = None,
        harness: str | None = None,
    ) -> dict[str, object]:
        current_generation = _mapping_int(trusted_state, "generation")
        if current_generation is None:
            raise RuntimeError("Guard policy integrity control state is invalid.")
        next_generation = current_generation + 1
        sign_ids = force_sign_decision_ids or set()
        pending_state: dict[str, object] = {
            "cutover_complete": True,
            "generation": current_generation,
            "pending_generation": next_generation,
            "version": _POLICY_INTEGRITY_CONTROL_VERSION,
        }
        if not self._store_policy_integrity_control_state(pending_state):
            raise RuntimeError("Guard could not persist the policy integrity control state.")
        for row in self._load_local_policy_rows(connection, harness=harness):
            decision_id = int(row["decision_id"])
            should_sign = decision_id in sign_ids
            if not should_sign:
                integrity_result = verify_local_policy_row(
                    _row_mapping(row),
                    key=key,
                    key_id=key_id,
                    degraded_mode=False,
                    trusted_generation=current_generation,
                )
                should_sign = integrity_result.status == "valid"
            if not should_sign:
                continue
            signed = sign_local_policy_row(
                _row_mapping(row),
                key,
                key_id=key_id,
                signed_at=now,
                generation=next_generation,
            )
            connection.execute(
                """
                update policy_decisions
                set integrity_version = ?,
                    integrity_generation = ?,
                    payload_hash = ?,
                    payload_mac = ?,
                    integrity_key_id = ?,
                    signed_at = ?
                where decision_id = ?
                """,
                (
                    signed["integrity_version"],
                    signed["integrity_generation"],
                    signed["payload_hash"],
                    signed["payload_mac"],
                    signed["integrity_key_id"],
                    signed["signed_at"],
                    decision_id,
                ),
            )
        return {
            "cutover_complete": True,
            "generation": next_generation,
            "pending_generation": None,
            "version": _POLICY_INTEGRITY_CONTROL_VERSION,
        }

    def _reconcile_policy_integrity_pending_generation(
        self,
        connection: sqlite3.Connection,
        *,
        key: bytes,
        key_id: str,
        trusted_state: dict[str, object],
    ) -> dict[str, object]:
        current_generation = _mapping_int(trusted_state, "generation")
        if current_generation is None:
            raise RuntimeError("Guard policy integrity control state is invalid.")
        pending_generation = trusted_state.get("pending_generation")
        if not isinstance(pending_generation, int) or pending_generation <= current_generation:
            return trusted_state
        rows = self._load_local_policy_rows(connection)
        next_state: dict[str, object]
        if not rows:
            next_state = {
                "cutover_complete": True,
                "generation": pending_generation,
                "pending_generation": None,
                "version": _POLICY_INTEGRITY_CONTROL_VERSION,
            }
        else:
            (
                has_legacy_rows,
                pending_candidates,
                pending_valid,
                current_valid,
            ) = self._classify_policy_integrity_pending_generation_rows(
                rows,
                key=key,
                key_id=key_id,
                current_generation=current_generation,
                pending_generation=pending_generation,
            )
            if has_legacy_rows:
                next_state = dict(trusted_state)
                if pending_candidates > 0 and current_valid == len(rows):
                    next_state["pending_generation"] = None
            elif pending_valid == len(rows):
                next_state = {
                    "cutover_complete": True,
                    "generation": pending_generation,
                    "pending_generation": None,
                    "version": _POLICY_INTEGRITY_CONTROL_VERSION,
                }
            elif current_valid == len(rows):
                next_state = dict(trusted_state)
                next_state["pending_generation"] = None
            else:
                next_state = dict(trusted_state)
        if not self._store_policy_integrity_control_state(next_state):
            raise RuntimeError("Guard could not persist the policy integrity control state.")
        return next_state

    def _classify_policy_integrity_pending_generation_rows(
        self,
        rows: Sequence[sqlite3.Row],
        *,
        key: bytes,
        key_id: str,
        current_generation: int,
        pending_generation: int,
    ) -> tuple[bool, int, int, int]:
        has_legacy_rows = False
        pending_candidates = 0
        pending_valid = 0
        current_valid = 0
        for row in rows:
            row_payload = _row_mapping(row)
            if _mapping_int(row_payload, "integrity_version") != POLICY_INTEGRITY_VERSION:
                has_legacy_rows = True
                current_result = verify_local_policy_row(
                    row_payload,
                    key=key,
                    key_id=key_id,
                    degraded_mode=False,
                    trusted_generation=current_generation,
                )
                if current_result.status == "valid":
                    current_valid += 1
                continue
            pending_candidates += 1
            pending_result = verify_local_policy_row(
                row_payload,
                key=key,
                key_id=key_id,
                degraded_mode=False,
                trusted_generation=pending_generation,
            )
            if pending_result.status == "valid":
                pending_valid += 1
                continue
            current_result = verify_local_policy_row(
                row_payload,
                key=key,
                key_id=key_id,
                degraded_mode=False,
                trusted_generation=current_generation,
            )
            if current_result.status == "valid":
                current_valid += 1
        return has_legacy_rows, pending_candidates, pending_valid, current_valid

    def _newer_authenticated_policy_integrity_generation(
        self,
        connection: sqlite3.Connection,
        *,
        key: bytes,
        key_id: str,
        trusted_generation: int | None,
    ) -> int | None:
        current_valid = 0
        newer_generations: set[int] = set()
        rows = self._load_local_policy_rows(connection)
        validated_rows = 0
        for row in rows:
            row_payload = _row_mapping(row)
            if _mapping_int(row_payload, "integrity_version") != POLICY_INTEGRITY_VERSION:
                return None
            row_generation = _mapping_int(row_payload, "integrity_generation")
            if row_generation is None:
                return None
            result = verify_local_policy_row(
                row_payload,
                key=key,
                key_id=key_id,
                degraded_mode=False,
                trusted_generation=row_generation,
            )
            if result.status != "valid":
                return None
            validated_rows += 1
            if trusted_generation is not None and row_generation == trusted_generation:
                current_valid += 1
                continue
            if trusted_generation is None or row_generation > trusted_generation:
                newer_generations.add(row_generation)
                continue
            return None
        if current_valid > 0 or len(newer_generations) != 1 or validated_rows != len(rows):
            return None
        return next(iter(newer_generations))

    def _resolved_policy_integrity_pending_generation(
        self,
        connection: sqlite3.Connection,
        *,
        key: bytes,
        key_id: str,
        trusted_state: dict[str, object],
    ) -> dict[str, object]:
        current_generation = _mapping_int(trusted_state, "generation")
        if current_generation is None:
            raise RuntimeError("Guard policy integrity control state is invalid.")
        pending_generation = trusted_state.get("pending_generation")
        if not isinstance(pending_generation, int) or pending_generation <= current_generation:
            return trusted_state
        rows = self._load_local_policy_rows(connection)
        next_state: dict[str, object]
        if not rows:
            next_state = {
                "cutover_complete": True,
                "generation": pending_generation,
                "pending_generation": None,
                "version": _POLICY_INTEGRITY_CONTROL_VERSION,
            }
        else:
            (
                has_legacy_rows,
                pending_candidates,
                pending_valid,
                current_valid,
            ) = self._classify_policy_integrity_pending_generation_rows(
                rows,
                key=key,
                key_id=key_id,
                current_generation=current_generation,
                pending_generation=pending_generation,
            )
            if has_legacy_rows:
                next_state = dict(trusted_state)
                if pending_candidates > 0 and current_valid == len(rows):
                    next_state["pending_generation"] = None
            elif pending_valid == len(rows):
                next_state = {
                    "cutover_complete": True,
                    "generation": pending_generation,
                    "pending_generation": None,
                    "version": _POLICY_INTEGRITY_CONTROL_VERSION,
                }
            elif current_valid == len(rows):
                next_state = dict(trusted_state)
                next_state["pending_generation"] = None
            else:
                next_state = dict(trusted_state)
        return next_state

    def _prepared_startup_policy_integrity_state(
        self,
        connection: sqlite3.Connection,
        *,
        key: bytes,
        key_id: str,
        trusted_state: dict[str, object],
    ) -> dict[str, object]:
        has_legacy_rows = self._count_legacy_local_policy_rows(connection) > 0
        prepared_state = dict(trusted_state)
        pending_generation = prepared_state.get("pending_generation")
        if not isinstance(pending_generation, int) and not has_legacy_rows:
            newer_authenticated_generation = self._newer_authenticated_policy_integrity_generation(
                connection,
                key=key,
                key_id=key_id,
                trusted_generation=_mapping_int(prepared_state, "generation"),
            )
            if newer_authenticated_generation is not None:
                prepared_state["generation"] = newer_authenticated_generation
        prepared_state = self._resolved_policy_integrity_pending_generation(
            connection,
            key=key,
            key_id=key_id,
            trusted_state=prepared_state,
        )
        if not bool(prepared_state.get("cutover_complete")) and not has_legacy_rows:
            prepared_state["cutover_complete"] = True
        return prepared_state

    def _prefetched_startup_state_still_matches_local_rows(
        self,
        connection: sqlite3.Connection,
        *,
        key: bytes,
        key_id: str,
        trusted_state: dict[str, object],
    ) -> bool:
        trusted_generation = _mapping_int(trusted_state, "generation")
        for row in self._load_local_policy_rows(connection):
            result = verify_local_policy_row(
                _row_mapping(row),
                key=key,
                key_id=key_id,
                degraded_mode=False,
                trusted_generation=trusted_generation,
            )
            if result.status != "valid":
                return False
        return True

    def _refresh_policy_integrity_state(
        self,
        connection: sqlite3.Connection,
        *,
        now: str,
        create_key: bool,
        secret_material: tuple[bytes | None, str | None] | None = None,
        allow_cutover_resign: bool = True,
    ) -> dict[str, object]:
        existing = self._load_policy_integrity_state(connection) or {}
        warnings = self._policy_integrity_path_warnings()
        prefetched_trusted_state = getattr(
            self,
            "_startup_prefetched_policy_integrity_trusted_state",
            _POLICY_INTEGRITY_LOOKUP_UNSET,
        )
        using_prefetched_trusted_state = prefetched_trusted_state is not _POLICY_INTEGRITY_LOOKUP_UNSET
        if using_prefetched_trusted_state:
            trusted_state = cast(dict[str, object] | None, prefetched_trusted_state)
        else:
            trusted_state = self._load_policy_integrity_control_state(create=create_key)
        if using_prefetched_trusted_state and getattr(
            self,
            "_startup_prefetched_policy_integrity_repair_failed",
            False,
        ):
            trusted_state = None
            warnings.append(POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE)
        prefetched_secret_material = getattr(
            self,
            "_startup_prefetched_policy_integrity_secret_material",
            _POLICY_INTEGRITY_LOOKUP_UNSET,
        )
        using_prefetched_secret_material = prefetched_secret_material is not _POLICY_INTEGRITY_LOOKUP_UNSET
        if secret_material is not None:
            raw_key, key_id = secret_material
        elif using_prefetched_secret_material:
            raw_key, key_id = cast(tuple[bytes | None, str | None], prefetched_secret_material)
        else:
            raw_key, key_id = self._policy_integrity_secret_material(create=create_key)
        if self._policy_integrity_secret_store is None:
            warnings.append(POLICY_INTEGRITY_REASON_SYSTEM_KEYRING_UNAVAILABLE)
        elif raw_key is None or key_id is None:
            warnings.append(POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE)
        if trusted_state is None:
            warnings.append(POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE)
        if (
            not warnings
            and trusted_state is not None
            and raw_key is not None
            and key_id is not None
            and not using_prefetched_trusted_state
        ):
            try:
                trusted_state = self._reconcile_policy_integrity_pending_generation(
                    connection,
                    key=raw_key,
                    key_id=key_id,
                    trusted_state=trusted_state,
                )
            except RuntimeError:
                warnings.append(POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE)
        has_only_signed_rows = self._count_legacy_local_policy_rows(connection) == 0
        if (
            not warnings
            and trusted_state is not None
            and not bool(trusted_state.get("cutover_complete"))
            and has_only_signed_rows
            and not using_prefetched_trusted_state
        ):
            next_trusted_state = dict(trusted_state)
            next_trusted_state["cutover_complete"] = True
            if not self._store_policy_integrity_control_state(next_trusted_state):
                warnings.append(POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE)
            else:
                trusted_state = next_trusted_state
        mode = POLICY_INTEGRITY_MODE_PROTECTED if not warnings else POLICY_INTEGRITY_MODE_DEGRADED
        cutover_complete = bool(trusted_state.get("cutover_complete")) if trusted_state is not None else False
        enforcement = POLICY_INTEGRITY_ENFORCEMENT_ENFORCE
        payload: dict[str, object] = {
            "backend": self._policy_integrity_backend_name(),
            "cutover_complete": cutover_complete,
            "degraded_reasons": list(dict.fromkeys(warnings)),
            "enforcement": enforcement,
            "generation": trusted_state.get("generation") if trusted_state is not None else None,
            "key_id": key_id,
            "mode": mode,
        }
        if payload != existing:
            self._store_policy_integrity_state(connection, payload, now=now)
        return payload

    def _prepare_startup_prefetched_policy_integrity_state(self) -> None:
        prefetched_trusted_state = getattr(
            self,
            "_startup_prefetched_policy_integrity_trusted_state",
            _POLICY_INTEGRITY_LOOKUP_UNSET,
        )
        prefetched_secret_material = getattr(
            self,
            "_startup_prefetched_policy_integrity_secret_material",
            _POLICY_INTEGRITY_LOOKUP_UNSET,
        )
        if (
            prefetched_trusted_state is _POLICY_INTEGRITY_LOOKUP_UNSET
            or prefetched_secret_material is _POLICY_INTEGRITY_LOOKUP_UNSET
        ):
            return
        trusted_state = cast(dict[str, object] | None, prefetched_trusted_state)
        if trusted_state is None:
            return
        raw_key, key_id = cast(tuple[bytes | None, str | None], prefetched_secret_material)
        if raw_key is None or key_id is None:
            return

        def compute_prepared_state(base_state: dict[str, object]) -> dict[str, object]:
            connection = sqlite3.connect(self.path, timeout=SQLITE_CONNECT_TIMEOUT_SECONDS)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute(f"pragma busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
                return self._prepared_startup_policy_integrity_state(
                    connection,
                    key=raw_key,
                    key_id=key_id,
                    trusted_state=base_state,
                )
            finally:
                connection.close()

        prepared_state = compute_prepared_state(trusted_state)
        current_trusted_state = self._load_policy_integrity_control_state(create=False)
        if current_trusted_state is None:
            connection = sqlite3.connect(self.path, timeout=SQLITE_CONNECT_TIMEOUT_SECONDS)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute(f"pragma busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
                still_matches = self._prefetched_startup_state_still_matches_local_rows(
                    connection,
                    key=raw_key,
                    key_id=key_id,
                    trusted_state=trusted_state,
                )
            finally:
                connection.close()
            if prepared_state == trusted_state and still_matches:
                self._startup_prefetched_policy_integrity_trusted_state = trusted_state
                return
            self._startup_prefetched_policy_integrity_repair_failed = True
            return
        if current_trusted_state != trusted_state:
            trusted_state = dict(current_trusted_state)
            prepared_state = compute_prepared_state(trusted_state)
        if prepared_state == trusted_state:
            self._startup_prefetched_policy_integrity_trusted_state = trusted_state
            return
        if self._store_policy_integrity_control_state(prepared_state):
            self._startup_prefetched_policy_integrity_trusted_state = prepared_state
            return
        self._startup_prefetched_policy_integrity_repair_failed = True

    def _policy_integrity_result_for_row(
        self,
        row: sqlite3.Row,
        *,
        mode: str,
        key: bytes | None,
        key_id: str | None,
        trusted_generation: int | None = None,
    ) -> PolicyIntegrityVerificationResult:
        source = str(row["source"]) if row["source"] is not None else None
        if is_remote_policy_source(source):
            return PolicyIntegrityVerificationResult(status="valid")
        return verify_local_policy_row(
            _row_mapping(row),
            key=key,
            key_id=key_id,
            degraded_mode=mode != "protected",
            trusted_generation=trusted_generation,
        )

    @staticmethod
    def _policy_row_payload(
        row: sqlite3.Row,
        *,
        integrity_result: PolicyIntegrityVerificationResult | None = None,
        state: dict[str, object] | None = None,
    ) -> dict[str, object]:
        source = str(row["source"])
        payload: dict[str, object] = {
            "action": str(row["action"]),
            "artifact_hash": row["artifact_hash"],
            "artifact_id": row["artifact_id"],
            "decision_id": int(row["decision_id"]) if row["decision_id"] is not None else None,
            "expires_at": row["expires_at"],
            "harness": str(row["harness"]),
            "owner": row["owner"],
            "publisher": row["publisher"],
            "reason": row["reason"],
            "scope": str(row["scope"]),
            "source": source,
            "updated_at": str(row["updated_at"]),
            "workspace": row["workspace"],
        }
        if integrity_result is not None and not is_remote_policy_source(source):
            payload["integrity_status"] = integrity_result.status
            payload["integrity_message"] = integrity_result.message
        if state is not None and not is_remote_policy_source(source):
            payload["integrity_mode"] = state.get("mode")
            payload["integrity_enforcement"] = state.get("enforcement")
        if row["integrity_version"] is not None:
            payload["integrity_version"] = int(row["integrity_version"])
        if row["integrity_generation"] is not None:
            payload["integrity_generation"] = int(row["integrity_generation"])
        if row["integrity_key_id"] is not None:
            payload["integrity_key_id"] = str(row["integrity_key_id"])
        if row["signed_at"] is not None:
            payload["signed_at"] = str(row["signed_at"])
        return payload

    def _repair_store_permissions(self) -> None:
        _set_private_mode_compat(self.guard_home, _GUARD_STORE_PRIVATE_DIR_MODE)
        for candidate in (
            self.path,
            self.guard_home / "guard.db-journal",
            self.guard_home / "guard.db-shm",
            self.guard_home / "guard.db-wal",
        ):
            if candidate.exists():
                _set_private_mode_compat(candidate, _GUARD_STORE_PRIVATE_FILE_MODE)
