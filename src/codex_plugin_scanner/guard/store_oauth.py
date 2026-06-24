"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false, reportUninitializedInstanceVariable=false

from __future__ import annotations

from .package_firewall_defaults import build_guard_local_entitlement_defaults

# ruff: noqa: F403,F405
from .store_base import *


class StoreOAuthConnectMixin:
    def get_cloud_sync_profile(self) -> dict[str, str] | None:
        oauth_payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if not isinstance(oauth_payload, dict) and self.repair_oauth_local_credential_storage_from_primary():
            oauth_payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if isinstance(oauth_payload, dict):
            oauth_health = self.get_oauth_local_credential_health()
            if not isinstance(oauth_health, dict) or oauth_health.get("state") != "healthy":
                return None
            metadata = self._oauth_local_credentials_metadata(oauth_payload)
            if metadata is None:
                return None
            issuer = metadata.get("issuer")
            if isinstance(issuer, str) and issuer.strip():
                profile = {
                    "auth_mode": "oauth",
                    "sync_url": _oauth_sync_url_from_issuer(issuer),
                }
                workspace_id = metadata.get("workspace_id")
                if isinstance(workspace_id, str) and workspace_id.strip():
                    profile["workspace_id"] = workspace_id.strip()
                return profile
        return None

    def clear_cloud_sync_state_for_reconnect(self) -> None:
        self.delete_sync_payloads(list(_GUARD_CLOUD_RESET_STATE_KEYS))

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
        supply_chain_entitlement_expires_at: str | None = None,
        supply_chain_firewall: bool | None = None,
        supply_chain_plan_id: str | None = None,
        workspace_id: str | None = None,
        runtime_id: str | None = None,
        runtime_label: str | None = None,
        access_token: str | None = None,
        access_token_expires_at: str | None = None,
    ) -> None:
        with self.hold_oauth_credential_lock():
            self._set_oauth_local_credentials_unlocked(
                issuer=issuer,
                client_id=client_id,
                refresh_token=refresh_token,
                dpop_private_key_pem=dpop_private_key_pem,
                dpop_public_jwk=dpop_public_jwk,
                dpop_public_jwk_thumbprint=dpop_public_jwk_thumbprint,
                now=now,
                grant_id=grant_id,
                machine_id=machine_id,
                supply_chain_entitlement_expires_at=supply_chain_entitlement_expires_at,
                supply_chain_firewall=supply_chain_firewall,
                supply_chain_plan_id=supply_chain_plan_id,
                workspace_id=workspace_id,
                runtime_id=runtime_id,
                runtime_label=runtime_label,
                access_token=access_token,
                access_token_expires_at=access_token_expires_at,
            )

    def _set_oauth_local_credentials_unlocked(
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
        supply_chain_entitlement_expires_at: str | None = None,
        supply_chain_firewall: bool | None = None,
        supply_chain_plan_id: str | None = None,
        workspace_id: str | None = None,
        runtime_id: str | None = None,
        runtime_label: str | None = None,
        access_token: str | None = None,
        access_token_expires_at: str | None = None,
    ) -> None:
        normalized_issuer = resolve_guard_oauth_client_config(issuer).issuer
        secret_payload = {
            "refresh_token": refresh_token,
            "dpop_private_key_pem": dpop_private_key_pem,
            "dpop_public_jwk": dpop_public_jwk,
            "dpop_public_jwk_thumbprint": dpop_public_jwk_thumbprint,
        }
        if isinstance(access_token, str) and access_token:
            secret_payload["access_token"] = access_token
        if isinstance(access_token_expires_at, str) and access_token_expires_at:
            secret_payload["access_token_expires_at"] = access_token_expires_at
        secret_json = json.dumps(secret_payload, sort_keys=True, separators=(",", ":"))
        secret_hash = _secret_fingerprint(secret_json)
        payload: dict[str, object] = {
            "issuer": normalized_issuer,
            "client_id": client_id,
            _OAUTH_LOCAL_CREDENTIALS_REF_KEY: self._oauth_local_credentials_ref,
            _OAUTH_LOCAL_CREDENTIALS_HASH_KEY: secret_hash,
        }
        if grant_id:
            payload["grant_id"] = grant_id
        if machine_id:
            payload["machine_id"] = machine_id
        if supply_chain_entitlement_expires_at:
            payload["supply_chain_entitlement_expires_at"] = supply_chain_entitlement_expires_at
        if isinstance(supply_chain_firewall, bool):
            payload["supply_chain_firewall"] = supply_chain_firewall
        if supply_chain_plan_id:
            payload["supply_chain_plan_id"] = supply_chain_plan_id
        if workspace_id:
            payload["workspace_id"] = workspace_id
        if runtime_id:
            payload["runtime_id"] = runtime_id
        if runtime_label:
            payload["runtime_label"] = runtime_label
        existing_payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        existing_secret_ref = (
            existing_payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY) if isinstance(existing_payload, dict) else None
        )
        existing_secret_hash = (
            existing_payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY) if isinstance(existing_payload, dict) else None
        )
        secret_material_changed = (
            existing_secret_ref != self._oauth_local_credentials_ref or existing_secret_hash != secret_hash
        )
        if secret_material_changed:
            self._clear_oauth_secret_payload_cache()
        # Metadata-only updates can skip the primary rewrite because the encrypted
        # fallback remains current and continues to backstop headless recovery.
        skip_primary_secret_rewrite = (
            not secret_material_changed
            and isinstance(self._oauth_secret_store, FallbackSecretStore)
            and isinstance(self._oauth_secret_store.primary, SystemKeyringSecretStore)
            and isinstance(self._oauth_secret_store.fallback, EncryptedFileSecretStore)
        )
        if not skip_primary_secret_rewrite:
            self._oauth_secret_store.set_secret(self._oauth_local_credentials_ref, secret_json)
        self._mirror_oauth_secret_to_fallback(self._oauth_local_credentials_ref, secret_json)
        self._assert_oauth_secret_persisted(self._oauth_local_credentials_ref, secret_json)
        self._remember_oauth_secret_payload(self._oauth_local_credentials_ref, secret_hash, secret_json)
        self.set_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY, payload, now)

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object] | None:
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if not isinstance(payload, dict):
            return None
        metadata = self._oauth_local_credentials_metadata(payload)
        if metadata is None:
            return None
        secret_payload = self._load_oauth_secret_payload(
            payload,
            allow_primary=allow_primary or self._oauth_primary_reads_are_no_ui_safe(),
        )
        if secret_payload is None:
            return None
        return self._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secret_payload)

    def get_recoverable_oauth_local_credentials(self) -> dict[str, object] | None:
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if not isinstance(payload, dict):
            return None
        metadata = self._oauth_local_credentials_metadata(payload)
        if metadata is None:
            return None
        secret_payload = self._load_oauth_fallback_secret_payload(payload)
        if secret_payload is None:
            return None
        return self._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secret_payload)

    def clear_oauth_local_credentials(self) -> None:
        self._clear_oauth_secret_payload_cache()
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if isinstance(payload, dict):
            secret_ref = payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY)
            if isinstance(secret_ref, str) and secret_ref:
                self._oauth_secret_store.delete_secret(secret_ref)
                if sys.platform == "darwin":
                    legacy_fallback = EncryptedFileSecretStore(self.guard_home)
                    legacy_path = legacy_fallback._path_for(secret_ref)
                    with suppress(OSError):
                        legacy_path.unlink()
        self.delete_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        if not isinstance(payload, dict) and self.repair_oauth_local_credential_storage_from_primary():
            payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
        health: dict[str, object] = {
            "configured": isinstance(payload, dict),
            "state": "not_configured",
            "backend": _secret_store_backend_name(self._oauth_secret_store),
            "fallback_backend": _secret_store_fallback_backend_name(self._oauth_secret_store),
        }
        if not isinstance(payload, dict):
            return health
        metadata = self._oauth_local_credentials_metadata(payload)
        if metadata is None:
            health["state"] = "degraded"
            return health
        secret_hash = payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY)
        cached_health = self._get_cached_oauth_health_result(secret_hash)
        if cached_health is not None:
            health.update(cached_health)
            return health
        secret_payload = self._load_oauth_secret_payload(
            payload,
            promote=True,
            allow_primary=self._oauth_primary_reads_are_repair_safe(),
        )
        can_repair_from_primary = self._oauth_primary_reads_are_repair_safe()
        if (
            secret_payload is None
            and can_repair_from_primary
            and self.repair_oauth_local_credential_storage_from_primary()
        ):
            refreshed_payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
            if isinstance(refreshed_payload, dict):
                payload = refreshed_payload
                secret_hash = payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY)
            secret_payload = self._load_oauth_secret_payload(
                payload,
                promote=True,
                allow_primary=self._oauth_primary_reads_are_repair_safe(),
            )
        if secret_payload is None:
            health["state"] = "degraded"
            self._remember_oauth_health_result(secret_hash, health)
            return health
        if self._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secret_payload) is None:
            health["state"] = "degraded"
            self._remember_oauth_health_result(secret_hash, health)
            return health
        health["state"] = "healthy"
        for key in ("issuer", "client_id", "grant_id", "machine_id", "workspace_id"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                health[key] = value
        self._remember_oauth_health_result(secret_hash, health)
        return health

    @staticmethod
    def _oauth_local_credentials_metadata(payload: dict[str, object]) -> dict[str, object] | None:
        issuer = payload.get("issuer")
        client_id = payload.get("client_id")
        if not isinstance(issuer, str) or not issuer:
            return None
        if not isinstance(client_id, str) or not client_id:
            return None
        result: dict[str, object] = {
            "issuer": issuer,
            "client_id": client_id,
        }
        for key in ("grant_id", "machine_id", "workspace_id", "runtime_id", "runtime_label"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        for key in ("supply_chain_entitlement_expires_at", "supply_chain_plan_id"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        supply_chain_firewall = payload.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            result["supply_chain_firewall"] = supply_chain_firewall
        return result

    def _oauth_primary_repair_available(self) -> bool:
        secret_store = self._oauth_secret_store
        return isinstance(secret_store, FallbackSecretStore) and isinstance(
            secret_store.primary,
            SystemKeyringSecretStore,
        )

    def _oauth_keychain_access_state_path(self) -> Path:
        return self.guard_home / _OAUTH_KEYCHAIN_ACCESS_STATE_FILE

    def _read_oauth_keychain_access_state(self) -> dict[str, object]:
        path = self._oauth_keychain_access_state_path()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _write_oauth_keychain_access_state(self, payload: dict[str, object]) -> None:
        path = self._oauth_keychain_access_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            tmp_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            _set_private_mode(tmp_path, _GUARD_STORE_PRIVATE_FILE_MODE)
            tmp_path.replace(path)
            _set_private_mode(path, _GUARD_STORE_PRIVATE_FILE_MODE)
        finally:
            if tmp_path.exists():
                with suppress(OSError):
                    tmp_path.unlink()

    def _should_attempt_oauth_storage_repair(self) -> bool:
        if not self._oauth_primary_repair_available():
            return False
        state = self._read_oauth_keychain_access_state()
        last_attempt = state.get("last_repair_attempt_at")
        if not isinstance(last_attempt, (int, float)):
            return True
        return (time.time() - float(last_attempt)) >= _OAUTH_STORAGE_REPAIR_MIN_INTERVAL_SECONDS

    def _mark_oauth_storage_repair_attempt(self) -> None:
        state = self._read_oauth_keychain_access_state()
        state["last_repair_attempt_at"] = time.time()
        self._write_oauth_keychain_access_state(state)

    def repair_oauth_local_credential_storage_from_primary(self) -> bool:
        """Rebuild OAuth credential storage from primary or recoverable fallback state."""
        with self.hold_oauth_credential_lock():
            payload = self.get_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY)
            if not isinstance(payload, dict):
                recovered_payload = self._recover_missing_oauth_local_credentials_payload(now=_now())
                if recovered_payload is None:
                    return False
                self.set_sync_payload(_OAUTH_LOCAL_CREDENTIALS_STATE_KEY, recovered_payload, _now())
                return True
            repaired_payload = None
            if self._should_attempt_oauth_storage_repair():
                self._mark_oauth_storage_repair_attempt()
                repaired_payload = self._load_oauth_secret_payload(payload, promote=True, allow_primary=True)
            if repaired_payload is None:
                if not self._oauth_fallback_recovery_allowed():
                    return False
                secret_ref = _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY))
                if (
                    self._oauth_primary_repair_available()
                    and secret_ref is not None
                    and not self._oauth_primary_secret_definitely_missing(secret_ref)
                ):
                    return False
                recoverable_credentials = self.get_recoverable_oauth_local_credentials()
                if recoverable_credentials is None:
                    return False
                recovered_inputs = self._build_recovered_oauth_local_credentials_inputs(
                    recoverable_credentials,
                )
                if recovered_inputs is None:
                    return False
                self._set_oauth_local_credentials_unlocked(
                    now=_now(),
                    **cast(dict[str, Any], cast(object, recovered_inputs)),
                )
            cache_key = self._oauth_health_process_cache_key(
                _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY)),
            )
            if cache_key is not None:
                _OAUTH_HEALTH_RESULT_PROCESS_CACHE.pop(cache_key, None)
            return True

    def _recover_missing_oauth_local_credentials_payload(self, *, now: str) -> dict[str, object] | None:
        secret_ref = self._oauth_local_credentials_ref
        secret_json = self._load_oauth_secret_json_without_payload(secret_ref)
        if secret_json is None:
            return None
        secret_payload = self._parse_oauth_secret_payload(secret_json)
        if secret_payload is None:
            return None
        latest_state = self.get_latest_guard_connect_state(now=now)
        issuer = self._recover_oauth_issuer_for_missing_metadata(latest_state)
        if issuer is None:
            return None
        try:
            oauth_client = resolve_guard_oauth_client_config(issuer)
        except ValueError:
            return None
        workspace_metadata = self._recover_oauth_workspace_metadata()
        recovered_payload: dict[str, object] = {
            "issuer": oauth_client.issuer,
            "client_id": oauth_client.client_id,
            _OAUTH_LOCAL_CREDENTIALS_REF_KEY: secret_ref,
            _OAUTH_LOCAL_CREDENTIALS_HASH_KEY: _secret_fingerprint(secret_json),
        }
        device = self.get_device_metadata()
        installation_id = device.get("installation_id")
        if isinstance(installation_id, str) and installation_id:
            recovered_payload["machine_id"] = installation_id
        for key in ("workspace_id", "supply_chain_plan_id", "supply_chain_entitlement_expires_at"):
            value = workspace_metadata.get(key)
            if isinstance(value, str) and value:
                recovered_payload[key] = value
        supply_chain_firewall = workspace_metadata.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            recovered_payload["supply_chain_firewall"] = supply_chain_firewall
        if (
            self._build_oauth_local_credentials_result(
                metadata=self._oauth_local_credentials_metadata(recovered_payload) or {},
                secret_payload=secret_payload,
            )
            is None
        ):
            return None
        self._mirror_oauth_secret_to_fallback(secret_ref, secret_json)
        self._remember_oauth_secret_payload(
            secret_ref,
            str(recovered_payload[_OAUTH_LOCAL_CREDENTIALS_HASH_KEY]),
            secret_json,
        )
        return recovered_payload

    def _load_oauth_secret_json_without_payload(self, secret_ref: str) -> str | None:
        primary_secret_json = None
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            primary_secret_json = self._get_secret_from_primary_store(secret_store.primary, secret_ref)
        else:
            primary_secret_json = self._get_secret_from_store(secret_store, secret_ref)
        if isinstance(primary_secret_json, str) and self._parse_oauth_secret_payload(primary_secret_json) is not None:
            return primary_secret_json
        if not self._oauth_fallback_recovery_allowed():
            return None
        if self._oauth_primary_repair_available() and not self._oauth_primary_secret_definitely_missing(secret_ref):
            return None
        fallback_secret_json = self._load_oauth_fallback_secret_json(secret_ref)
        if isinstance(fallback_secret_json, str) and self._parse_oauth_secret_payload(fallback_secret_json) is not None:
            return fallback_secret_json
        return None

    @staticmethod
    def _recover_oauth_issuer_for_missing_metadata(latest_state: dict[str, object] | None) -> str | None:
        if not isinstance(latest_state, dict):
            return None
        allowed_origin = latest_state.get("allowed_origin")
        if isinstance(allowed_origin, str) and allowed_origin.strip():
            return allowed_origin.strip()
        sync_url = latest_state.get("sync_url")
        if isinstance(sync_url, str) and sync_url.strip():
            return _allowed_origin_from_sync_url(sync_url.strip())
        return None

    def _recover_oauth_workspace_metadata(self) -> dict[str, object]:
        payload = self.get_sync_payload("supply_chain_bundle_entitlement")
        workspace_id = None
        entitlement_fields: dict[str, object] = {}
        if isinstance(payload, dict):
            raw_workspace_id = payload.get("workspace_id")
            if isinstance(raw_workspace_id, str) and raw_workspace_id.strip():
                workspace_id = raw_workspace_id.strip()
            raw_tier = payload.get("tier")
            if isinstance(raw_tier, str) and raw_tier.strip():
                recovered_entitlement = build_guard_local_entitlement_defaults(
                    {"tier": raw_tier.strip()},
                    now=datetime.now(timezone.utc),
                )
                if isinstance(recovered_entitlement, dict):
                    entitlement_fields.update(recovered_entitlement)
        if workspace_id is None:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    select workspace_id
                    from guard_supply_chain_bundle_cache
                    order by cached_at desc
                    limit 1
                    """
                ).fetchone()
            if row is not None:
                raw_workspace_id = row["workspace_id"]
                if isinstance(raw_workspace_id, str) and raw_workspace_id.strip():
                    workspace_id = raw_workspace_id.strip()
        metadata: dict[str, object] = {}
        if workspace_id is not None:
            metadata["workspace_id"] = workspace_id
        for key in ("supply_chain_plan_id", "supply_chain_entitlement_expires_at"):
            value = entitlement_fields.get(key)
            if isinstance(value, str) and value:
                metadata[key] = value
        supply_chain_firewall = entitlement_fields.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            metadata["supply_chain_firewall"] = supply_chain_firewall
        return metadata

    @staticmethod
    def _build_recovered_oauth_local_credentials_inputs(
        credentials: dict[str, object],
    ) -> _RecoveredOAuthLocalCredentialInputs | None:
        issuer = _string_value(credentials.get("issuer"))
        client_id = _string_value(credentials.get("client_id"))
        refresh_token = _string_value(credentials.get("refresh_token"))
        dpop_private_key_pem = _string_value(credentials.get("dpop_private_key_pem"))
        dpop_public_jwk = credentials.get("dpop_public_jwk")
        dpop_public_jwk_thumbprint = _string_value(credentials.get("dpop_public_jwk_thumbprint"))
        supply_chain_firewall = credentials.get("supply_chain_firewall")
        supply_chain_firewall_value = supply_chain_firewall if isinstance(supply_chain_firewall, bool) else None
        if (
            issuer is None
            or client_id is None
            or refresh_token is None
            or dpop_private_key_pem is None
            or not isinstance(dpop_public_jwk, dict)
            or dpop_public_jwk_thumbprint is None
        ):
            return None
        recovered_inputs: _RecoveredOAuthLocalCredentialInputs = {
            "issuer": issuer,
            "client_id": client_id,
            "refresh_token": refresh_token,
            "dpop_private_key_pem": dpop_private_key_pem,
            "dpop_public_jwk": {str(key): str(value) for key, value in dpop_public_jwk.items()},
            "dpop_public_jwk_thumbprint": dpop_public_jwk_thumbprint,
            "grant_id": _string_value(credentials.get("grant_id")),
            "machine_id": _string_value(credentials.get("machine_id")),
            "supply_chain_entitlement_expires_at": _string_value(
                credentials.get("supply_chain_entitlement_expires_at"),
            ),
            "supply_chain_firewall": supply_chain_firewall_value,
            "supply_chain_plan_id": _string_value(credentials.get("supply_chain_plan_id")),
            "workspace_id": _string_value(credentials.get("workspace_id")),
            "runtime_id": _string_value(credentials.get("runtime_id")),
            "runtime_label": _string_value(credentials.get("runtime_label")),
            "access_token": _string_value(credentials.get("access_token")),
            "access_token_expires_at": _string_value(credentials.get("access_token_expires_at")),
        }
        return recovered_inputs

    def _load_oauth_secret_payload(
        self,
        payload: dict[str, object],
        *,
        promote: bool = True,
        allow_primary: bool = True,
    ) -> dict[str, object] | None:
        secret_ref = payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY)
        secret_hash = payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY)
        if not isinstance(secret_ref, str) or not secret_ref:
            return None
        if not isinstance(secret_hash, str) or not secret_hash:
            return None
        cached_secret_payload = self._get_cached_oauth_secret_payload(secret_ref, secret_hash)
        if cached_secret_payload is not None:
            return cached_secret_payload
        fallback_secret_json = self._load_oauth_fallback_secret_json(secret_ref)
        skip_fallback_first = (
            sys.platform == "darwin"
            and isinstance(self._oauth_secret_store, FallbackSecretStore)
            and isinstance(self._oauth_secret_store.primary, SystemKeyringSecretStore)
        )
        fallback_secret_payload = self._load_validated_oauth_fallback_secret_payload(
            fallback_secret_json,
            secret_hash,
        )
        prefer_primary_over_fallback = skip_fallback_first and allow_primary
        if fallback_secret_payload is not None and not prefer_primary_over_fallback:
            self._remember_oauth_secret_payload(secret_ref, secret_hash, fallback_secret_json)
            return fallback_secret_payload
        if not allow_primary:
            return None
        for candidate in self._get_secret_candidates(
            self._oauth_secret_store,
            secret_ref,
            secret_hash,
            prefer_fallback_first=True,
            fallback_token_hint=fallback_secret_json,
        ):
            if not _secret_matches_hash(candidate, secret_hash):
                continue
            secret_payload = self._parse_oauth_secret_payload(candidate)
            if secret_payload is None:
                continue
            if promote:
                self._mirror_oauth_secret_to_fallback(secret_ref, candidate)
            self._remember_oauth_secret_payload(secret_ref, secret_hash, candidate)
            return secret_payload
        return None

    def _resolve_oauth_fallback_store(self) -> EncryptedFileSecretStore | None:
        secret_store = self._oauth_secret_store
        if isinstance(secret_store, FallbackSecretStore):
            return secret_store.fallback if isinstance(secret_store.fallback, EncryptedFileSecretStore) else None
        if isinstance(secret_store, EncryptedFileSecretStore):
            return secret_store
        return None

    def _load_oauth_fallback_secret_json(self, secret_ref: str) -> str | None:
        fallback_store = self._resolve_oauth_fallback_store()
        if fallback_store is None:
            return None
        secret_json = self._get_secret_from_store(fallback_store, secret_ref)
        return secret_json if isinstance(secret_json, str) and secret_json else None

    def _oauth_process_cache_scope(self) -> str:
        return str(self.guard_home.expanduser().resolve())

    def _oauth_secret_process_cache_key(self, secret_ref: str, secret_hash: str) -> tuple[str, str, str]:
        return (self._oauth_process_cache_scope(), secret_ref, secret_hash)

    def _oauth_health_process_cache_key(self, secret_hash: str | None) -> tuple[str, str] | None:
        if not isinstance(secret_hash, str) or not secret_hash:
            return None
        return (self._oauth_process_cache_scope(), secret_hash)

    def _get_cached_oauth_secret_payload(self, secret_ref: str, secret_hash: str) -> dict[str, object] | None:
        cached = self._cached_oauth_secret_payload
        if cached is not None and cached[0] == secret_ref and cached[1] == secret_hash:
            parsed = self._parse_oauth_secret_payload(cached[2])
            if parsed is not None:
                return parsed
        process_cached = _OAUTH_SECRET_PAYLOAD_PROCESS_CACHE.get(
            self._oauth_secret_process_cache_key(secret_ref, secret_hash)
        )
        if process_cached is None:
            return None
        parsed = self._parse_oauth_secret_payload(process_cached)
        if parsed is None:
            return None
        self._cached_oauth_secret_payload = (secret_ref, secret_hash, process_cached)
        return parsed

    def _remember_oauth_secret_payload(self, secret_ref: str, secret_hash: str, secret_json: str | None) -> None:
        if not isinstance(secret_json, str) or not secret_json:
            return
        self._cached_oauth_secret_payload = (secret_ref, secret_hash, secret_json)
        cache_key = self._oauth_secret_process_cache_key(secret_ref, secret_hash)
        scope = cache_key[0]
        for existing_key in list(_OAUTH_SECRET_PAYLOAD_PROCESS_CACHE):
            if existing_key[0] == scope and existing_key[1] == secret_ref and existing_key != cache_key:
                _OAUTH_SECRET_PAYLOAD_PROCESS_CACHE.pop(existing_key, None)
        _OAUTH_SECRET_PAYLOAD_PROCESS_CACHE[cache_key] = secret_json

    def _get_cached_oauth_health_result(self, secret_hash: object) -> dict[str, object] | None:
        cache_key = self._oauth_health_process_cache_key(secret_hash if isinstance(secret_hash, str) else None)
        if cache_key is None:
            return None
        cached = _OAUTH_HEALTH_RESULT_PROCESS_CACHE.get(cache_key)
        if cached is None:
            return None
        cached_at, cached_health = cached
        state = cached_health.get("state")
        ttl = _OAUTH_HEALTH_CACHE_TTL_SECONDS if state == "healthy" else _OAUTH_HEALTH_DEGRADED_CACHE_TTL_SECONDS
        if (time.monotonic() - cached_at) >= ttl:
            _OAUTH_HEALTH_RESULT_PROCESS_CACHE.pop(cache_key, None)
            return None
        return dict(cached_health)

    def _remember_oauth_health_result(self, secret_hash: object, health: dict[str, object]) -> None:
        cache_key = self._oauth_health_process_cache_key(secret_hash if isinstance(secret_hash, str) else None)
        if cache_key is None:
            return
        state = health.get("state")
        if state not in {"healthy", "degraded"}:
            return
        _OAUTH_HEALTH_RESULT_PROCESS_CACHE[cache_key] = (time.monotonic(), dict(health))

    def _clear_oauth_secret_payload_cache(self) -> None:
        self._cached_oauth_secret_payload = None
        scope = self._oauth_process_cache_scope()
        for cache_key in list(_OAUTH_SECRET_PAYLOAD_PROCESS_CACHE):
            if cache_key[0] == scope:
                _OAUTH_SECRET_PAYLOAD_PROCESS_CACHE.pop(cache_key, None)
        for cache_key in list(_OAUTH_HEALTH_RESULT_PROCESS_CACHE):
            if cache_key[0] == scope:
                _OAUTH_HEALTH_RESULT_PROCESS_CACHE.pop(cache_key, None)

    @staticmethod
    def _parse_oauth_secret_payload(secret_json: str) -> dict[str, object] | None:
        try:
            secret_payload = json.loads(secret_json)
        except json.JSONDecodeError:
            return None
        return secret_payload if isinstance(secret_payload, dict) else None

    def _load_validated_oauth_fallback_secret_payload(
        self,
        secret_json: str | None,
        secret_hash: str,
    ) -> dict[str, object] | None:
        if not isinstance(secret_json, str) or not secret_json:
            return None
        if not _secret_matches_hash(secret_json, secret_hash):
            return None
        return self._parse_oauth_secret_payload(secret_json)

    def _load_oauth_fallback_secret_payload(self, payload: dict[str, object]) -> dict[str, object] | None:
        secret_ref = payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY)
        if not isinstance(secret_ref, str) or not secret_ref:
            return None
        secret_json = self._load_oauth_fallback_secret_json(secret_ref)
        if secret_json is None:
            return None
        return self._parse_oauth_secret_payload(secret_json)

    @staticmethod
    def _build_oauth_local_credentials_result(
        *,
        metadata: dict[str, object],
        secret_payload: dict[str, object],
    ) -> dict[str, object] | None:
        refresh_token = secret_payload.get("refresh_token")
        dpop_private_key_pem = secret_payload.get("dpop_private_key_pem")
        dpop_public_jwk = secret_payload.get("dpop_public_jwk")
        dpop_public_jwk_thumbprint = secret_payload.get("dpop_public_jwk_thumbprint")
        if not isinstance(refresh_token, str) or not refresh_token:
            return None
        if not isinstance(dpop_private_key_pem, str) or not dpop_private_key_pem:
            return None
        if not isinstance(dpop_public_jwk, dict):
            return None
        if not isinstance(dpop_public_jwk_thumbprint, str) or not dpop_public_jwk_thumbprint:
            return None
        result: dict[str, object] = {
            "issuer": metadata["issuer"],
            "client_id": metadata["client_id"],
            "refresh_token": refresh_token,
            "dpop_private_key_pem": dpop_private_key_pem,
            "dpop_public_jwk": {str(key): str(value) for key, value in dpop_public_jwk.items()},
            "dpop_public_jwk_thumbprint": dpop_public_jwk_thumbprint,
        }
        access_token = secret_payload.get("access_token")
        if isinstance(access_token, str) and access_token:
            result["access_token"] = access_token
        access_token_expires_at = secret_payload.get("access_token_expires_at")
        if isinstance(access_token_expires_at, str) and access_token_expires_at:
            result["access_token_expires_at"] = access_token_expires_at
        for key in ("grant_id", "machine_id", "workspace_id", "runtime_id", "runtime_label"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        for key in ("supply_chain_entitlement_expires_at", "supply_chain_plan_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        supply_chain_firewall = metadata.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            result["supply_chain_firewall"] = supply_chain_firewall
        return result

    def get_latest_guard_connect_state(self, *, now: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_latest_connect_state(connection, now=now)

    def get_effective_guard_connect_state(self, *, now: str) -> dict[str, object] | None:
        latest_state = self.get_latest_guard_connect_state(now=now)
        cloud_profile = self.get_cloud_sync_profile()
        sync_summary = self.get_sync_payload("sync_summary")
        return self._normalize_guard_connect_state(
            latest_state=latest_state,
            cloud_profile=cloud_profile,
            sync_summary=sync_summary if isinstance(sync_summary, dict) else None,
            now=now,
        )

    def record_guard_connect_pairing_completed(
        self,
        *,
        sync_url: str,
        allowed_origin: str,
        now: str,
        request_id: str | None = None,
    ) -> dict[str, object]:
        normalized_request_id = request_id.strip() if isinstance(request_id, str) and request_id.strip() else None
        resolved_request_id = normalized_request_id or f"connect-{uuid4().hex}"
        proof = {
            "pairing_completed_at": now,
            "first_synced_at": None,
            "receipts_stored": 0,
            "inventory_items": 0,
            "runtime_session_id": None,
            "runtime_session_synced_at": None,
        }
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_connect_states (
                  request_id,
                  sync_url,
                  allowed_origin,
                  status,
                  milestone,
                  reason,
                  created_at,
                  updated_at,
                  expires_at,
                  completed_at,
                  proof_json
                )
                values (?, ?, ?, 'connected', 'first_sync_pending', null, ?, ?, ?, ?, ?)
                """,
                (
                    resolved_request_id,
                    sync_url,
                    allowed_origin,
                    now,
                    now,
                    now,
                    now,
                    json.dumps(proof),
                ),
            )
            return load_connect_state(connection, resolved_request_id, now=now) or {}

    def record_latest_guard_connect_sync_result(
        self,
        *,
        status: str,
        milestone: str,
        now: str,
        reason: str | None = None,
        request_id: str | None = None,
        sync_payload: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection:
            latest_state: dict[str, object] | None
            if isinstance(request_id, str) and request_id.strip():
                latest_state = load_connect_state(connection, request_id.strip(), now=now)
            else:
                row = connection.execute(
                    """
                    select request_id
                    from guard_connect_states
                    where status in ('connected', 'retry_required')
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
            if latest_state.get("status") not in {"connected", "retry_required"}:
                return latest_state
            if request_id is None and latest_state.get("status") != "connected":
                return latest_state
            return persist_connect_result(
                connection,
                request_id=str(latest_state["request_id"]),
                status=status,
                milestone=milestone,
                updated_at=now,
                reason=reason,
                sync_payload=sync_payload,
            )

    def record_latest_guard_connect_sync_success(
        self,
        *,
        sync_payload: dict[str, object],
        now: str,
        request_id: str | None = None,
    ) -> dict[str, object] | None:
        return self.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="first_sync_succeeded",
            now=now,
            reason=None,
            request_id=request_id,
            sync_payload=sync_payload,
        )

    def _normalize_guard_connect_state(
        self,
        *,
        latest_state: dict[str, object] | None,
        cloud_profile: dict[str, str] | None,
        sync_summary: dict[str, object] | None,
        now: str,
    ) -> dict[str, object] | None:
        if cloud_profile is None:
            if latest_state is not None and self._guard_connect_state_requires_oauth(latest_state):
                return self._coerce_guard_connect_state_status(
                    state=latest_state,
                    status="retry_required",
                    milestone="first_sync_failed",
                    reason="Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again.",
                    sync_summary=sync_summary,
                    now=now,
                )
            return latest_state
        normalized = self._hydrate_guard_connect_state_from_cloud_profile(
            latest_state=latest_state,
            cloud_profile=cloud_profile,
            sync_summary=sync_summary,
            now=now,
        )
        if normalized is None:
            return None
        status = str(normalized.get("status") or "")
        milestone = str(normalized.get("milestone") or "")
        has_sync_summary = bool(sync_summary)
        if (
            has_sync_summary
            and status != "retry_required"
            and milestone not in {"first_sync_failed", "sync_not_available"}
        ):
            return self._coerce_guard_connect_state_status(
                state=normalized,
                status="connected",
                milestone="first_sync_succeeded",
                reason="first_sync_succeeded",
                sync_summary=sync_summary,
                now=now,
            )
        if status in {"expired", "waiting"} or milestone in {"expired", "waiting_for_browser"}:
            return self._coerce_guard_connect_state_status(
                state=normalized,
                status="connected",
                milestone="first_sync_pending",
                reason="waiting_for_first_sync",
                sync_summary=sync_summary,
                now=now,
            )
        return normalized

    def _guard_connect_state_requires_oauth(self, latest_state: dict[str, object]) -> bool:
        request_id = latest_state.get("request_id")
        if not isinstance(request_id, str) or not request_id.strip():
            return False
        status = str(latest_state.get("status") or "")
        return status == "connected"

    def _hydrate_guard_connect_state_from_cloud_profile(
        self,
        *,
        latest_state: dict[str, object] | None,
        cloud_profile: dict[str, str],
        sync_summary: dict[str, object] | None,
        now: str,
    ) -> dict[str, object]:
        sync_url = str(cloud_profile["sync_url"])
        allowed_origin = _allowed_origin_from_sync_url(sync_url)
        if latest_state is None:
            return self._coerce_guard_connect_state_status(
                state={
                    "request_id": None,
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                    "status": "connected",
                    "milestone": "first_sync_pending",
                    "reason": "waiting_for_first_sync",
                    "created_at": None,
                    "updated_at": now,
                    "expires_at": None,
                    "completed_at": None,
                    "proof": {},
                },
                status="connected",
                milestone="first_sync_succeeded" if sync_summary else "first_sync_pending",
                reason="first_sync_succeeded" if sync_summary else "waiting_for_first_sync",
                sync_summary=sync_summary,
                now=now,
            )
        hydrated = dict(latest_state)
        hydrated["sync_url"] = str(hydrated.get("sync_url") or sync_url)
        hydrated["allowed_origin"] = str(hydrated.get("allowed_origin") or allowed_origin or "")
        return self._coerce_guard_connect_state_status(
            state=hydrated,
            status=str(hydrated.get("status") or "connected"),
            milestone=str(
                hydrated.get("milestone") or ("first_sync_succeeded" if sync_summary else "first_sync_pending")
            ),
            reason=(
                str(hydrated.get("reason"))
                if isinstance(hydrated.get("reason"), str)
                else ("first_sync_succeeded" if sync_summary else "waiting_for_first_sync")
            ),
            sync_summary=sync_summary,
            now=now,
        )

    def _coerce_guard_connect_state_status(
        self,
        *,
        state: dict[str, object],
        status: str,
        milestone: str,
        reason: str | None,
        sync_summary: dict[str, object] | None,
        now: str,
    ) -> dict[str, object]:
        proof_source = state.get("proof")
        proof = dict(proof_source) if isinstance(proof_source, dict) else {}
        synced_at = None
        receipts_stored = 0
        inventory_tracked = 0
        runtime_session_id = None
        runtime_session_synced_at = None
        if isinstance(sync_summary, dict):
            synced_at_value = sync_summary.get("synced_at")
            if isinstance(synced_at_value, str) and synced_at_value:
                synced_at = synced_at_value
            receipts_value = sync_summary.get("receipts_stored")
            if isinstance(receipts_value, int):
                receipts_stored = max(0, receipts_value)
            inventory_value = sync_summary.get("inventory_tracked", sync_summary.get("inventory"))
            if isinstance(inventory_value, int):
                inventory_tracked = max(0, inventory_value)
            runtime_session_id_value = sync_summary.get("runtime_session_id")
            if isinstance(runtime_session_id_value, str) and runtime_session_id_value:
                runtime_session_id = runtime_session_id_value
            runtime_session_synced_at_value = sync_summary.get("runtime_session_synced_at")
            if isinstance(runtime_session_synced_at_value, str) and runtime_session_synced_at_value:
                runtime_session_synced_at = runtime_session_synced_at_value
        existing_receipts = proof.get("receipts_stored")
        existing_inventory = proof.get("inventory_items")
        proof.setdefault("pairing_completed_at", state.get("completed_at"))
        if synced_at is not None:
            proof["first_synced_at"] = synced_at
        else:
            proof.setdefault("first_synced_at", None)
        proof["receipts_stored"] = max(
            receipts_stored,
            existing_receipts if isinstance(existing_receipts, int) else 0,
        )
        proof["inventory_items"] = max(
            inventory_tracked,
            existing_inventory if isinstance(existing_inventory, int) else 0,
        )
        proof["runtime_session_id"] = runtime_session_id or proof.get("runtime_session_id")
        proof["runtime_session_synced_at"] = runtime_session_synced_at or proof.get("runtime_session_synced_at")
        payload = {
            "request_id": state.get("request_id"),
            "sync_url": state.get("sync_url"),
            "allowed_origin": state.get("allowed_origin"),
            "status": status,
            "milestone": milestone,
            "reason": reason,
            "created_at": state.get("created_at"),
            "updated_at": state.get("updated_at") or now,
            "expires_at": state.get("expires_at"),
            "completed_at": state.get("completed_at") or proof.get("pairing_completed_at"),
            "proof": proof,
        }
        return build_connect_state_response(payload, poll_after_ms=0)

    @staticmethod
    def _cloud_workspace_id_from_connection(connection: sqlite3.Connection) -> str | None:
        oauth_row = connection.execute(
            "select payload_json from sync_state where state_key = 'oauth_local_credentials'"
        ).fetchone()
        if oauth_row is not None:
            oauth_payload = json.loads(str(oauth_row["payload_json"]))
            if isinstance(oauth_payload, dict):
                workspace_id = oauth_payload.get("workspace_id")
                if isinstance(workspace_id, str) and workspace_id.strip():
                    return workspace_id
        return None
