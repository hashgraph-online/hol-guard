"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false, reportUninitializedInstanceVariable=false

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Concatenate, ParamSpec

from .oauth_token_claims import oauth_binding_metadata
from .package_firewall_defaults import build_guard_local_entitlement_defaults
from .runtime.extension_control_authority import ExtensionControlAuthorityView

# ruff: noqa: F403,F405
from .store_base import *
from .store_oauth_metadata import copy_oauth_binding_metadata

_P = ParamSpec("_P")


def _with_oauth_credential_lock(
    unlocked: Callable[Concatenate[StoreOAuthConnectMixin, _P], None],
) -> Callable[Concatenate[StoreOAuthConnectMixin, _P], None]:
    """Bind the OAuth credential lock around an unlocked credential writer."""

    @wraps(unlocked)
    def _locked(
        self: StoreOAuthConnectMixin,
        /,
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> None:
        with self.hold_oauth_credential_lock():
            getattr(self, unlocked.__name__)(*args, **kwargs)

    return _locked


class StoreOAuthConnectMixin:
    def legacy_macos_oauth_secret_migration_required(self) -> bool:
        """Return whether authenticated OAuth metadata lacks its local vault copy."""
        if sys.platform != "darwin":
            return False
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(payload, dict):
            return False
        secret_ref = _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY))
        secret_hash = _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY))
        if secret_ref is None or secret_hash is None:
            return False
        fallback = self._resolve_oauth_fallback_store()
        return fallback is not None and fallback.get_secret(secret_ref) is None

    def migrate_legacy_macos_oauth_secret(self, *, allow_interactive: bool = True) -> bool:
        """Mirror legacy Keychain OAuth state during an explicit action."""

        if not self._allow_system_keyring or not self.legacy_macos_oauth_secret_migration_required():
            return False
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        assert isinstance(payload, dict)
        secret_ref = _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY))
        secret_hash = _string_value(payload.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY))
        assert secret_ref is not None and secret_hash is not None
        secret_store = self._oauth_secret_store
        if not allow_interactive and isinstance(secret_store, MigratingFallbackSecretStore):
            secret_json = secret_store.get_secret_no_ui(secret_ref)
        else:
            secret_json = self._get_secret_from_store(secret_store, secret_ref)
        if (
            secret_json is None
            or not _secret_matches_hash(secret_json, secret_hash)
            or self._parse_oauth_secret_payload(secret_json) is None
        ):
            return False
        self._remember_oauth_secret_payload(secret_ref, secret_hash, secret_json)
        return True

    def get_cloud_sync_profile(self) -> dict[str, str] | None:
        oauth_payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(oauth_payload, dict) and self.repair_oauth_local_credential_storage_from_primary():
            oauth_payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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

    def list_oauth_sources(self) -> list[dict[str, object]]:
        """List all configured connection source profiles.

        Returns a list of dicts with 'source', 'issuer', and 'workspace_id'
        fields for each source that has OAuth credentials.
        """
        return [dict(source) for source in self._native_store_call("oauth_sources_list", {})]

    def clear_cloud_sync_state_for_reconnect(
        self,
        *,
        now: str | None = None,
        managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
    ) -> None:
        self.clear_policy_bundle_authority(
            now or _now(),
            policy_bundle_last_error={},
            managed_controls_publish=managed_controls_publish,
        )
        self.delete_sync_payloads(
            [
                state_key
                for state_key in _GUARD_CLOUD_RESET_STATE_KEYS
                if state_key
                not in {
                    "managed_controls_active",
                    "managed_controls_negotiated_capabilities",
                }
            ]
        )
        review_sync_key = "guard_cloud_review_sync_state"
        if self.guard_source != "default":
            review_sync_key += f":{self.guard_source}"
        review_sync = self.get_sync_payload(review_sync_key)
        if isinstance(review_sync, dict) and review_sync.get("state") == "error":
            error = review_sync.get("last_error")
            if review_sync.get("last_error_code") in {"cloud_auth_expired", "cloud_connect_required"} or (
                review_sync.get("last_error_code") is None
                and isinstance(error, str)
                and error.startswith(
                    (
                        "Guard authorization expired.",
                        "Guard Cloud sign-in on this device is no longer valid.",
                        "HTTP Error 401:",
                    )
                )
            ):
                self.set_sync_payload(
                    review_sync_key,
                    {**review_sync, "state": "idle", "last_error": None, "last_error_code": None},
                    now or _now(),
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
        device_id: str | None = None,
        supply_chain_entitlement_expires_at: str | None = None,
        supply_chain_firewall: bool | None = None,
        supply_chain_plan_id: str | None = None,
        workspace_id: str | None = None,
        cloud_user_profile: dict[str, str] | None = None,
        runtime_id: str | None = None,
        runtime_label: str | None = None,
        access_token: str | None = None,
        access_token_expires_at: str | None = None,
        force_primary_secret_rewrite: bool = False,
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
        if device_id:
            payload["device_id"] = device_id
        if supply_chain_entitlement_expires_at:
            payload["supply_chain_entitlement_expires_at"] = supply_chain_entitlement_expires_at
        if isinstance(supply_chain_firewall, bool):
            payload["supply_chain_firewall"] = supply_chain_firewall
        if supply_chain_plan_id:
            payload["supply_chain_plan_id"] = supply_chain_plan_id
        if workspace_id:
            payload["workspace_id"] = workspace_id
        if cloud_user_profile:
            payload["cloud_user_profile"] = cloud_user_profile
        if runtime_id:
            payload["runtime_id"] = runtime_id
        if runtime_label:
            payload["runtime_label"] = runtime_label
        existing_payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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
        # Metadata-only updates skip primary rewrite while fallback remains current.
        skip_primary_secret_rewrite = (
            not force_primary_secret_rewrite
            and not secret_material_changed
            and isinstance(self._oauth_secret_store, FallbackSecretStore)
            and isinstance(self._oauth_secret_store.primary, SystemKeyringSecretStore)
            and isinstance(self._oauth_secret_store.fallback, EncryptedFileSecretStore)
        )
        if not skip_primary_secret_rewrite:
            self._oauth_secret_store.set_secret(self._oauth_local_credentials_ref, secret_json)
        self._mirror_oauth_secret_to_fallback(self._oauth_local_credentials_ref, secret_json)
        self._assert_oauth_secret_persisted(self._oauth_local_credentials_ref, secret_json)
        self._remember_oauth_secret_payload(self._oauth_local_credentials_ref, secret_hash, secret_json)
        self.set_sync_payload(self._oauth_local_credentials_state_key, payload, now)

    set_oauth_local_credentials = _with_oauth_credential_lock(_set_oauth_local_credentials_unlocked)

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object] | None:
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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
        with self.hold_oauth_refresh_lock():
            self._clear_oauth_local_credentials_locked()

    def _clear_oauth_local_credentials_locked(self) -> None:
        with self.hold_oauth_credential_lock():
            self._clear_oauth_secret_payload_cache()
            payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
            if isinstance(payload, dict):
                secret_ref = payload.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY)
                if isinstance(secret_ref, str) and secret_ref:
                    self._oauth_secret_store.delete_secret(secret_ref)
                    if sys.platform == "darwin":
                        legacy_fallback = EncryptedFileSecretStore(self.guard_home)
                        legacy_path = legacy_fallback._path_for(secret_ref)
                        with suppress(OSError):
                            legacy_path.unlink()
            self.delete_sync_payload(self._oauth_local_credentials_state_key)
            # A capability bound to one OAuth grant must not survive disconnect for a later grant.
            self.delete_sync_payloads(list(_GUARD_CLOUD_COMMAND_STATE_KEYS))

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(payload, dict) and self.repair_oauth_local_credential_storage_from_primary():
            payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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
            refreshed_payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
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
        copy_oauth_binding_metadata(payload, result)
        for key in ("supply_chain_entitlement_expires_at", "supply_chain_plan_id"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        supply_chain_firewall = payload.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            result["supply_chain_firewall"] = supply_chain_firewall
        cloud_user_profile = payload.get("cloud_user_profile")
        if isinstance(cloud_user_profile, dict):
            result["cloud_user_profile"] = cloud_user_profile
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
        if (
            not isinstance(self.get_sync_payload(self._oauth_local_credentials_state_key), dict)
            and not self._oauth_secret_is_recoverable_without_payload()
        ):
            # Nothing is configured and nothing is recoverable, so there is nothing to repair. Taking the
            # exclusive credential lock for this read-only answer let every health probe on a fresh home
            # queue behind each other on a cold runner until the daemon start timed out.
            return False
        with self.hold_oauth_credential_lock():
            payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
            if not isinstance(payload, dict):
                recovered_payload = self._recover_missing_oauth_local_credentials_payload(now=_now())
                if recovered_payload is None:
                    return False
                self.set_sync_payload(self._oauth_local_credentials_state_key, recovered_payload, _now())
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
        if access_token := _string_value(secret_payload.get("access_token")):
            recovered_payload.update(oauth_binding_metadata(access_token, issuer=oauth_client.issuer))
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

    def _oauth_secret_is_recoverable_without_payload(self) -> bool:
        return self._load_oauth_secret_json_without_payload(self._oauth_local_credentials_ref) is not None

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
            "device_id": _string_value(credentials.get("device_id")),
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
        fallback_secret_payload = self._load_validated_oauth_fallback_secret_payload(
            fallback_secret_json,
            secret_hash,
        )
        if fallback_secret_payload is not None:
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
        copy_oauth_binding_metadata(metadata, result)
        for key in ("supply_chain_entitlement_expires_at", "supply_chain_plan_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                result[key] = value
        supply_chain_firewall = metadata.get("supply_chain_firewall")
        if isinstance(supply_chain_firewall, bool):
            result["supply_chain_firewall"] = supply_chain_firewall
        cloud_user_profile = metadata.get("cloud_user_profile")
        if isinstance(cloud_user_profile, dict):
            result["cloud_user_profile"] = cloud_user_profile
        return result

    def get_latest_guard_connect_state(self, *, now: str) -> dict[str, object] | None:
        return self._native_store_call("guard_connect_latest_state", {"now": now})

    def get_effective_guard_connect_state(self, *, now: str) -> dict[str, object] | None:
        profile = self.get_cloud_sync_profile()
        cloud_profile = None
        if profile is not None:
            sync_url = str(profile["sync_url"])
            cloud_profile = {"sync_url": sync_url, "allowed_origin": _allowed_origin_from_sync_url(sync_url)}
        return self._native_store_call("guard_connect_effective_state", {"now": now, "cloud_profile": cloud_profile})

    def record_guard_connect_pairing_completed(
        self,
        *,
        sync_url: str,
        allowed_origin: str,
        now: str,
        request_id: str | None = None,
    ) -> dict[str, object]:
        normalized_request_id = request_id.strip() if isinstance(request_id, str) and request_id.strip() else None
        return self._native_store_call(
            "guard_connect_record_pairing",
            {
                "request_id": normalized_request_id or f"connect-{uuid4().hex}",
                "sync_url": sync_url,
                "allowed_origin": allowed_origin,
                "now": now,
            },
        )

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
        return self._native_store_call(
            "guard_connect_record_sync_result",
            {
                "status": status,
                "milestone": milestone,
                "now": now,
                "reason": reason,
                "request_id": request_id,
                "sync_payload": sync_payload,
            },
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
