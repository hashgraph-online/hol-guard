"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

import hmac

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
class FallbackSecretStore:
    """Fallback-capable secret store that tolerates primary backend failures."""

    @_preserve_module
    def __init__(self, primary: SecretStore, fallback: SecretStore) -> None:
        self.primary = primary
        self.fallback = fallback

    @_preserve_module
    def set_secret(self, secret_id: str, value: str) -> None:
        try:
            self.primary.set_secret(secret_id, value)
        except Exception:
            self.fallback.set_secret(secret_id, value)

    @_preserve_module
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

    @_preserve_module
    def promote_secret(self, secret_id: str, value: str) -> None:
        try:
            primary_value = self.primary.get_secret(secret_id)
        except Exception:
            primary_value = None
        if primary_value is not None and hmac.compare_digest(
            primary_value.encode("utf-8", "surrogatepass"), value.encode("utf-8", "surrogatepass")
        ):
            return
        try:
            self.primary.set_secret(secret_id, value)
        except Exception:
            return

    @_preserve_module
    def delete_secret(self, secret_id: str) -> None:
        for store in (self.primary, self.fallback):
            try:
                store.delete_secret(secret_id)
            except Exception:
                _base._store_logger.warning(
                    "Failed to delete Guard secret from %s",
                    type(store).__name__,
                )
                continue


@_preserve_module
class MigratingFallbackSecretStore(FallbackSecretStore):
    """Prefer the local fallback and migrate a legacy primary value once."""

    @_preserve_module
    def set_secret(self, secret_id: str, value: str) -> None:
        with _base.suppress(Exception):
            self.primary.set_secret(secret_id, value)
        self.fallback.set_secret(secret_id, value)

    @_preserve_module
    def get_secret(self, secret_id: str) -> str | None:
        return self._get_secret_and_migrate(secret_id, allow_interactive=True)

    @_preserve_module
    def get_secret_no_ui(self, secret_id: str) -> str | None:
        """Migrate only when the primary can answer without authentication UI."""

        return self._get_secret_and_migrate(secret_id, allow_interactive=False)

    @_preserve_module
    def _get_secret_and_migrate(self, secret_id: str, *, allow_interactive: bool) -> str | None:
        try:
            fallback_value = self.fallback.get_secret(secret_id)
        except Exception:
            fallback_value = None
        if fallback_value is not None:
            return fallback_value
        try:
            if not allow_interactive and isinstance(self.primary, _base.SystemKeyringSecretStore):
                primary_value = self.primary.get_secret_with_timeout(secret_id, timeout_seconds=0.5)
            else:
                primary_value = self.primary.get_secret(secret_id)
        except Exception:
            return None
        if primary_value is None:
            return None
        try:
            self.fallback.set_secret(secret_id, primary_value)
        except Exception:
            return None
        return primary_value


@_preserve_module
def _system_keyring_availability_cache_path(guard_home: Path) -> Path:
    return guard_home / _base._SYSTEM_KEYRING_AVAILABILITY_CACHE_FILE


@_preserve_module
def _read_system_keyring_availability_cache(guard_home: Path) -> bool | None:
    if _base.sys.platform != "darwin":
        return None
    path = _base._system_keyring_availability_cache_path(guard_home)
    try:
        payload = _base.json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _base.json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    checked_at = payload.get("checked_at")
    available = payload.get("available")
    if isinstance(checked_at, bool) or not isinstance(checked_at, (int, float)):
        return None
    if not isinstance(available, bool):
        return None
    if (_base.time.time() - float(checked_at)) >= _base._SYSTEM_KEYRING_AVAILABILITY_CACHE_TTL_SECONDS:
        return None
    return available


@_preserve_module
def _write_system_keyring_availability_cache(guard_home: Path, *, available: bool) -> None:
    if _base.sys.platform != "darwin":
        return
    path = _base._system_keyring_availability_cache_path(guard_home)
    tmp_path = path.with_name(f".{path.name}.{_base.uuid4().hex}.tmp")
    payload = {
        "available": available,
        "checked_at": _base.time.time(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(
            _base.json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        _base._set_private_mode(tmp_path, _base._GUARD_STORE_PRIVATE_FILE_MODE)
        tmp_path.replace(path)
    except OSError:
        return
    finally:
        with _base.suppress(OSError):
            tmp_path.unlink()


@_preserve_module
def _system_keyring_is_available(guard_home: Path, *, use_cache: bool = True) -> bool:
    cached = _base._read_system_keyring_availability_cache(guard_home) if use_cache else None
    if cached is not None:
        return cached
    if not use_cache and _base.sys.platform == "darwin":
        _base.SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    available = _base.SystemKeyringSecretStore._is_available()
    _base._write_system_keyring_availability_cache(guard_home, available=available)
    return available


@_preserve_module
def _build_oauth_secret_store(
    guard_home: Path,
    *,
    allow_system_keyring: bool = False,
) -> SecretStore:
    fallback_store = _base.EncryptedFileSecretStore(guard_home)
    if _base.sys.platform == "darwin":
        if not allow_system_keyring:
            return fallback_store
        return _base.MigratingFallbackSecretStore(
            _base.SystemKeyringSecretStore(service_name="hol-guard.oauth"),
            fallback_store,
        )
    if _base._system_keyring_is_available(guard_home):
        return _base.FallbackSecretStore(
            _base.SystemKeyringSecretStore(service_name="hol-guard.oauth"),
            fallback_store,
        )
    return fallback_store


@_preserve_module
def _build_policy_integrity_secret_store(
    guard_home: Path,
    *,
    allow_system_keyring: bool = False,
) -> SecretStore | None:
    if _base.sys.platform == "darwin":
        fallback_store = _base.EncryptedFileSecretStore(guard_home)
        if not allow_system_keyring:
            return fallback_store
        if _base.SystemKeyringSecretStore._test_keyring_module() is not None:
            return _base.MigratingFallbackSecretStore(
                _base.SystemKeyringSecretStore(service_name=_base._POLICY_INTEGRITY_SERVICE_NAME),
                fallback_store,
            )
        if not _base.SystemKeyringSecretStore._backend_is_available():
            return fallback_store
        if not _base.SystemKeyringSecretStore._supports_native_macos_security_reads():
            return fallback_store
        return _base.MigratingFallbackSecretStore(
            _base.SystemKeyringSecretStore(service_name=_base._POLICY_INTEGRITY_SERVICE_NAME),
            fallback_store,
        )
    if _base.SystemKeyringSecretStore._backend_is_available():
        return _base.SystemKeyringSecretStore(service_name=_base._POLICY_INTEGRITY_SERVICE_NAME)
    return None


@_preserve_module
def _secret_store_backend_name(secret_store: SecretStore) -> str:
    if isinstance(secret_store, _base.SystemKeyringSecretStore):
        return "system-keyring"
    if isinstance(secret_store, _base.EncryptedFileSecretStore):
        return "encrypted-file"
    if isinstance(secret_store, _base.UnavailableSecretStore):
        return "unavailable"
    if isinstance(secret_store, _base.FallbackSecretStore):
        return _base._secret_store_backend_name(secret_store.primary)
    return "unknown"


@_preserve_module
def _secret_store_fallback_backend_name(secret_store: SecretStore) -> str | None:
    if isinstance(secret_store, _base.FallbackSecretStore):
        return _base._secret_store_backend_name(secret_store.fallback)
    return None


# Bind dependencies after declarations so each owner can be imported first.
from . import store_base as _base  # noqa: E402
from .store_base import Path, SecretStore  # noqa: E402
