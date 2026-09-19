"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
class SystemKeyringSecretStore:
    """Cross-platform OS credential store backed by the Python keyring library."""

    _MACOS_KEYCHAIN_HEALTH_CACHE_TTL_SECONDS = 5.0
    _WINDOWS_NO_SUCH_LOGON_SESSION = 1312
    _macos_keychain_health_cache: tuple[float, bool] | None = None
    _native_macos_security_reads_cache: tuple[tuple[int, int], bool] | None = None

    @_preserve_module
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self._windows_keyring_unavailable = False

    @staticmethod
    @_preserve_module
    def _load_keyring_module():
        """Load the optional keyring package.

        Returns None when the package is absent. Installed-keyring failures
        propagate so callers can surface them instead of silently degrading
        credential storage.
        """
        test_keyring = _base.SystemKeyringSecretStore._test_keyring_module()
        if test_keyring is not None:
            return test_keyring
        try:
            return _base.importlib.import_module("keyring")
        except ModuleNotFoundError as exc:
            if exc.name == "keyring":
                return None
            raise

    @classmethod
    @_preserve_module
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
            _base._store_logger.warning(
                "Guard system keyring backend could not be initialized; using encrypted-file fallback.",
                exc_info=True,
            )
            return None

    @staticmethod
    @_preserve_module
    def _test_keyring_module():
        if not _base.os.environ.get("PYTEST_CURRENT_TEST"):
            return None
        store_path_raw = _base.os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
        if not store_path_raw:
            return None

        @_preserve_module
        class _TestKeyringModule:
            @staticmethod
            @_preserve_module
            def _store_path() -> Path:
                return _base.Path(store_path_raw)

            @classmethod
            @_preserve_module
            def _load(cls) -> dict[tuple[str, str], str]:
                store_path = cls._store_path()
                if not store_path.is_file():
                    return {}
                payload = _base.json.loads(store_path.read_text(encoding="utf-8"))
                return {
                    (str(service_name), str(secret_id)): str(secret_value)
                    for service_name, secrets in payload.items()
                    if isinstance(service_name, str) and isinstance(secrets, dict)
                    for secret_id, secret_value in secrets.items()
                    if isinstance(secret_id, str) and isinstance(secret_value, str)
                }

            @classmethod
            @_preserve_module
            def _persist(cls, secrets: dict[tuple[str, str], str]) -> None:
                payload: dict[str, dict[str, str]] = {}
                for (service_name, secret_id), secret_value in secrets.items():
                    payload.setdefault(service_name, {})[secret_id] = secret_value
                store_path = cls._store_path()
                store_path.parent.mkdir(parents=True, exist_ok=True)
                store_path.write_text(
                    _base.json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
                )

            @staticmethod
            @_preserve_module
            def get_keyring():
                @_preserve_module
                class _Backend:
                    priority = 1

                return _Backend()

            @classmethod
            @_preserve_module
            def set_password(cls, service_name: str, secret_id: str, value: str) -> None:
                secrets = cls._load()
                secrets[(service_name, secret_id)] = value
                cls._persist(secrets)

            @classmethod
            @_preserve_module
            def get_password(cls, service_name: str, secret_id: str) -> str | None:
                return cls._load().get((service_name, secret_id))

            @classmethod
            @_preserve_module
            def delete_password(cls, service_name: str, secret_id: str) -> None:
                secrets = cls._load()
                secrets.pop((service_name, secret_id), None)
                cls._persist(secrets)

        return _TestKeyringModule

    @staticmethod
    @_preserve_module
    def _load_macos_keyring_api_module():
        from keyring.backends.macOS import api as macos_keyring_api

        return macos_keyring_api

    @staticmethod
    @_preserve_module
    def _macos_default_keychain_path() -> Path | None:
        result = _base.SystemKeyringSecretStore._run_macos_security_command("default-keychain", "-d", "user")
        if result is None:
            return None
        raw_path = result.stdout.strip().strip('"').strip("'")
        if not raw_path:
            return None
        return _base.Path(raw_path).expanduser()

    @staticmethod
    @_preserve_module
    def _run_macos_security_command(*args: str) -> subprocess.CompletedProcess[str] | None:
        if _base.sys.platform != "darwin":
            return None
        security_path = _base.Path("/usr/bin/security")
        if not security_path.exists():
            return None
        try:
            result = _base.subprocess.run(
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
    @_preserve_module
    def _macos_user_keychain_paths(cls) -> tuple[Path, ...]:
        result = cls._run_macos_security_command("list-keychains", "-d", "user")
        if result is None:
            return ()
        paths: list[Path] = []
        for line in result.stdout.splitlines():
            raw_path = line.strip().strip('"').strip("'")
            if raw_path:
                paths.append(_base.Path(raw_path).expanduser())
        return tuple(paths)

    @classmethod
    @_preserve_module
    def _macos_keychain_path_is_usable(cls, path: Path | None) -> bool:
        if path is None:
            return False
        expanded = path.expanduser()
        if not expanded.exists():
            return False
        return cls._run_macos_security_command("show-keychain-info", str(expanded)) is not None

    @staticmethod
    @_preserve_module
    def _normalized_macos_keychain_path(path: Path) -> str:
        return _base.os.path.realpath(_base.os.fspath(path.expanduser()))

    @classmethod
    @_preserve_module
    def _clear_macos_keychain_health_cache(cls) -> None:
        cls._macos_keychain_health_cache = None

    @classmethod
    @_preserve_module
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
    @_preserve_module
    def _macos_default_keychain_is_usable(cls) -> bool:
        if _base.sys.platform != "darwin":
            return False
        cached = cls._macos_keychain_health_cache
        now = _base.time.monotonic()
        if cached is not None and (now - cached[0]) < cls._MACOS_KEYCHAIN_HEALTH_CACHE_TTL_SECONDS:
            return cached[1]
        result = cls._macos_default_keychain_is_usable_uncached()
        cls._macos_keychain_health_cache = (now, result)
        return result

    @classmethod
    @_preserve_module
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
    @_preserve_module
    def _is_available(cls) -> bool:
        if cls._test_keyring_module() is not None:
            return True
        if not cls._backend_is_available():
            return False
        if _base.sys.platform == "darwin" and not cls._macos_default_keychain_is_usable():  # noqa: SIM103
            return False
        return True

    @classmethod
    @_preserve_module
    def _is_windows_keyring_session_unavailable(cls, error: BaseException) -> bool:
        if _base.sys.platform != "win32":
            return False
        return cls._WINDOWS_NO_SUCH_LOGON_SESSION in {
            getattr(error, "winerror", None),
            getattr(error, "errno", None),
        }

    @_preserve_module
    def _mark_windows_keyring_unavailable(self) -> None:
        if self._windows_keyring_unavailable:
            return
        self._windows_keyring_unavailable = True
        _base._store_logger.warning(
            "Guard system keyring writes are unavailable in this Windows session; policy integrity is degraded."
        )

    @_preserve_module
    def _clear_windows_keyring_unavailable(self) -> None:
        self._windows_keyring_unavailable = False

    @_preserve_module
    def _is_unavailable(self) -> bool:
        return self._windows_keyring_unavailable

    @_preserve_module
    def set_secret(self, secret_id: str, value: str) -> None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            raise RuntimeError(
                "Guard system keyring backend is unavailable; the Python 'keyring' "
                "package could not be imported. Reinstall hol-guard to restore it."
            )
        try:
            keyring_module.set_password(self.service_name, secret_id, value)
        except Exception as error:
            if not self._is_windows_keyring_session_unavailable(error):
                raise
            self._mark_windows_keyring_unavailable()
            raise
        self._clear_windows_keyring_unavailable()

    @_preserve_module
    def get_secret(self, secret_id: str) -> str | None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            return None
        try:
            value = keyring_module.get_password(self.service_name, secret_id)
        except Exception as error:
            if not self._is_windows_keyring_session_unavailable(error):
                raise
            return None
        return value if isinstance(value, str) and value else None

    @classmethod
    @_preserve_module
    def _supports_native_macos_security_reads(cls) -> bool:
        if _base.sys.platform != "darwin":
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

    @_preserve_module
    def _get_secret_without_macos_ui(self, secret_id: str) -> str | None:
        if not self._supports_native_macos_security_reads():
            return None
        data = None
        try:
            from ctypes import byref

            macos_keyring_api = self._load_macos_keyring_api_module()
            # The macOS keyring backend returns password bytes here but exposes
            # its decoder under the historical cfstr_to_str name.
            cfstr_to_str = getattr(macos_keyring_api, "cfstr_to_str", None)
            cf_release = getattr(macos_keyring_api, "CFRelease", None)
            # Keep prompt suppression scoped to this query. Disabling keychain
            # interaction process-wide makes otherwise readable items fail auth.
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
        if status == 0:
            if not callable(cfstr_to_str):
                return None
            try:
                value = cfstr_to_str(data)
            except Exception:
                value = None
            finally:
                if data is not None and callable(cf_release):
                    with _base.suppress(Exception):
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

    @_preserve_module
    def _get_macos_secret_in_isolated_process(
        self,
        secret_id: str,
        *,
        timeout_seconds: float,
    ) -> str | None:
        """Read one Keychain item behind a killable process boundary.

        Some macOS Keychain configurations can block inside
        ``SecItemCopyMatching`` even with the query-local no-UI flag. A thread
        timeout cannot recover from that native call, so passive Guard reads
        run in a disposable interpreter and fail closed when the deadline
        expires.
        """

        worker = (
            "import json,sys;"
            "from codex_plugin_scanner.guard.store_base import SystemKeyringSecretStore;"
            "value=SystemKeyringSecretStore(service_name=sys.argv[1])."
            "_get_secret_without_macos_ui(sys.argv[2]);"
            "sys.stdout.write(json.dumps({'value':value},separators=(',',':')))"
        )
        environment = {
            key: value
            for key, value in _base.os.environ.items()
            if key in {"HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "TMPDIR", "USER"} or key.startswith("LC_")
        }
        try:
            completed = _base.subprocess.run(
                [_base.sys.executable, "-I", "-c", worker, self.service_name, secret_id],
                check=False,
                capture_output=True,
                env=environment,
                stdin=_base.subprocess.DEVNULL,
                timeout=max(timeout_seconds, 0.1),
            )
        except (OSError, _base.subprocess.TimeoutExpired):
            return None
        if completed.returncode != 0:
            return None
        try:
            payload = _base.json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, _base.json.JSONDecodeError):
            return None
        value = payload.get("value") if isinstance(payload, dict) else None
        return value if isinstance(value, str) and value else None

    @_preserve_module
    def get_secret_with_timeout(self, secret_id: str, *, timeout_seconds: float = 0.0) -> str | None:
        if _base.sys.platform != "darwin" and self._test_keyring_module() is not None:
            return self.get_secret(secret_id)
        if _base.sys.platform == "darwin":
            if (
                self._test_keyring_module() is not None
                and getattr(type(self)._get_macos_secret_in_isolated_process, "__name__", "")
                == "_get_macos_secret_in_isolated_process"
            ):
                return self.get_secret(secret_id)
            if self._supports_native_macos_security_reads():
                return self._get_macos_secret_in_isolated_process(
                    secret_id,
                    timeout_seconds=timeout_seconds,
                )
            if self._test_keyring_module() is not None:
                return self.get_secret(secret_id)
            if self.service_name == _base._POLICY_INTEGRITY_SERVICE_NAME:
                # Passive policy-integrity reads must fail closed when native
                # no-UI access is unavailable.
                return None
            return None
        if self._supports_native_macos_security_reads():
            return self._get_secret_without_macos_ui(secret_id)
        return self.get_secret(secret_id)

    @_preserve_module
    def delete_secret(self, secret_id: str) -> None:
        keyring_module = self._load_keyring_module_or_none()
        if keyring_module is None:
            return
        try:
            keyring_module.delete_password(self.service_name, secret_id)
        except Exception:
            return


# Bind dependencies after declarations so each owner can be imported first.
from . import store_base as _base  # noqa: E402
from .store_base import Path, subprocess  # noqa: E402
