"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
def _acquire_advisory_file_lock(handle) -> None:
    if _base.os.name == "nt":
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


@_preserve_module
def _release_advisory_file_lock(handle) -> None:
    if _base.os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@_preserve_module
class EncryptedFileSecretStore:
    """Encrypted file-based secret store for Guard credentials.

    The Fernet key and encrypted payloads both live inside the same per-user Guard
    directory, so this is encrypted-at-rest fallback storage rather than a substitute
    for an OS credential manager.
    """

    @_preserve_module
    def __init__(self, guard_home: Path) -> None:
        self.base_dir = guard_home / "secrets"
        self.key_path = self.base_dir / "key.bin"
        self._fernet: Fernet | None = None

    @_preserve_module
    def _ensure_ready(self) -> None:
        if self._fernet is not None:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Owner-only directory access is required for encrypted secret material.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        _base.os.chmod(self.base_dir, 0o700)
        lock_key = _base.os.path.realpath(_base.os.fspath(self.key_path))
        with _base._ENCRYPTED_SECRET_INIT_LOCKS_GUARD:
            thread_lock = _base._ENCRYPTED_SECRET_INIT_LOCKS.setdefault(lock_key, _base.threading.Lock())
        with thread_lock:
            if self._fernet is not None:
                return
            lock_path = self.base_dir / ".key-init.lock"
            with lock_path.open("a+b") as lock_handle:
                _base.os.chmod(lock_path, 0o600)
                deadline = _base.time.monotonic() + 30.0
                while True:
                    try:
                        _base._acquire_advisory_file_lock(lock_handle)
                        break
                    except BlockingIOError:
                        if _base.time.monotonic() >= deadline:
                            raise RuntimeError("timed out initializing encrypted Guard secrets") from None
                        _base.time.sleep(0.01)
                try:
                    if not self.key_path.exists():
                        self._atomic_write_bytes(self.key_path, _base.Fernet.generate_key(), 0o600)
                    key = self._load_fernet_key()
                    _base.os.chmod(self.key_path, 0o600)
                    self._fernet = _base.Fernet(key)
                finally:
                    _base._release_advisory_file_lock(lock_handle)

    @_preserve_module
    def set_secret(self, secret_id: str, value: str) -> None:
        self._ensure_ready()
        payload = self._encrypt_fernet(value)
        path = self._path_for(secret_id)
        self._atomic_write_text(path, _base.json.dumps(payload), 0o600)

    @_preserve_module
    def get_secret(self, secret_id: str) -> str | None:
        self._ensure_ready()
        path = self._path_for(secret_id)
        if not path.exists():
            return None
        try:
            payload = _base.json.loads(path.read_text(encoding="utf-8"))
        except _base.json.JSONDecodeError:
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

    @_preserve_module
    def delete_secret(self, secret_id: str) -> None:
        self._ensure_ready()
        path = self._path_for(secret_id)
        if path.exists():
            path.unlink()

    @_preserve_module
    def _path_for(self, secret_id: str) -> Path:
        normalized = secret_id.replace("/", "_").replace(":", "_")
        return self.base_dir / f"{normalized}.enc"

    @_preserve_module
    def _load_fernet_key(self) -> bytes:
        existing = self.key_path.read_bytes().strip()
        if not existing:
            raise RuntimeError("encrypted Guard secret key is empty")
        try:
            decoded = _base.base64.urlsafe_b64decode(existing)
        except (ValueError, TypeError):
            decoded = b""
        if len(decoded) == 32:
            if len(existing) == 32:
                upgraded = _base.base64.urlsafe_b64encode(existing)
                self._atomic_write_bytes(self.key_path, upgraded, 0o600)
                return upgraded
            return existing
        if len(existing) == 32:
            upgraded = _base.base64.urlsafe_b64encode(existing)
            self._atomic_write_bytes(self.key_path, upgraded, 0o600)
            return upgraded
        raise RuntimeError("encrypted Guard secret key is invalid")

    @_preserve_module
    def _atomic_write_bytes(self, path: Path, payload: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.{_base.uuid4().hex}.tmp")
        try:
            with tmp_path.open("wb") as handle:
                handle.write(payload)
                handle.flush()
                _base.os.fsync(handle.fileno())
            _base.os.chmod(tmp_path, mode)
            _base.os.replace(tmp_path, path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    @_preserve_module
    def _atomic_write_text(self, path: Path, payload: str, mode: int) -> None:
        self._atomic_write_bytes(path, payload.encode("utf-8"), mode)

    @_preserve_module
    def _encrypt_fernet(self, value: str) -> dict[str, str]:
        fernet = self._fernet
        if fernet is None:
            raise RuntimeError("secret store is not initialized")
        token = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return {
            "version": "fernet-v1",
            "ciphertext": token,
        }

    @_preserve_module
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
        except (_base.InvalidToken, ValueError, TypeError):
            return None
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None

    @_preserve_module
    def _decrypt_legacy_payload(self, payload: dict[str, object]) -> str | None:
        nonce_value = payload.get("nonce")
        ciphertext_value = payload.get("ciphertext")
        if not isinstance(nonce_value, str) or not isinstance(ciphertext_value, str):
            return None
        try:
            nonce = _base.base64.urlsafe_b64decode(nonce_value.encode("ascii"))
            ciphertext = _base.base64.urlsafe_b64decode(ciphertext_value.encode("ascii"))
            key = _base.base64.urlsafe_b64decode(self._load_fernet_key())
        except (ValueError, TypeError):
            return None
        keystream = _base._expand_keystream(key=key, nonce=nonce, length=len(ciphertext))
        plaintext = bytes(item ^ mask for item, mask in zip(ciphertext, keystream, strict=True))
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None


@_preserve_module
class UnavailableSecretStore:
    """Secret store placeholder for platforms without safe credential storage."""

    @_preserve_module
    def __init__(self, guard_home: Path | None = None) -> None:
        self._legacy_fallback = _base.EncryptedFileSecretStore(guard_home) if guard_home is not None else None

    @_preserve_module
    def set_secret(self, secret_id: str, value: str) -> None:
        _ = (secret_id, value)
        raise RuntimeError(
            "Guard local credentials require an available OS credential store. "
            "Fix the system credential store, then sign in again."
        )

    @_preserve_module
    def get_secret(self, secret_id: str) -> str | None:
        _ = secret_id
        return None

    @_preserve_module
    def delete_secret(self, secret_id: str) -> None:
        if self._legacy_fallback is None:
            return
        legacy_path = self._legacy_fallback._path_for(secret_id)
        with _base.suppress(OSError):
            legacy_path.unlink()


@_preserve_module
def _expand_keystream(*, key: bytes, nonce: bytes, length: int) -> bytes:
    chunks: list[bytes] = []
    generated = 0
    counter = 0
    while generated < length:
        counter_bytes = counter.to_bytes(4, byteorder="big", signed=False)
        digest = _base.sha256(key + nonce + counter_bytes).digest()
        chunks.append(digest)
        generated += len(digest)
        counter += 1
    return b"".join(chunks)[:length]


@_preserve_module
def _set_private_mode(path: Path, mode: int) -> None:
    if _base.os.name == "nt":
        return
    try:
        _base.os.chmod(path, mode)
    except OSError as exc:
        _base._store_logger.debug("Could not set private mode %o on %s: %s", mode, path, exc)
        return


# Bind dependencies after declarations so each owner can be imported first.
from . import store_base as _base  # noqa: E402
from .store_base import Fernet, Path  # noqa: E402
