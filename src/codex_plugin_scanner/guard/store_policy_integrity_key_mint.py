"""Cross-process first mint of the local policy-integrity signing key."""

from __future__ import annotations

import base64
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from .advisory_lock_handoff import hold_advisory_file_lock

MINT_LOCK_FILE_NAME = ".policy-integrity-key-mint.lock"
_MINT_LOCK_TIMEOUT_SECONDS = 10.0
_MINT_LOCK_RETRY_SECONDS = 0.01
NATIVE_MINT_FEATURE = "native-policy-integrity-key-mint-v1"
NATIVE_KEYRING_MINT_FEATURE = "native-policy-integrity-key-mint-secret-service-v1"
_SECRET_SERVICE_BACKEND = ("keyring.backends.SecretService", "Keyring")
_NATIVE_MINT_COMMAND = "policy-integrity-key-mint"
_NATIVE_MINT_STATES = frozenset({"present", "armed", "busy", "unavailable"})
# The native mint gives its two lock waits one four-second budget, inside this deadline.
_NATIVE_MINT_TIMEOUT_SECONDS = 15.0
_NATIVE_MINT_OUTPUT_LIMIT = 4096


def native_mint_keyring_service(guard_home: Path, secret_store: object) -> str | None:
    """Return the keyring service the native mint may write for this store.

    Only the Linux store that mirrors Python keyring's own Secret Service
    backend into the vault qualifies. The native client writes items exactly as
    that backend does; a chained backend, a configured collection or a test
    keyring would not read them back the same way, so those keep Python's mint.
    """

    if sys.platform != "linux":
        return None
    from .store_base import _POLICY_INTEGRITY_SERVICE_NAME, EncryptedFileSecretStore, SystemKeyringSecretStore
    from .store_policy_integrity_backend import MirroredPolicyIntegritySecretStore

    if type(secret_store) is not MirroredPolicyIntegritySecretStore:
        return None
    primary, fallback = secret_store.primary, secret_store.fallback
    if type(primary) is not SystemKeyringSecretStore or primary.service_name != _POLICY_INTEGRITY_SERVICE_NAME:
        return None
    if type(fallback) is not EncryptedFileSecretStore or fallback.base_dir != guard_home / "secrets":
        return None
    if SystemKeyringSecretStore._test_keyring_module() is not None:
        return None
    keyring_module = SystemKeyringSecretStore._load_keyring_module_or_none()
    try:
        backend = keyring_module.get_keyring() if keyring_module is not None else None
    except Exception:
        return None
    backend_type = type(backend)
    if (backend_type.__module__, backend_type.__name__) != _SECRET_SERVICE_BACKEND:
        return None
    if getattr(backend, "preferred_collection", None) is not None:
        return None
    return primary.service_name


def native_policy_integrity_key_mint(guard_home: Path, *, keyring_service: str | None = None) -> str | None:
    """Ask the native runtime to mint the key in the encrypted-file store.

    With ``keyring_service`` the native mint writes the store that mirrors the
    Linux desktop keyring into the vault, keeping that store's rules.

    The answer names a state and never carries the key: ``present`` (read it
    back from the store), ``armed`` or ``busy`` (mint nothing), or
    ``unavailable``. ``None`` means no runtime offers the mint, and the caller
    keeps its own.
    """

    from .mdm.runtime_request import runtime_answer

    # The runtime runs from its own directory, so a relative home would name
    # another place there.
    request: dict[str, object] = {"guard_home": str(guard_home.expanduser().resolve())}
    if keyring_service is not None:
        request["keyring"] = {"service_name": keyring_service}
    answer = runtime_answer(
        NATIVE_MINT_FEATURE if keyring_service is None else NATIVE_KEYRING_MINT_FEATURE,
        _NATIVE_MINT_COMMAND,
        request,
        output_limit=_NATIVE_MINT_OUTPUT_LIMIT,
        # One budget for the status check and the command together.
        deadline=time.monotonic() + _NATIVE_MINT_TIMEOUT_SECONDS,
    )
    if answer is None or set(answer) != {"state"}:
        return None
    state = answer["state"]
    return state if isinstance(state, str) and state in _NATIVE_MINT_STATES else None


def mint_policy_integrity_key_once(
    guard_home: Path,
    *,
    read_key: Callable[[], str | None],
    write_key: Callable[[str], None],
    native_controls_armed: Callable[[], bool],
) -> str | None:
    """Return the stored signing key, minting one only while holding the mint lock.

    Processes that start together on a fresh Guard home can all find no key.
    Without the lock each mints its own and the last write replaces the
    others, so a native verifier key derived from an earlier key no longer
    matches the stored one and every later daemon fails closed. Under the
    lock the store is read again, and a key another process wrote wins.

    Returns ``None`` when the lock cannot be taken in time, or when native
    controls are already armed with a key this process cannot read.
    """

    guard_home.mkdir(parents=True, exist_ok=True)
    lock_path = guard_home / MINT_LOCK_FILE_NAME
    os.close(os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600))
    try:
        with hold_advisory_file_lock(
            path=lock_path,
            timeout_seconds=_MINT_LOCK_TIMEOUT_SECONDS,
            poll_seconds=_MINT_LOCK_RETRY_SECONDS,
            timeout_message="policy-integrity key mint lock is busy",
        ):
            existing = read_key()
            if existing is not None:
                return existing
            if native_controls_armed():
                return None
            write_key(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
            return read_key()
    except TimeoutError:
        return None
