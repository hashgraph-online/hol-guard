from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import cast

_PROCESS_LOCK = threading.RLock()
_LOCK_TIMEOUT_SECONDS = 10.0


def _store_path() -> Path | None:
    value = os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
    return Path(value) if value else None


def _load() -> dict[tuple[str, str], str]:
    store_path = _store_path()
    if store_path is None or not store_path.is_file():
        return {}
    decoded = cast(object, json.loads(store_path.read_text(encoding="utf-8")))
    if not isinstance(decoded, Mapping):
        return {}
    result: dict[tuple[str, str], str] = {}
    for service_name, secrets in cast(Mapping[object, object], decoded).items():
        if not isinstance(service_name, str) or not isinstance(secrets, Mapping):
            continue
        for secret_id, secret_value in cast(Mapping[object, object], secrets).items():
            if isinstance(secret_id, str) and isinstance(secret_value, str):
                result[(service_name, secret_id)] = secret_value
    return result


def _persist(secrets: dict[tuple[str, str], str]) -> None:
    store_path = _store_path()
    if store_path is None:
        return
    payload: dict[str, dict[str, str]] = {}
    for (service_name, secret_id), secret_value in secrets.items():
        payload.setdefault(service_name, {})[secret_id] = secret_value
    store_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = store_path.with_name(f".{store_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        _ = temporary_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        _ = temporary_path.replace(store_path)
    finally:
        temporary_path.unlink(missing_ok=True)


@contextmanager
def _exclusive_store_lock() -> Generator[None]:
    store_path = _store_path()
    if store_path is None:
        yield
        return
    lock_path = store_path.with_name(f".{store_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    while True:
        try:
            lock_path.mkdir()
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for the fake keyring store lock") from None
            time.sleep(0.01)
    try:
        yield
    finally:
        lock_path.rmdir()


def get_keyring():
    class _Backend:
        priority: int = 1 if _store_path() is not None else 0

    return _Backend()


def set_password(service_name: str, secret_id: str, value: str) -> None:
    with _PROCESS_LOCK, _exclusive_store_lock():
        secrets = _load()
        secrets[(service_name, secret_id)] = value
        _persist(secrets)


def get_password(service_name: str, secret_id: str) -> str | None:
    return _load().get((service_name, secret_id))


def delete_password(service_name: str, secret_id: str) -> None:
    with _PROCESS_LOCK, _exclusive_store_lock():
        secrets = _load()
        _ = secrets.pop((service_name, secret_id), None)
        _persist(secrets)
