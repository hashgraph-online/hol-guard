from __future__ import annotations

import json
import os
from pathlib import Path


def _store_path() -> Path | None:
    value = os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
    return Path(value) if value else None


def _load() -> dict[tuple[str, str], str]:
    store_path = _store_path()
    if store_path is None or not store_path.is_file():
        return {}
    payload = json.loads(store_path.read_text(encoding="utf-8"))
    return {
        (str(service_name), str(secret_id)): str(secret_value)
        for service_name, secrets in payload.items()
        if isinstance(service_name, str) and isinstance(secrets, dict)
        for secret_id, secret_value in secrets.items()
        if isinstance(secret_id, str) and isinstance(secret_value, str)
    }


def _persist(secrets: dict[tuple[str, str], str]) -> None:
    store_path = _store_path()
    if store_path is None:
        return
    payload: dict[str, dict[str, str]] = {}
    for (service_name, secret_id), secret_value in secrets.items():
        payload.setdefault(service_name, {})[secret_id] = secret_value
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def get_keyring():
    class _Backend:
        priority = 1 if _store_path() is not None else 0

    return _Backend()


def set_password(service_name: str, secret_id: str, value: str) -> None:
    secrets = _load()
    secrets[(service_name, secret_id)] = value
    _persist(secrets)


def get_password(service_name: str, secret_id: str) -> str | None:
    return _load().get((service_name, secret_id))


def delete_password(service_name: str, secret_id: str) -> None:
    secrets = _load()
    secrets.pop((service_name, secret_id), None)
    _persist(secrets)
