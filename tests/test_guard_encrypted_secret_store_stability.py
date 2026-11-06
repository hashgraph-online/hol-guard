from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_PROCESS_WRITER = textwrap.dedent(
    """
    import json
    import sys
    import time
    from pathlib import Path
    from types import MethodType

    from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

    guard_home, secret_id, value, first_marker_raw, second_marker_raw, result_path_raw, role = sys.argv[1:]
    first_marker = Path(first_marker_raw)
    second_marker = Path(second_marker_raw)
    result_path = Path(result_path_raw)

    def wait_for_path(path: Path, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if path.exists():
                return True
            time.sleep(0.01)
        return path.exists()

    store = EncryptedFileSecretStore(Path(guard_home))
    original = store._atomic_write_bytes
    key_writes = 0

    def instrumented_write(self, path: Path, payload: bytes, mode: int) -> None:
        global key_writes
        if path == self.key_path:
            key_writes += 1
            if role == "first":
                first_marker.touch()
                wait_for_path(second_marker, 1.0)
            else:
                second_marker.touch()
        original(path, payload, mode)

    store._atomic_write_bytes = MethodType(instrumented_write, store)
    error = None
    try:
        if role == "second" and not wait_for_path(first_marker, 5.0):
            raise RuntimeError("first key write did not start")
        store.set_secret(secret_id, value)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    result_path.write_text(
        json.dumps({"secret_id": secret_id, "key_writes": key_writes, "error": error}),
        encoding="utf-8",
    )
    """
)


def test_concurrent_process_first_use_creates_one_key_and_preserves_both_writes(tmp_path: Path) -> None:
    first_marker = tmp_path / "first-key-write-started"
    second_marker = tmp_path / "second-key-write-started"
    result_paths = (tmp_path / "result-0.json", tmp_path / "result-1.json")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    processes = (
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _PROCESS_WRITER,
                str(tmp_path),
                "secret-0",
                "value-0",
                str(first_marker),
                str(second_marker),
                str(result_paths[0]),
                "first",
            ],
            env=environment,
        ),
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _PROCESS_WRITER,
                str(tmp_path),
                "secret-1",
                "value-1",
                str(first_marker),
                str(second_marker),
                str(result_paths[1]),
                "second",
            ],
            env=environment,
        ),
    )

    for process in processes:
        assert process.wait(timeout=10) == 0

    results: list[dict[str, Any]] = [json.loads(path.read_text(encoding="utf-8")) for path in result_paths]
    assert all(result["error"] is None for result in results)
    assert sum(int(result["key_writes"]) for result in results) == 1
    reopened = EncryptedFileSecretStore(tmp_path)
    assert reopened.get_secret("secret-0") == "value-0"
    assert reopened.get_secret("secret-1") == "value-1"


def test_invalid_existing_vault_key_fails_closed_without_rotation(tmp_path: Path) -> None:
    enrolled = EncryptedFileSecretStore(tmp_path)
    enrolled.set_secret("authority", "value")
    encrypted_path = enrolled._path_for("authority")
    ciphertext = encrypted_path.read_bytes()
    enrolled.key_path.write_bytes(b"")

    restarted = EncryptedFileSecretStore(tmp_path)
    with pytest.raises(RuntimeError, match="key is empty"):
        restarted.get_secret("authority")

    assert enrolled.key_path.read_bytes() == b""
    assert encrypted_path.read_bytes() == ciphertext
