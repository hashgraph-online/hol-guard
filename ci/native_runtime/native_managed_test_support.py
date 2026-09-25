"""Production-client integration fixtures; no Python resident implementation."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_resident_client import close_native_residents, native_resident_client_request


@pytest.fixture(name="managed_runtime")
def managed_runtime(tmp_path: Path) -> Iterator[tuple[Path, Path]]:
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled Rust runtime; native retirement proof cannot skip")
    runtime = Path(binary).resolve(strict=True)
    guard_home = tmp_path / "guard-home"
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    try:
        yield runtime, guard_home
    finally:
        assert close_native_residents(guard_home), "managed native resident cleanup did not complete"


def environment(guard_home: Path) -> dict[str, str]:
    result = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    result.update(HOME=str(guard_home.parent), USERPROFILE=str(guard_home.parent))
    return result


def request(runtime: Path, guard_home: Path, payload: bytes) -> dict[str, object]:
    raw = native_resident_client_request(
        executable=runtime,
        guard_home=guard_home,
        environment=environment(guard_home),
        payload=payload,
        timeout_seconds=5.0,
        raw_hook_envelope=True,
    )
    assert raw is not None, "production native client did not return a bound response"
    value = json.loads(raw)
    assert isinstance(value, dict)
    assert value["schema"] == "guard-hook-edge-result.v2"
    assert value["authority"] == "rust"
    result = value["result"]
    assert isinstance(result, dict) and result["minimum_action"] == "allow"
    return value
