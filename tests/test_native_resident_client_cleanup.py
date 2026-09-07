from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard.native_resident_client import _PersistentNativeClientPool


def test_close_native_resident_clients_attempts_all_selected_pools_before_raising(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    guard_home = tmp_path / "guard-home"
    state_dir = guard_home / "native-runtime"
    first_pool = client_module._client_pool_for(tmp_path / "runtime-a", state_dir, {})
    second_pool = client_module._client_pool_for(tmp_path / "runtime-b", state_dir, {})
    closed: list[_PersistentNativeClientPool] = []

    def close_pool(pool: _PersistentNativeClientPool) -> None:
        closed.append(pool)
        if pool is first_pool:
            raise RuntimeError("first close failed")

    monkeypatch.setattr(_PersistentNativeClientPool, "close", close_pool)

    with pytest.raises(RuntimeError, match="first close failed"):
        client_module.close_native_resident_clients(guard_home)

    assert closed == [first_pool, second_pool]
    assert not any(Path(key[1]).parent == guard_home.resolve() for key in client_module._CLIENT_POOLS)
