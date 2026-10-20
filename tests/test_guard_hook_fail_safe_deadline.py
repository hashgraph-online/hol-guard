"""A failed hook must not spend its expired budget resolving paths."""

from __future__ import annotations

import time
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import server as module


def test_expired_hook_deadline_skips_optional_fail_safe_path_rpc() -> None:
    calls: list[object] = []
    handler = SimpleNamespace(
        _optional_string=lambda value: value if isinstance(value, str) else None,
        _settled_hook_directories=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    result = module._GuardDaemonHandler._validated_fail_safe_hook_paths(
        handler,
        {"workspace": ["/tmp/project"]},
        hook_deadline=time.monotonic() - 1,
    )
    assert result == (None, None)
    assert not calls
