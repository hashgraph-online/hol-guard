"""Answer containment routing from the compiled resident in tests that patch the host.

Many routing tests patch ``sys.platform`` to replay another host's sink, and
point ``guard_home`` at a scratch directory with no enrolled resident. This
fixture keeps the routing answer the resident's own: it asks the session's
resident, on the real platform, with the host the test chose. Only the host
fact and the home are redirected; the routing table is never re-implemented.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeVar

import pytest

from codex_plugin_scanner.guard import native_hook_containment_route as route_module

_T = TypeVar("_T")
_SINK_USERS = (
    "codex_plugin_scanner.guard.adapters.zcode_contained_tests",
    "codex_plugin_scanner.guard.adapters.codex_contained_tests",
    "codex_plugin_scanner.guard.daemon.hook_contained_grant",
)
# Both hook paths take the route through ``edge_containment_route``, which
# asks ``native_containment_route`` when an edge carries no stamped route.
_ROUTE_USERS = ("codex_plugin_scanner.guard.native_hook_containment_route",)


@pytest.fixture
def containment_resident(monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path) -> Path:
    """Route every containment question through the session resident; returns its home."""

    home = native_approval_reuse_runtime
    real_platform = sys.platform
    real_sink = route_module.native_containment_sink
    real_route = route_module.native_containment_route

    def on_real_host(call: Callable[[], _T]) -> _T:
        # The host the test chose, asked from the platform the resident runs on.
        host = route_module.host_platform()
        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", real_platform)
            patch.setattr(route_module, "host_platform", lambda: host)
            return call()

    def sink(
        response: Mapping[str, object],
        *,
        harness: str,
        bridge: bool,
        payload: Mapping[str, object],
        guard_home: Path | None,
        deadline: float | None = None,
    ) -> route_module.ContainmentSink:
        del guard_home, deadline
        return on_real_host(
            lambda: real_sink(response, harness=harness, bridge=bridge, payload=payload, guard_home=home)
        )

    def route(
        result: Mapping[str, object],
        *,
        event_name: object,
        recording_only: bool,
        guard_home: Path | None,
        deadline: float | None = None,
    ) -> str:
        del guard_home, deadline
        return on_real_host(
            lambda: real_route(result, event_name=event_name, recording_only=recording_only, guard_home=home)
        )

    for name in _SINK_USERS:
        monkeypatch.setattr(importlib.import_module(name), "native_containment_sink", sink)
    for name in _ROUTE_USERS:
        monkeypatch.setattr(importlib.import_module(name), "native_containment_route", route)
    return home
