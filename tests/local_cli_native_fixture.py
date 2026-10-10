"""Run local CLI and MCP grant and contributed MCP decisions through a keyed compiled resident.

The grant decision is native-authoritative: the resident reads ``guard.db``
and answers, and refuses to serve a home that holds no policy verifier key.
Tests that build a real ``GuardStore`` under a temp home enrol that home's own
verifier key before each native call, then close the resident on teardown.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from .native_runtime_fixtures import _resolve_native_hook_runtime

_TEST_GUARD_HOME: list[Path] = []
_SCRATCH_GUARD_HOME = Path(tempfile.mkdtemp(prefix="native-guard-home-"))


def native_test_guard_home() -> Path:
    """The per-test Guard home that synthetic stores hand the native resident.

    A fresh home per test keeps each resident's restart budget independent.
    Tests that never reach the resident (the Python oracle) share one scratch home.
    """

    return _TEST_GUARD_HOME[0] if _TEST_GUARD_HOME else _SCRATCH_GUARD_HOME


@pytest.fixture(autouse=True)
def native_local_cli_grant_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    from codex_plugin_scanner.guard import local_cli_grant_decision, local_mcp_grant_decision
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
        provision_native_verifier_key_for_store,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime import mcp_server_grants
    from codex_plugin_scanner.guard.store import GuardStore

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(_resolve_native_hook_runtime()))
    homes: set[Path] = set()
    _TEST_GUARD_HOME[:] = [tmp_path / "native-guard-home"]

    def keyed(native: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a native grant call so its home holds a verifier key first."""

        def call(*, guard_home: Path, **kwargs: Any) -> Any:
            if guard_home not in homes:
                provision_native_verifier_key_for_store(GuardStore(guard_home))
                homes.add(guard_home)
            return native(guard_home=guard_home, **kwargs)

        return call

    monkeypatch.setattr(
        local_cli_grant_decision, "native_local_cli_grant", keyed(local_cli_grant_decision.native_local_cli_grant)
    )
    monkeypatch.setattr(
        local_mcp_grant_decision, "native_local_mcp_grant", keyed(local_mcp_grant_decision.native_local_mcp_grant)
    )
    monkeypatch.setattr(
        mcp_server_grants,
        "native_contributed_mcp_decision",
        keyed(mcp_server_grants.native_contributed_mcp_decision),
    )
    yield
    for home in homes:
        close_native_residents(home)
    _TEST_GUARD_HOME.clear()
