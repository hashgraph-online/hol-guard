"""Run local CLI and MCP grant and contributed MCP decisions through a keyed compiled resident.

The grant decision is native-authoritative: the resident reads ``guard.db``
and answers, and refuses to serve a home that holds no policy verifier key.
Tests that build a real ``GuardStore`` under a temp home enrol that home's own
verifier key before each native call, then close the resident on teardown.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from .native_runtime_fixtures import _resolve_native_hook_runtime


@pytest.fixture(autouse=True)
def native_local_cli_grant_resident(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from codex_plugin_scanner.guard import local_cli_grant_decision, local_mcp_grant_decision
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
        provision_native_verifier_key_for_store,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime import mcp_server_grants
    from codex_plugin_scanner.guard.store import GuardStore

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(_resolve_native_hook_runtime()))
    real = local_cli_grant_decision.native_local_cli_grant
    homes: set[Path] = set()

    def keyed(*, guard_home: Path, **kwargs):
        if guard_home not in homes:
            provision_native_verifier_key_for_store(GuardStore(guard_home))
            homes.add(guard_home)
        return real(guard_home=guard_home, **kwargs)

    real_mcp = local_mcp_grant_decision.native_local_mcp_grant

    def keyed_mcp(*, guard_home: Path, **kwargs):
        if guard_home not in homes:
            provision_native_verifier_key_for_store(GuardStore(guard_home))
            homes.add(guard_home)
        return real_mcp(guard_home=guard_home, **kwargs)

    real_contributed = mcp_server_grants.native_contributed_mcp_decision

    def keyed_contributed(*, guard_home: Path, **kwargs):
        if guard_home not in homes:
            provision_native_verifier_key_for_store(GuardStore(guard_home))
            homes.add(guard_home)
        return real_contributed(guard_home=guard_home, **kwargs)

    monkeypatch.setattr(mcp_server_grants, "native_contributed_mcp_decision", keyed_contributed)
    monkeypatch.setattr(local_cli_grant_decision, "native_local_cli_grant", keyed)
    monkeypatch.setattr(local_mcp_grant_decision, "native_local_mcp_grant", keyed_mcp)
    yield
    for home in homes:
        close_native_residents(home)
