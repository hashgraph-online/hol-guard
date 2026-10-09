"""The resident owns the contributed MCP decision; Python only presents it."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.local_cli_trust import _contributed_mcp_decision
from codex_plugin_scanner.guard.native_local_cli_identity import LocalCliIdentityUnavailableError
from codex_plugin_scanner.guard.runtime import mcp_server_grants
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import load_mcp_contribution_payloads

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_grants_python_oracle import oracle_apply_contributed_mcp_decision
from .test_guard_mcp_server_grants import _artifact, _AuthorityStore, _layer

_ACTIONS = ("allow", "warn", "review", "require-reapproval", "block")


def _package_cases() -> list[tuple[str, str, str, str]]:
    cases: list[tuple[str, str, str, str]] = []
    for payload in load_mcp_contribution_payloads():
        launch = payload["launch"]
        if launch["kind"] != "package-launcher":
            continue
        tools = [tool["name"] for tool in payload["tools"][:3]] + ["unlisted_tool"]
        for tool in tools:
            cases.append((payload["id"], launch["command"], launch["package"], tool))
    return cases


def _identity(command: str, package: str):
    args = ("-y", package) if command == "npx" else (package,)
    return build_mcp_server_identity(config_path="", command=command, args=args, transport="stdio")


@pytest.mark.parametrize("lockdown", [False, True])
def test_resident_matches_the_python_reference_for_every_bundled_package(lockdown: bool) -> None:
    mismatches: list[str] = []
    shared_home = _AuthorityStore()  # one resident for the whole matrix
    for mcp_id, command, package, tool in _package_cases():
        catalog_id = "command." + mcp_id.replace(".", "-")
        layer = _layer(ControlLayerKind.LOCAL_ADMIN, catalog_id, ControlState.ENABLED, lockdown=lockdown)
        store = _AuthorityStore((layer,))
        store.guard_home, store.path = shared_home.guard_home, shared_home.path
        artifact = _artifact(_identity(command, package), tool)
        for action in _ACTIONS:
            expected = oracle_apply_contributed_mcp_decision(store, artifact, action)
            actual = mcp_server_grants.apply_contributed_mcp_decision(store, artifact, action)
            if expected != actual:
                mismatches.append(f"{mcp_id} {tool} {action}: {expected} != {actual}")
    assert not mismatches, mismatches[:5]


def test_inactive_extension_decides_nothing_natively() -> None:
    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "write_file")
    assert mcp_server_grants.apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None


@pytest.fixture
def silent_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_server_grants, "native_contributed_mcp_decision", lambda **_kwargs: None)


def test_presenter_fails_closed_without_a_resident_answer(silent_resident: None) -> None:
    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "write_file")
    layer = _layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED)
    with pytest.raises(LocalCliIdentityUnavailableError):
        mcp_server_grants.apply_contributed_mcp_decision(_AuthorityStore((layer,)), artifact, "allow")


@pytest.mark.parametrize("action", ["allow", "warn"])
def test_unanswered_contributed_decision_holds_an_allowed_call(silent_resident: None, action: str) -> None:
    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "read_file")
    held = _contributed_mcp_decision(_AuthorityStore(), artifact, action)  # type: ignore[arg-type]
    assert held is not None
    assert held[0] == "review"
    assert held[1] == "catalog-mcp-extension"


@pytest.mark.parametrize("action", ["review", "require-reapproval", "block"])
def test_unanswered_contributed_decision_never_loosens_a_stricter_call(silent_resident: None, action: str) -> None:
    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "read_file")
    assert _contributed_mcp_decision(_AuthorityStore(), artifact, action) is None  # type: ignore[arg-type]


def test_store_without_a_pinned_home_is_unavailable_not_allowed() -> None:
    class _NoHome:
        def read_extension_control_authority_for_registry(self, registry: object) -> object:
            raise AssertionError("must not be read without a pinned store")

    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "write_file")
    with pytest.raises(LocalCliIdentityUnavailableError):
        mcp_server_grants.apply_contributed_mcp_decision(_NoHome(), artifact, "allow")  # type: ignore[arg-type]
