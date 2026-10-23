"""The resident owns the contributed MCP decision; Python only presents it."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import load_mcp_contribution_payloads, mcp_tool_state
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.temporary_mcp_approvals import temporary_mcp_grant_selector

from . import mcp_extension_driver as extension_driver
from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_case_batches import package_case_batches
from .mcp_recorded_expectations import expected_decision, recorded
from .test_guard_mcp_server_grants import _artifact, _AuthorityStore, _layer
from .test_guard_temporary_mcp_approvals import _artifact as _browser_click_artifact
from .test_guard_temporary_mcp_approvals import _evaluate

_ACTIONS = ("allow", "warn", "review", "require-reapproval", "block")
_LOCKDOWN_REASON = "This MCP tool is blocked by its authenticated extension authority."
_MCP_SOURCES = Path(__file__).resolve().parents[1] / "contributions" / "mcp-servers"


def _cases_from(payloads) -> list[tuple[str, str, str, str, str]]:
    cases: list[tuple[str, str, str, str, str]] = []
    for payload in payloads:
        launch = payload["launch"]
        if launch["kind"] != "package-launcher":
            continue
        tools = [tool["name"] for tool in payload["tools"][:3]] + ["unlisted_tool"]
        for tool in tools:
            cases.append((payload["id"], launch["command"], launch["package"], tool, mcp_tool_state(payload, tool)))
    return cases


def _package_cases(root: Path | None = None) -> list[tuple[str, str, str, str, str]]:
    return _cases_from(load_mcp_contribution_payloads(root))


# Collection precedes the fixtures that route authenticated native metadata, and
# validating a contribution asks the resident for its URL grammar. Parametrize
# from the source files as written; every test compares these cases with the
# resident-validated load, so a contribution validation would change still fails.
_SOURCE_PACKAGE_CASES = _cases_from(
    json.loads(path.read_text(encoding="utf-8")) for path in sorted(_MCP_SOURCES.glob("mcp.*.json"))
)


@pytest.fixture(scope="module")
def native_package_cases():
    """Defer the per-worker inventory load until function fixtures route native calls."""
    return cache(_package_cases)


def _identity(command: str, package: str):
    args = ("-y", package) if command == "npx" else (package,)
    return build_mcp_server_identity(config_path="", command=command, args=args, transport="stdio")


def test_recorded_expectations_cover_every_state_lockdown_and_action(native_package_cases) -> None:
    rows = {(row["state"], row["lockdown"], row["action"]) for row in recorded()["decision_table"]}
    assert rows == {
        (state, lockdown, action)
        for state in ("allow", "review", "block", "inherit")
        for lockdown in (False, True)
        for action in _ACTIONS
    }
    native_cases = native_package_cases()
    assert {state for *_rest, state in native_cases} <= {"allow", "review", "block", "inherit"}
    assert sorted(native_cases) == sorted(_SOURCE_PACKAGE_CASES)


@pytest.mark.parametrize("lockdown", [False, True])
@pytest.mark.parametrize(
    "case_batch", package_case_batches(_SOURCE_PACKAGE_CASES), ids=lambda cases: cases[0][0] + "-" + cases[0][3]
)
def test_resident_matches_the_recorded_expectations_for_every_bundled_package(
    lockdown: bool, case_batch: list[tuple[str, str, str, str, str]], native_package_cases
) -> None:
    selected = set(case_batch)
    native_batch = [case for case in native_package_cases() if case in selected]
    assert sorted(native_batch) == sorted(case_batch)
    mismatches: list[str] = []
    for mcp_id, command, package, tool, state in native_batch:
        catalog_id = "command." + mcp_id.replace(".", "-")
        layer = _layer(ControlLayerKind.LOCAL_ADMIN, catalog_id, ControlState.ENABLED, lockdown=lockdown)
        store = _AuthorityStore((layer,))
        artifact = _artifact(_identity(command, package), tool)
        for action in _ACTIONS:
            if lockdown:
                # The resident enforces the authenticated global lockdown before any
                # per-tool state: every call is blocked unless the request already is.
                expected = None if action == "block" else ("block", recorded()["source"], _LOCKDOWN_REASON)
            else:
                expected = expected_decision(state, lockdown, action)
            actual = extension_driver.apply_contributed_mcp_decision(store, artifact, action)
            if expected != actual:
                mismatches.append(f"{mcp_id} {tool} {action}: {expected} != {actual}")
    assert not mismatches, mismatches[:5]


def test_recorded_matching_cases_pin_the_endpoint_identity_assertions() -> None:
    """Endpoint and runtime-identity matching is enforced by the Rust test over these rows."""
    by_name = {case["name"]: case["matches"] for case in recorded()["matching_cases"]}
    pinned = {
        "dot-segment route matches canonical": True,
        "trailing slash does not cross-match (launch without slash)": False,
        "trailing slash matches itself": True,
        "percent-encoded equivalent route matches": True,
        "ipv4-mapped ipv6 identity matches native ipv4 launch": True,
        "expanded ipv6 identity matches compressed launch": True,
        "server name matches without runtime endpoint identity": True,
        "different remote endpoint does not match": False,
        "unresolved endpoint does not fall back to server name": False,
        "direct command without server identity does not match": False,
        "direct command without tool identity does not match": False,
    }
    assert {name: by_name.get(name) for name in pinned} == pinned
    direct = [value for name, value in by_name.items() if name.startswith("direct command ")]
    assert direct.count(True) == 24 and direct.count(False) == 8


def test_inactive_extension_decides_nothing_natively() -> None:
    artifact = _artifact(_identity("npx", "@modelcontextprotocol/server-filesystem"), "write_file")
    assert extension_driver.apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None


def _store_with_saved_server_allow(tmp_path: Path) -> tuple[GuardStore, GuardArtifact]:
    """A routine browser click whose server holds a saved approval-gate allow."""
    artifact = _browser_click_artifact(tool_name="click")
    identity = artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    store = GuardStore(tmp_path / "guard-home")
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(str(identity["identity_hash"])),
            source="approval-gate",
            expires_at=(now + timedelta(hours=5)).isoformat(),
        ),
        now.isoformat(),
    )
    return store, artifact


def test_saved_approval_gate_allow_lifts_a_review_when_the_catalog_is_answered(tmp_path: Path) -> None:
    store, artifact = _store_with_saved_server_allow(tmp_path)
    lifted = _evaluate(tmp_path, store, artifact, {"uid": "button-1"})
    assert (lifted.action, lifted.source) == ("allow", "temporary-mcp-grant")
