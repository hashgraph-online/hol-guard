"""Measure rich catalogs and bounded permission publication with disposable data.

Run with ``uv run --no-sync python scripts/benchmark_mcp_catalog_scale.py [connections]``.
Each connection advertises 100 tools; ten have explicit choices by default.
Pass --native with explicit built runtime/compiler paths to verify a real ACK.
No installed Guard state is read or written.
"""

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[math.ceil(len(ordered) * 0.95) - 1]


@contextmanager
def isolated_environment(root: Path):
    names = ("HOME", "CODEX_HOME", "HOL_GUARD_HOME", "HOL_GUARD_NATIVE")
    previous = {name: os.environ.get(name) for name in names}
    home = root / "home"
    home.mkdir()
    os.environ.update(HOME=str(home), CODEX_HOME=str(root / "codex"), HOL_GUARD_HOME=str(root / "guard-home"))
    if options.native:
        os.environ["HOL_GUARD_NATIVE"] = "force"
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("connections", type=int, nargs="?", default=100)
parser.add_argument("--permissions-per-connection", type=int, default=10)
parser.add_argument("--native", action="store_true")
options = parser.parse_args()
assert 1 <= options.connections <= 100
assert 1 <= options.permissions_per_connection <= 100
if options.connections * options.permissions_per_connection > POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS:
    parser.error(
        f"Selected permissions exceed the native publication limit ({POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS}); "
        "reduce --permissions-per-connection. Each rich catalog still contains 100 tools."
    )
if options.native and not all(
    os.environ.get(name) for name in ("HOL_GUARD_NATIVE_BINARY", "HOL_GUARD_NATIVE_SOURCE_COMPILER")
):
    parser.error("--native requires explicit HOL_GUARD_NATIVE_BINARY and HOL_GUARD_NATIVE_SOURCE_COMPILER paths")


with tempfile.TemporaryDirectory(prefix="guard-mcp-scale-") as scratch, isolated_environment(Path(scratch)):
    root = Path(scratch)
    store = GuardStore(root / "guard-home", prime_policy_integrity=False)
    store._policy_integrity_secret_material = lambda *, create: (b"m" * 32, "fixture")
    connection_count = options.connections
    names = tuple(f"tool_{index:03}" for index in range(100))
    seen_at = utc_now()
    servers = []
    setup_start = time.perf_counter()
    for index in range(connection_count):
        observed = [observed_mcp_tool("codex", f"mcp__fixture_{index:03}__{name}") for name in names]
        assert all(tool is not None for tool in observed)
        tools = [tool for tool in observed if tool is not None]
        server, identity = tools[0].server_identity, tools[0].identity
        commands = (
            *(LocalCliCommand(tool.command_id, tool.name, tool.qualified_name, "Fixture tool") for tool in tools),
            LocalCliCommand("other", "Other tools", "fixture ...", "Unknown tools need review"),
        )
        catalog = McpCatalogResult(
            tuple({"name": tool.qualified_name, "inputSchema": {"type": "object"}} for tool in tools),
            complete=True,
            pages=1,
            protocol_version="2026-07-28",
        )
        servers.append(server)
        store.record_local_cli_observation(
            identity,
            seen_at=seen_at,
            surface="mcp",
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            help_status="ok",
        )
        store.replace_local_cli_commands(
            identity.cli_id,
            commands,
            mcp_catalog=catalog,
            identity_hash=identity.identity_hash,
            seen_at=seen_at,
        )
        store.upsert_local_cli_grant(
            identity=identity,
            state="allowed",
            expected_revision=store.read_local_cli_revision(),
            updated_at=seen_at,
            command_states={
                tool.command_id: "allow" if tool_index % 2 == 0 else "block"
                for tool_index, tool in enumerate(tools[: options.permissions_per_connection])
            },
        )
    setup_seconds = time.perf_counter() - setup_start

    list_times: list[float] = []
    api = LocalCliApiService(store=store)
    items: list[dict[str, object]] = []
    for _ in range(30):
        started = time.perf_counter()
        items = cast(list[dict[str, object]], api.list_items()["items"])
        list_times.append((time.perf_counter() - started) * 1000)
    assert len(items) == connection_count
    known_count = 0
    for item in items:
        summary = item.get("mcp_catalog")
        assert isinstance(summary, dict)
        count = summary.get("known_count")
        assert isinstance(count, int)
        known_count += count
    assert known_count == connection_count * 100

    provision_native_verifier_key_for_store(store)
    if options.native:
        publisher = NativePolicySnapshotPublisher(store=store)
    else:
        from tests.native_policy_snapshot_test_fixtures import _ack, _status

        publisher = NativePolicySnapshotPublisher(
            store=store, status_provider=_status, client_request=lambda **kwargs: _ack(kwargs["payload"])
        )
    try:
        started = time.perf_counter()
        publisher._publish_once()
        publish_ms = (time.perf_counter() - started) * 1000
        assert publisher.is_ready(), publisher.last_error
        snapshot = publisher._snapshot
        assert snapshot is not None
        snapshot_bytes = len(json.dumps(snapshot, separators=(",", ":")).encode())
        assert snapshot_bytes <= POLICY_SNAPSHOT_MAX_BYTES
        actions = snapshot["effective_policy"]["mcp_tool_actions"]
        assert len(actions) == connection_count * options.permissions_per_connection
        expected_blocks = connection_count * (options.permissions_per_connection // 2)
        expected_allows = connection_count * ((options.permissions_per_connection + 1) // 2)
        assert sum(action == "block" for action in actions.values()) == expected_blocks
        assert sum(action == "allow" for action in actions.values()) == expected_allows
    finally:
        publisher.close()
        if options.native:
            assert close_native_residents(store.guard_home), "Owned native runtime did not stop"

    config = GuardConfig(guard_home=store.guard_home, workspace=root / "workspace", mode="prompt")
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="fixture_000",
        tool_name="mcp__fixture_000__tool_000",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=servers[0],
        tool_definition={"name": "mcp__fixture_000__tool_000", "inputSchema": {"type": "object"}},
    )
    arguments = {}
    artifact_hash = build_tool_call_hash(artifact, arguments, workspace=root, config=config)
    decision_times: list[float] = []
    decision = None
    for _ in range(300):
        started = time.perf_counter()
        decision = evaluate_tool_call(
            store=store,
            config=config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
            claim_saved_approval=False,
        )
        decision_times.append((time.perf_counter() - started) * 1000)
    assert decision is not None and decision.action == "allow"
    print(
        {
            "machine": platform.machine(),
            "connections": len(items),
            "tools": connection_count * 100,
            "native_ack": "real" if options.native else "mocked",
            "native_permission_entries": len(actions),
            "native_permission_limit": POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS,
            "native_snapshot_bytes": snapshot_bytes,
            "setup_s": round(setup_seconds, 3),
            "api_list_median_ms": round(statistics.median(list_times), 2),
            "api_list_p95_ms": round(p95(list_times), 2),
            "publish_ms": round(publish_ms, 2),
            "decision_median_ms": round(statistics.median(decision_times), 3),
            "decision_p95_ms": round(p95(decision_times), 3),
        }
    )
