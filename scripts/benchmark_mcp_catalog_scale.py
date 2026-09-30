"""Measure Guard catalog scale with disposable data and a mocked native ACK.

Run with ``uv run --no-sync python scripts/benchmark_mcp_catalog_scale.py [connections]``.
Each connection advertises 100 tools. No installed Guard state is read or written.
"""

import math
import platform
import statistics
import sys
import tempfile
import time
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
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.native_policy_snapshot_test_fixtures import _ack, _status


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[math.ceil(len(ordered) * 0.95) - 1]


with tempfile.TemporaryDirectory(prefix="guard-mcp-scale-") as scratch:
    root = Path(scratch)
    store = GuardStore(root / "guard-home")
    connection_count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    assert 1 <= connection_count <= 100
    names = tuple(f"tool_{index:03}" for index in range(100))
    commands = (
        *(LocalCliCommand(name, name, name, "Fixture tool") for name in names),
        LocalCliCommand("other", "Other tools", "fixture ...", "Unknown tools need review"),
    )
    catalog = McpCatalogResult(
        tuple({"name": name, "inputSchema": {"type": "object"}} for name in names),
        complete=True,
        pages=1,
        protocol_version="2026-07-28",
    )
    seen_at = utc_now()
    servers = []
    setup_start = time.perf_counter()
    for index in range(connection_count):
        server = build_mcp_server_identity(
            config_path="", command="npx", args=("-y", f"@fixture/server-{index:03}"), transport="stdio"
        )
        identity = UnlistedCliIdentity(
            cli_id=f"local-cli.scale-{index:03}",
            name=f"Fixture connector {index:03}",
            kind="executable",
            identity_hash=server.identity_hash,
            example_label=f"fixture-{index:03}",
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
            command_states={name: "allow" if tool_index % 2 == 0 else "block" for tool_index, name in enumerate(names)},
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

    store._policy_integrity_secret_material = lambda *, create: (b"m" * 32, "fixture")
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kwargs: _ack(kwargs["payload"])
    )
    try:
        started = time.perf_counter()
        publisher._publish_once()
        publish_ms = (time.perf_counter() - started) * 1000
        assert publisher.is_ready()
    finally:
        publisher.close()

    config = GuardConfig(guard_home=store.guard_home, workspace=root / "workspace", mode="prompt")
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="server-000",
        tool_name="tool_000",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=servers[0],
        tool_definition={"name": "tool_000", "inputSchema": {"type": "object"}},
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
            "setup_s": round(setup_seconds, 3),
            "api_list_median_ms": round(statistics.median(list_times), 2),
            "api_list_p95_ms": round(p95(list_times), 2),
            "publish_ms": round(publish_ms, 2),
            "decision_median_ms": round(statistics.median(decision_times), 3),
            "decision_p95_ms": round(p95(decision_times), 3),
        }
    )
