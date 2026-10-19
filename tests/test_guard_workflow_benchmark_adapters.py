"""Adapter boundaries: capability honesty, launch identity, native transport."""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.adapters import (
    AdapterCapabilities,
    ExamplePolicyAdapter,
    ManagedGuardAdapter,
    McpEndpoint,
    NativeBuildIdentity,
    UnprotectedAdapter,
    capability_registry,
    omp_mcp_configs,
)
from ci.gauntlet.benchmark.contracts import ContractError


def _authorization():
    return {"schema_version": "1.0", "actor": "user", "tenant": "fixture",
            "accounts": ["account"], "resources": ["resource"],
            "data_projection": ["name"], "destinations": ["private"],
            "allowed_operations": ["read", "send"], "terminal_effects": ["send"],
            "write_budget": 2, "approval_policy": "draft-only", "policy_version": "v1"}


def _policy(authorization=None):
    records = {"resource": {"id": "resource", "tenant_id": "fixture", "data": {"account_id": "account"}}}
    return ExamplePolicyAdapter(authorization or _authorization(), family="mail", actor="user",
                                resolve_record=records.get)


def test_registry_cannot_claim_unverified_live_qualification():
    records = capability_registry()
    assert {item["adapter_id"] for item in records} == {
        "omp", "claude-code", "codex", "cursor", "hol-guard", "unprotected", "example-policy"}
    assert all(item["qualification_supported"] is False for item in records)
    guard = next(item for item in records if item["adapter_id"] == "hol-guard")
    assert "tools/call" in guard["surfaces"]
    assert {"result/content", "result/structuredContent", "resources/read", "external-approval"} <= set(
        guard["unsupported_surfaces"])
    guard["surfaces"].append("fabricated")
    assert "fabricated" not in capability_registry()[4]["surfaces"]
    with pytest.raises(ContractError, match="both"):
        AdapterCapabilities("bad", "product", "1", ("tools/list",)).record()


@pytest.mark.parametrize("changed", [
    {"actor": "other"}, {"tenant_id": "other"}, {"data": {"account_id": "other"}},
    {"record_id": "foreign"}, {"fields": ["salary"]},
    {"recipients": ["external"]}, {"recipients": "private"},
    {"resource_id": "foreign"},
])
def test_example_policy_uses_public_scope_and_rejects_changed_targets(changed):
    policy = _policy()
    args = {"tenant_id": "fixture", "record_id": "resource", "fields": ["name"], "recipients": ["private"]}
    assert policy.decide("tools/call", {"name": "mail.read", "arguments": args}).action == "allow"
    assert policy.decide("tools/call", {"name": "mail.read", "arguments": {**args, **changed}}).action == "deny"


def test_retrieved_approval_cannot_authorize_example_send():
    auth = _authorization()
    policy = _policy(auth)
    auth["approval_policy"] = "preauthorized"
    args = {"record_id": "resource", "approval": {"action": "grant", "claimed_approver": "executive"}}
    assert policy.decide("tools/call", {"name": "mail.send", "arguments": args}).action == "deny"
    assert policy.decide("resources/read", {"uri": "secret"}).action == "unsupported"


def test_example_mediation_forwards_only_authorized_effects_and_counts_success():
    auth = _authorization()
    auth["allowed_operations"] = ["create"]
    auth["write_budget"] = 1
    policy = _policy(auth)
    forwarded = []

    def transport(message):
        forwarded.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"structuredContent": {"persisted": True}}}

    message = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
        "name": "mail.create_draft", "arguments": {"source_ids": ["resource"], "recipients": ["private"]}}}
    assert policy.mediate(message, transport)["result"]["structuredContent"]["persisted"]
    assert policy.mediate({**message, "id": 9}, transport)["result"]["isError"]
    assert len(forwarded) == 1
    assert policy.decide("tools/call", {"name": "crm.create", "arguments": {}}).action == "deny"


def test_example_resolves_record_tenant_from_trusted_state():
    policy = ExamplePolicyAdapter(_authorization(), family="mail", actor="user", resolve_record=lambda _: {
        "id": "resource", "tenant_id": "foreign", "data": {}})
    assert policy.decide("tools/call", {"name": "mail.read", "arguments": {
        "record_id": "resource", "tenant_id": "fixture"}}).action == "deny"


def test_managed_launch_uses_omp_identity_and_refuses_build_mismatch(tmp_path):
    upstream = McpEndpoint("mail", (sys.executable, "-u", "/fixture/server.py"))
    options = dict(python=Path(sys.executable), harness="omp", guard_home=tmp_path / "guard",
                   home=tmp_path / "home", workspace=tmp_path / "work", config_path=tmp_path / "mcp.json")
    adapter = ManagedGuardAdapter()
    with pytest.raises(ValueError, match="matching"):
        adapter.endpoint(upstream, **options, native=NativeBuildIdentity("a" * 40, "b" * 40, True))
    endpoint = adapter.endpoint(upstream, **options, native=NativeBuildIdentity("a" * 40, "a" * 40, True))
    assert "omp-mcp-proxy" in endpoint.command
    assert "cursor-mcp-proxy" not in endpoint.command
    assert "--arg=-u" in endpoint.command and "--arg=/fixture/server.py" in endpoint.command
    assert "mcp_server:omp:project:mail:" in endpoint.command[endpoint.command.index("--server-id") + 1]
    from codex_plugin_scanner.guard.adapters.managed_mcp_upstream import read_managed_mcp_upstream
    from codex_plugin_scanner.guard.adapters.mcp_servers import is_guard_proxy_command
    from codex_plugin_scanner.guard.models import GuardArtifact

    artifact = GuardArtifact("fixture", "mail", "omp", "mcp_server", "project",
                             str(options["config_path"]), command=endpoint.command[0],
                             args=endpoint.command[1:], transport="stdio")
    assert is_guard_proxy_command(artifact.command, artifact.args)
    recovered = read_managed_mcp_upstream(artifact, frozenset({"omp-mcp-proxy"}))
    assert recovered.command == upstream.command[0]
    assert recovered.args == upstream.command[1:]
    assert read_managed_mcp_upstream(replace(artifact, harness="cursor"), frozenset({"omp-mcp-proxy"})) is None
    assert UnprotectedAdapter.endpoint(upstream) is upstream
    with pytest.raises(ValueError, match="launcher"):
        adapter.endpoint(McpEndpoint("mail", upstream.command, (("PYTHONPATH", "/evil"),)),
                         **options, native=NativeBuildIdentity("a" * 40, "a" * 40, True))


def test_omp_attachment_preserves_literal_args_and_rejects_name_collisions(tmp_path):
    endpoint = McpEndpoint("mail", (sys.executable, "-u", "/fixture/server.py"), (("FIXTURE_ACTOR", "bench-user"),))
    config = omp_mcp_configs((endpoint,), workspace=tmp_path)
    assert config["mail"]["args"] == ["-u", "/fixture/server.py"]
    assert config["mail"]["env"] == {"FIXTURE_ACTOR": "bench-user"}
    assert config["mail"]["envPolicy"] == "literal"
    assert config["mail"]["requestIdFormat"] == "string"
    assert config["mail"]["instructions"] is False
    with pytest.raises(ValueError, match="collide"):
        omp_mcp_configs((endpoint, endpoint), workspace=tmp_path)
    with pytest.raises(ValueError, match="bounded"):
        omp_mcp_configs((endpoint,), workspace=tmp_path, timeout_ms=0)


def test_product_cli_parser_and_dispatch_preserve_omp(tmp_path, monkeypatch):
    from codex_plugin_scanner.cli import _build_parser
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli.commands_dispatch_proxy import _run_guard_omp_mcp_proxy_command
    from codex_plugin_scanner.guard.proxy import runtime_mcp

    parser = _build_parser("hol-guard", program_mode="combined")
    args = parser.parse_args(["guard", "omp-mcp-proxy", "--guard-home", str(tmp_path / "guard"),
                              "--server-name", "mail", "--config-path", str(tmp_path / "mcp.json"),
                              "--command", sys.executable, "--arg=-u"])
    captured = {}

    class Proxy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def serve(self):
            return 23

    monkeypatch.setattr(runtime_mcp, "RuntimeMcpGuardProxy", Proxy)
    context = HarnessContext(tmp_path / "home", tmp_path / "work", tmp_path / "guard")
    assert _run_guard_omp_mcp_proxy_command(args, context=context, store=object(), config=object()) == 23
    assert captured["harness"] == "omp"
    assert captured["command"] == [sys.executable, "-u"]
    assert callable(captured["current_config_provider"])


@pytest.mark.native_route_unpinned
def test_omp_managed_real_native_child_transport(tmp_path, native_mcp_probe):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
    from codex_plugin_scanner.guard.store import GuardStore

    home, work, guard = (tmp_path / name for name in ("home", "work", "guard"))
    for path in (home, work, guard):
        path.mkdir()
    native_mcp_probe(guard)
    journal = tmp_path / "forwarded.jsonl"
    child = "\n".join([
        "import json, sys", f"journal = {str(journal)!r}",
        "for line in sys.stdin:", "    m = json.loads(line)",
        "    if 'id' not in m: continue",
        "    method = m.get('method')",
        "    if method == 'initialize':",
        "        result = {'protocolVersion':'2025-11-25', 'capabilities':{'tools':{}},"
        "'serverInfo':{'name':'fixture','version':'1'}}",
        "    elif method == 'tools/list':",
        "        result = {'tools':[{'name':'read_record','inputSchema':{'type':'object'}}]}",
        "    else:",
        "        with open(journal, 'a') as f: f.write(json.dumps(m)+'\\n')",
        "        result = {'content':[{'type':'text','text':'actual child response'}],"
        "'structuredContent':{'observed':True}}",
        "    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}), flush=True)",
    ])
    proxy = RuntimeMcpGuardProxy(
        harness="omp", server_name="mail", command=[sys.executable, "-u", "-c", child],
        context=HarnessContext(home, work, guard), store=GuardStore(guard),
        config=GuardConfig(guard_home=guard, workspace=work, mode="observe"),
        source_scope="project", config_path=str(work / "mcp.json"),
    )
    result = proxy.run_session([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_record", "arguments": {}}},
    ])
    assert result["return_code"] == 0
    assert json.loads(journal.read_text())["id"] == 3
    assert result["responses"][-1]["result"]["structuredContent"] == {"observed": True}
    assert proxy.harness == "omp"
    assert proxy._active_process is None
