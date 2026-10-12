#!/usr/bin/env python3
"""Record the original CLI support outcomes before native retirement."""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from types import ModuleType
from typing import cast
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
SOURCE_REF = "d75f7f7c590536b3116bd03643033e19ca4117f9"


def pinned_source(path: str) -> str:
    return subprocess.check_output(["git", "show", f"{SOURCE_REF}:{path}"], cwd=ROOT, text=True)


def compile_nodes(source: str, names: set[str], bindings: dict) -> ModuleType:
    nodes = [
        node
        for node in ast.parse(source).body
        if (isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names)
        or (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names)
    ]
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(module), "pinned-original-cli-support", "exec"), bindings)
    module = ModuleType("original_cli_support")
    vars(module).update(bindings)
    return module


def original_helpers(source: str) -> ModuleType:
    names = {
        "_copilot_runtime_server_command",
        "_copilot_runtime_server_environment",
        "_copilot_runtime_server_transport",
        "_copilot_runtime_server_config_digest",
        "_copilot_runtime_tool_metadata",
        "_copilot_runtime_config_tool_definition",
        "_copilot_runtime_match_priority",
        "_copilot_mcp_tool_token",
        "_copilot_runtime_server_entries",
        "_mcp_server_entries_from_path",
        "_mcp_servers_payload",
        "_resolve_copilot_mcp_runtime_tool",
        "_resolve_copilot_mcp_runtime_server",
        "_resolve_copilot_workspace_root",
    }
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes} != names:
        raise ValueError("original helper source is incomplete")
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes],
        type_ignores=[],
    )
    bindings = {
        "dataclass": dataclass,
        "__name__": "__main__",
        "hashlib": hashlib,
        "json": json,
        "re": re,
        "Path": Path,
        "Mapping": Mapping,
        "cast": cast,
        "_COPILOT_TOOL_METADATA_MISSING": object(),
    }
    nodes.extend(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name in {"_CopilotMcpRuntimeServer", "_CopilotMcpRuntimeTool"}
    )
    nodes.sort(key=lambda node: node.lineno)
    module.body = [module.body[0], *nodes]
    exec(compile(ast.fix_missing_locations(module), "original-cli-runtime-support", "exec"), bindings)
    module = ModuleType("original_cli_support")
    vars(module).update(bindings)
    return module


def main() -> None:
    source = ROOT / "src/codex_plugin_scanner/guard/cli/commands_support_runtime_resolution.py"
    original = pinned_source(source.relative_to(ROOT).as_posix())
    legacy = original_helpers(original)
    configs: list[object] = [
        None,
        {},
        [],
        "invalid",
        {"command": " node ", "args": ["", "--help", 1]},
        {"command": ["", "node", "worker.js", None], "args": ["--stdio"]},
        {"command": "", "args": "ignored"},
        {"env": {"PATH": "bin", "": "ignored", "TOKEN": 1}},
        {"url": "https://example.invalid/mcp"},
        {"transport": " STREAMABLE_HTTP "},
        {"transport": "", "type": "http"},
        {"type": "local"},
        {"type": "custom"},
        {"tools": {"echo": {"inputSchema": {}, "description": " config "}}},
        {"tools": [{"name": "echo", "schema": [1]}, {"name": "other"}]},
        {"command": "\u001cnode\u001f", "env": {"\u001c": "ignored", "PATH": "bin"}},
        {"description": "Ω 東京", "args": [1.25, -0.0, 1e20]},
    ]
    cases: list[dict[str, object]] = []
    for config in configs:
        mapping = config if isinstance(config, dict) else None
        command, args = legacy._copilot_runtime_server_command(mapping)
        environment, keys = legacy._copilot_runtime_server_environment(mapping)
        cases.append(
            {
                "operation": "server_fields",
                "params": {"config": config},
                "expected": {
                    "command": command,
                    "args": list(args),
                    "environment": environment,
                    "env_keys": list(keys),
                    "transport": legacy._copilot_runtime_server_transport(mapping),
                    "config_sha256": legacy._copilot_runtime_server_config_digest(config),
                },
            }
        )
    payloads = [
        {},
        {"tool_schema": None, "schema": {"ignored": True}, "description": " top "},
        {"tool": {"inputSchema": {}, "description": " nested "}},
        {"toolCalls": [{"name": "other", "schema": "ignored"}, {"name": "echo", "args": {}, "schema": []}]},
        {"toolDefinition": {"toolDescription": " definition "}},
    ]
    for config, payload in itertools.product(configs, payloads):
        schema, description = legacy._copilot_runtime_tool_metadata(
            payload,
            server_config=config,
            requested_tool_name="mcp_demo_echo",
            runtime_tool_name="echo",
        )
        cases.append(
            {
                "operation": "tool_metadata",
                "params": {
                    "config": config,
                    "payload": payload,
                    "requested_tool_name": "mcp_demo_echo",
                    "runtime_tool_name": "echo",
                },
                "expected": {"schema": schema, "description": description},
            }
        )
    for config_path, preferred in itertools.product(
        ["workspace/.mcp.json", "workspace/.vscode/mcp.json", "home/.copilot/mcp-config.json", "mcp.json"],
        [None, "cli", "ide", "unknown"],
    ):
        cases.append(
            {
                "operation": "match_priority",
                "params": {"config_path": config_path, "preferred": preferred},
                "expected": legacy._copilot_runtime_match_priority(
                    config_path=config_path, preferred_workspace_config=preferred
                ),
            }
        )
    for value in [" Demo-Server ", "écho", "MCP__server", "", "東京", "SERVER.2", "\u001c Demo \u001f", "ΟΣ"]:
        cases.append(
            {"operation": "tool_token", "params": {"value": value}, "expected": legacy._copilot_mcp_tool_token(value)}
        )
    sources = {source.relative_to(ROOT).as_posix(): hashlib.sha256(original.encode()).hexdigest()}
    url_path = "src/codex_plugin_scanner/guard/runtime/mcp_server_contribution.py"
    url_source = pinned_source(url_path)
    names = {
        "_REMOTE_MCP_URL_MAX_LENGTH",
        "_HEX_DIGITS",
        "_UNRESERVED_PATH_CHARS",
        "_SUB_DELIMITERS",
        "_REMOTE_PATH_CHARS",
        "_REMOTE_QUERY_CHARS",
        "_valid_dns_hostname",
        "_normalized_remote_component",
        "_remove_remote_dot_segments",
        "_normalized_remote_path",
        "_normalized_remote_query",
        "normalized_remote_mcp_url",
    }
    urls = compile_nodes(
        url_source,
        names,
        {"ip_address": ip_address, "IPv6Address": IPv6Address, "urlsplit": urlsplit, "urlunsplit": urlunsplit},
    )
    for value in [
        None,
        12,
        "",
        "https://example.com/mcp?q=a%2Fb",
        "https://EXAMPLE.COM.:443/a/../mcp?x=%7e",
        "https://example.com/",
        "https://localhost/mcp",
        "https://127.0.0.1/mcp",
        "http://example.com/mcp",
        "https://user:pass@example.com/mcp",
        "https://example.com:444/mcp",
        "https://example.com/%00",
        "https://example.com/mcp#fragment",
    ]:
        cases.append(
            {"operation": "remote_url", "params": {"value": value}, "expected": urls.normalized_remote_mcp_url(value)}
        )
    sources[url_path] = hashlib.sha256(url_source.encode()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="cli-support-parity-") as directory:
        root = Path(directory)
        home, workspace = root / "home", root / "workspace"
        for relative in ["workspace/.vscode/mcp.json", "workspace/.mcp.json", "home/.copilot/mcp-config.json"]:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {"command": "node", "args": [relative]},
                            "demo-long": {"url": "https://example.com/mcp"},
                        }
                    }
                )
            )
        for tool, preferred in itertools.product(
            ["mcp_demo_echo", "mcp_demo_long_echo", "demo/echo", "missing/echo", "ordinary", "mcp_"],
            [None, "cli", "ide"],
        ):
            if "/" in tool:
                name, runtime = tool.split("/", 1)
                server = legacy._resolve_copilot_mcp_runtime_server(
                    server_name=name, home_dir=home, workspace=workspace, preferred_workspace_config=preferred
                )
                expected = {"server": asdict(server), "tool_name": runtime} if server else None
            else:
                selected = legacy._resolve_copilot_mcp_runtime_tool(
                    tool_name=tool, home_dir=home, workspace=workspace, preferred_workspace_config=preferred
                )
                expected = {"server": asdict(selected.server), "tool_name": selected.tool_name} if selected else None
            cases.append(
                {
                    "operation": "selection_fixture",
                    "params": {"tool_name": tool, "preferred": preferred},
                    "expected": json.loads(json.dumps(expected).replace(str(root), "<root>")),
                }
            )
    output = {
        "schema": "guard-cli-runtime-support-parity.v1",
        "source": source.relative_to(ROOT).as_posix(),
        "source_ref": SOURCE_REF,
        "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "source_hashes": sources,
        "source_identifiers": {
            path: sorted(
                {node.id for node in ast.walk(ast.parse(pinned_source(path))) if isinstance(node, ast.Name)}
                | {
                    node.name
                    for node in ast.walk(ast.parse(pinned_source(path)))
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                }
            )
            for path in sources
        },
        "cases": cases,
    }
    destination = ROOT / "rust/crates/guard-runtime/tests/fixtures/cli_runtime_support_vectors.json"
    destination.write_text(json.dumps(output, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    print(f"Recorded {len(cases)} original outcomes")


if __name__ == "__main__":
    main()
