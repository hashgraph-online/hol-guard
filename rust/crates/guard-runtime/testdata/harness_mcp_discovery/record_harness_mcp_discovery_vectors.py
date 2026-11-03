#!/usr/bin/env python3
"""Record `harness_mcp_discovery` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still groups, labels and matches configured stdio
MCP servers in Python (the base of the commit that introduced the native
`harness_mcp_discovery` runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output harness_mcp_discovery_vectors.json>

`group` cases feed fixed servers through `_stdio_servers`, with the harness
read and the display label stubbed per server, and pin the servers it kept by
the request index that created each group. `match` cases pin the index
`discovered_server_for_observation` picked. Server identities are synthetic, so
no native runtime is needed. All values are fake.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import harness_mcp_discovery as discovery
from codex_plugin_scanner.guard.adapters.contracts import display_name_for
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity

REDACTION_ARGS = [
    ["--token", "fake-token-value"],
    ["--api-key=fake-key"],
    ["--API_KEY", "fake-key"],
    ["--password", "fake-pass", "--port", "8080"],
    ["--my-token", "fake"],
    ["--client_secret=fake"],
    ["https://mcp.example.test/sse?apikey=fake-key"],
    ["Authorization=Bearer fake"],
    ["--no-token", "next-is-hidden"],
    ["--token"],
    ["TOKEN=1"],
    ["x=apikey=y"],
    ["--auth", "fake"],
    ["bearer", "fake"],
    ["secret=1"],
    ["--secretive=1"],
    ["mysecret=1"],
    ["  --token  ", "shown"],
    ["--api_key", "fake"],
    ["-token", "fake"],
    ["--DB-Password", "fake"],
    ["--x-secret=fake", "--apikey"],
    ["API-KEY=fake", "--Authorization", "fake"],
    ["--passwd=", "--bearer=fake"],
    ["--ΩMEGA-token", "fake"],
    ["it's", "a b", "", 'say "hi"', "tab\there", "ünïcode", "C:\\Program Files\\x\\"],
    ["--token", "--token", "visible"],
]
BLANKS = [("blank", "", []), ("spaces", "   ", ["x"]), ("tab", "\t\x1c", []), ("kept", "uvx", ["fake-mcp"])]


def _identity(command: str, args_hash: str, package: str | None, seed: str) -> McpServerIdentity:
    return McpServerIdentity(
        config_path="",
        command=command,
        args_hash=args_hash,
        package_name=package,
        package_version=None,
        package_source="unknown",
        transport="stdio",
        env_keys=(),
        env_values_hash="0" * 64,
        identity_hash=(seed * 64)[:64],
    )


def _server(harness: str, name: str, command: str, args: list[str], **extra: object) -> dict[str, object]:
    return {
        "harness": harness,
        "name": name,
        "command": command,
        "args": args,
        "source_scope": str(extra.get("scope", "user")),
        "config_path": str(extra.get("config", f"~/.{harness}/mcp.json")),
        "identity_hash": (str(extra.get("seed", "a")) * 64)[:64],
        "package_name": extra.get("package"),
        "server_command": str(extra.get("server_command", command)),
        "args_hash": str(extra.get("args_hash", "b" * 64)),
        "label": extra.get("label"),
    }


def _managed(spec: dict[str, object]) -> ManagedMcpServer:
    package = spec["package_name"]
    identity = _identity(
        str(spec["server_command"]),
        str(spec["args_hash"]),
        package if isinstance(package, str) else None,
        str(spec["identity_hash"]),
    )
    return ManagedMcpServer(
        harness=str(spec["harness"]),
        name=str(spec["name"]),
        source_scope=str(spec["source_scope"]),
        config_path=str(spec["config_path"]),
        command=str(spec["command"]),
        args=tuple(str(arg) for arg in spec["args"]),  # type: ignore[union-attr]
        transport="stdio",
        env={},
        enabled=True,
        identity=identity,
    )


Case = tuple[str, list[dict[str, object]], bool, int]


def _group_cases() -> list[Case]:
    same = {"seed": "c", "config": "~/.cursor/mcp.json"}
    dup_labels = ["Cursor", "Claude Code", "Cursor", " ", "Codex", "Gemini"]
    codex = "~/.codex/config.toml"
    names = [
        ("  spaced name  ", "node", None),
        ("   ", "npx @fake/pkg", "@fake/pkg"),
        ("", "/usr/local/bin/my-server", ""),
        ("", "./", None),
        ("", "/", None),
        ("", "..", None),
        ("", "tools/./bin/", None),
        ("", "  spaced cmd  ", None),
        ("\u3000", "a//b", None),
        ("N" * 130, "node", None),
        ("ü" * 121, "node", None),
    ]
    sort = [
        ("gemini", "beta", "node", {}),
        ("claude-code", "Alpha", "node", {}),
        ("claude-code", "alpha", "deno", {}),
        ("claude-code", "alpha", "deno", {"args_hash": "a" * 64}),
        ("cursor", "zeta", "node", {"label": "cursor"}),
        ("cursor", "Émile", "node", {}),
        ("codex", "same", "node", {}),
        ("codex", "same", "node", {}),
        ("unknown-harness", "x", "node", {}),
    ]
    redaction = [
        _server("cursor", f"redact-{i:02d}", "node", args, seed=f"{i:02x}") for i, args in enumerate(REDACTION_ARGS)
    ]
    redaction.append(_server("cursor", "redact-command", "TOKEN=fake", ["--secret", "fake"], seed="ff"))
    redaction.append(_server("cursor", "long", "node", [f"--segment-{i}=value-{i}" for i in range(30)], seed="ee"))
    redaction.append(_server("cursor", "long-ü", "nödé", ["ü" * 200], seed="dd"))
    return [
        ("empty", [], False, 100),
        ("one-plain-server", [_server("cursor", "github", "npx", ["-y", "@fake/github-mcp"])], False, 100),
        (
            "duplicates-merge-labels-and-more",
            [_server("cursor", "dup", "node", ["a.js"], label=label, **same) for label in dup_labels],
            False,
            100,
        ),
        (
            "duplicates-three-labels",
            [
                _server("cursor", "dup", "node", ["a.js"], label=label, **same)
                for label in ["Zed", "Alpha", "Zed", "Beta"]
            ],
            False,
            100,
        ),
        (
            "duplicates-first-wins",
            [
                _server("codex", "srv", "node", ["first.js"], seed="d", config=codex),
                _server("codex", "srv", "python3", ["second.py"], seed="d", config=codex),
                _server("codex", "srv", "node", ["third.js"], seed="d", scope="project"),
            ],
            False,
            100,
        ),
        (
            "blank-commands-are-skipped",
            [_server("cursor", name, command, args) for name, command, args in BLANKS],
            False,
            100,
        ),
        (
            "name-fallbacks",
            [_server("cursor", n, *_split(c), package=p, seed="123456789ef"[i]) for i, (n, c, p) in enumerate(names)],
            False,
            100,
        ),
        (
            "sort-by-label-name-command-args",
            [_server(h, n, c, [], seed=str(i + 1), **x) for i, (h, n, c, x) in enumerate(sort)],
            False,
            100,
        ),
        (
            "limit-truncates-after-sort",
            [_server("cursor", f"server-{i:03d}", "node", [f"s{i}.js"], seed=f"{i:x}") for i in range(7)],
            False,
            4,
        ),
        ("redaction-and-quoting-posix", redaction, False, 100),
        ("redaction-and-quoting-windows", redaction, True, 100),
        (
            "connection-hash-escapes-non-ascii",
            [
                _server("cursor", "sérvér ✓", "node", [], config="~/.cursör/mcp ✓.json", scope="workspace"),
                _server("cursor", 'quote " back \\ slash', "node", [], seed="9", config="~/x\ny.json"),
            ],
            False,
            100,
        ),
    ]


def _split(launch: str) -> tuple[str, list[str]]:
    if launch == "npx @fake/pkg":
        return "npx", ["@fake/pkg"]
    return launch, []


def _label(spec: dict[str, object]) -> str:
    label = spec["label"]
    if isinstance(label, str):
        return label
    return display_name_for(str(spec["harness"]))


def _record_group(name: str, specs: list[dict[str, object]], windows: bool, limit: int) -> dict[str, object]:
    servers = [_managed(spec) for spec in specs]
    entries = [{**spec, "label": _label(spec)} for spec in specs]
    labels = iter([str(entry["label"]) for entry in entries if str(entry["command"]).strip()])
    discovery.observable_stdio_servers_with_proxy = lambda _detection: tuple(servers)  # type: ignore[assignment]
    discovery.display_name_for = lambda _harness: next(labels)  # type: ignore[assignment]
    host = "posix"
    if windows:
        host = "nt"
    discovery.os = SimpleNamespace(name=host)  # type: ignore[assignment]
    discovery.MAX_DISCOVERED_MCP_SERVERS = limit  # type: ignore[attr-defined]
    found = discovery._stdio_servers([SimpleNamespace(harness="all")])  # type: ignore[list-item]
    first: dict[str, int] = {}
    for index, server in enumerate(servers):
        built = discovery._identity_for(server)
        if built is not None:
            first.setdefault(built[0].identity_hash, index)
    expect = [
        {
            "index": first[item.identity.identity_hash],
            "cli_id": item.identity.cli_id,
            "name": item.identity.name,
            "identity_hash": item.identity.identity_hash,
            "configuration_hash": item.connection_identity.configuration_hash,  # type: ignore[union-attr]
            "example_label": item.identity.example_label,
            "launch_command": item.launch_command,
            "source_label": item.source_label,
        }
        for item in found
    ]
    request = {"op": "group", "windows": windows, "limit": limit, "servers": entries}
    return {"name": name, "request": request, "expect": {"servers": expect}}


def _discovered(
    cli_id: str, seed: str, command: str, args_hash: str, label: str
) -> discovery.DiscoveredHarnessMcpServer:
    identity = UnlistedCliIdentity(cli_id, "srv", "executable", "1" * 64, "srv")
    return discovery.DiscoveredHarnessMcpServer(
        identity=identity,
        server_identity=_identity(command, args_hash, None, seed),
        source_label=label,
        launch_command=command,
    )


def _launch(cli_id: str, server_hash: str, command: str, args_hash: str, label: str | None) -> dict[str, str | None]:
    query = {"cli_id": cli_id, "server_identity_hash": server_hash, "server_command": command, "args_hash": args_hash}
    return {**query, "source_label": label}


def _match_cases() -> list[dict[str, object]]:
    legacy = "local-cli.mcp-" + "a" * 8
    servers = [
        _discovered("local-cli.mcp-one", "a", "node", "h1", "Cursor"),
        _discovered("local-cli.mcp-two", "b", "npx", "h2", "Codex"),
        _discovered("local-cli.mcp-two", "c", "npx", "h3", "Codex"),
        _discovered("local-cli.mcp-three", "a", "node", "h1", "Claude Code"),
        _discovered("local-cli.mcp-four", "d", "uvx", "h4", "Gemini"),
        _discovered("local-cli.mcp-five", "d", "uvx", "h4", "Gemini"),
        _discovered("local-cli.mcp-ü", "é", "nödé", "hé", "Ünïcode"),
    ]
    a64, b64, d64, e64 = ("a" * 64, "b" * 64, "d" * 64, "é" * 64)
    queries: list[tuple[str, dict[str, str | None]]] = [
        ("cli-id-unique", {"cli_id": "local-cli.mcp-one"}),
        ("cli-id-with-matching-hash", {"cli_id": "local-cli.mcp-one", "server_identity_hash": a64}),
        ("cli-id-with-other-hash", {"cli_id": "local-cli.mcp-one", "server_identity_hash": b64}),
        ("cli-id-ambiguous", {"cli_id": "local-cli.mcp-two"}),
        ("cli-id-ambiguous-narrowed-by-hash", {"cli_id": "local-cli.mcp-two", "server_identity_hash": "c" * 64}),
        ("cli-id-unknown", {"cli_id": "local-cli.mcp-none"}),
        ("legacy-id-falls-back-to-launch", _launch(legacy, a64, "node", "h1", "Cursor")),
        ("legacy-id-without-label", _launch(legacy, a64, "node", "h1", None)),
        ("legacy-id-other-label", _launch(legacy, a64, "node", "h1", "Codex")),
        ("non-legacy-id-does-not-fall-back", _launch("local-cli.mcp-x", a64, "node", "h1", "Cursor")),
        ("legacy-id-ambiguous-launch", _launch("local-cli.mcp-" + "d" * 8, d64, "uvx", "h4", "Gemini")),
        ("legacy-id-unicode-prefix", _launch("local-cli.mcp-" + "é" * 8, e64, "nödé", "hé", "Ünïcode")),
        ("legacy-id-short-hash", _launch("local-cli.mcp-ab", "ab", "node", "h1", "Cursor")),
        ("hash-only-unique", {"server_identity_hash": "b" * 64}),
        ("hash-only-ambiguous", {"server_identity_hash": a64}),
        ("empty-cli-id-is-absent", {"cli_id": "", "server_identity_hash": "c" * 64}),
        ("launch-unique", {"server_command": "npx", "args_hash": "h3"}),
        ("launch-ambiguous", {"server_command": "node", "args_hash": "h1"}),
        ("launch-without-args-hash", {"server_command": "npx"}),
        ("launch-empty-command", {"server_command": "", "args_hash": "h3"}),
        ("nothing", {}),
        ("label-alone-is-nothing", {"source_label": "Cursor"}),
    ]
    cases: list[dict[str, object]] = []
    keys = ("cli_id", "server_command", "args_hash", "server_identity_hash", "source_label")
    wire = [
        {
            "cli_id": server.identity.cli_id,
            "identity_hash": server.server_identity.identity_hash,
            "command": server.server_identity.command,
            "args_hash": server.server_identity.args_hash,
            "source_label": server.source_label,
        }
        for server in servers
    ]
    for name, query in queries:
        full = {key: query.get(key) for key in keys}
        picked = discovery.discovered_server_for_observation(servers, **full)  # type: ignore[arg-type]
        index = None
        for position, server in enumerate(servers):
            if picked is server:
                index = position
        request = {"op": "match", "servers": wire, "query": full}
        cases.append({"name": f"match-{name}", "request": request, "expect": {"index": index}})
    return cases


def main(output: Path) -> None:
    cases = [_record_group(*case) for case in _group_cases()]
    cases.extend(_match_cases())
    document = {"schema": "guard-harness-mcp-discovery-vectors.v1", "cases": cases}
    output.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
