"""Kimi fixture cases for `record_adapter_vectors.py`: the `.kimi-code`
`config.toml` hook lists and `mcp.json` servers under the Kimi home and the
workspace. Paths are relative to the fixture root; `<ROOT>` stands for it in
contents.
"""

from __future__ import annotations

from adapter_vector_cases import case, doc, file, link, raw

KH = "home/.kimi-code"
KW = "work/.kimi-code"

HOOKS = """\
hooks = [
  { event = "PreToolUse", command = "a.sh", matcher = "Bash", timeout = 30 },
  { event = 5, command = "b.sh" },
  { event = "Stop", command = "   " },
  { event = "Stop", command = 5 },
  { event = "Stop", command = "c.sh", matcher = "", timeout = 1.5 },
  { event = "X", command = "d.sh", matcher = 3, timeout = true },
  { event = "ÄY", command = "e.sh", timeout = "30" },
  { command = "f.sh", matcher = "m", timeout = 0.0 },
  { event = "", command = "g.sh", timeout = 1979-05-27 },
  { event = "Big", command = "h.sh", timeout = 9223372036854775807 },
  { event = "Neg", command = "i.sh", timeout = -0.0 },
  "not-a-table",
  7,
]
"""

TABLES = """\
[[hooks]]
event = "SessionStart"
command = "s.sh"
matcher = "startup"

[[hooks]]
event = "PostToolUse"
command = " p.sh "
timeout = 10
"""

SERVERS = {
    "local": {"command": "node", "args": ["a", 1, 1.5, True, False, None, 1e20, 1e-5, -0.0, 12345678901234567890123]},
    "remote": {"url": "https://mcp.example/x", "command": 5},
    "both": {"command": "c", "url": "https://both", "transport": "sse"},
    "args_not_list": {"command": "c", "args": "abc"},
    "bare": {},
    "not_dict": "x",
    "list_config": ["y"],
}


def kimi_cases() -> list[dict]:
    return [
        case("nothing"),
        case("no_workspace", [file(f"{KH}/config.toml", HOOKS)], workspace=None),
        case("config_hooks", [file(f"{KH}/config.toml", HOOKS)]),
        case("config_hook_tables", [file(f"{KW}/config.toml", TABLES)]),
        case("hooks_not_list", [file(f"{KH}/config.toml", '[hooks]\nevent = "x"\ncommand = "y"\n')]),
        case("config_empty", [file(f"{KH}/config.toml", "# nothing\n")]),
        case("config_invalid", [file(f"{KH}/config.toml", "[[\n")]),
        case("config_bom", [raw(f"{KH}/config.toml", b'\xef\xbb\xbfhooks = [{ command = "x" }]\n')]),
        case("config_invalid_utf8", [raw(f"{KH}/config.toml", b'a = "\xff"\n')]),
        case("config_unreadable", [file(f"{KH}/config.toml", 'hooks = [{ command = "x" }]\n', mode=0o000)]),
        case("config_is_directory", dirs=[f"{KH}/config.toml"]),
        case(
            "config_symlink",
            [file("elsewhere/c.toml", 'hooks = [{ event = "Stop", command = "l.sh" }]\n')],
            [link(f"{KH}/config.toml", "<ROOT>/elsewhere/c.toml")],
        ),
        case("mcp_servers", [doc(f"{KH}/mcp.json", {"mcpServers": SERVERS})]),
        case(
            "mcp_nan_args",
            [file(f"{KW}/mcp.json", '{"mcpServers": {"n": {"command": "x", "args": [NaN, Infinity, -Infinity]}}}')],
        ),
        case("mcp_not_dict", [doc(f"{KH}/mcp.json", {"mcpServers": ["x"]})]),
        case("mcp_top_level_list", [doc(f"{KH}/mcp.json", [{"mcpServers": SERVERS}])]),
        case("mcp_empty", [doc(f"{KH}/mcp.json", {})]),
        case("mcp_invalid", [file(f"{KH}/mcp.json", "{")]),
        case("mcp_invalid_utf8", [raw(f"{KH}/mcp.json", b'{"mcpServers": {"\xff": {}}}')]),
        case("mcp_bom", [raw(f"{KH}/mcp.json", b'\xef\xbb\xbf{"mcpServers": {"b": {"command": "x"}}}')]),
        case(
            "mcp_duplicate_keys",
            [
                file(
                    f"{KH}/mcp.json",
                    '{"mcpServers": {"d": {"command": "one"}, "e": {"url": "u"}, "d": {"command": "two"}}}',
                )
            ],
        ),
        case(
            "mcp_escaped_text",
            [file(f"{KH}/mcp.json", '{"mcpServers": {"caf\\u00e9 \\ud83d\\ude00": {"command": "\\u00e9"}}}')],
        ),
        case("mcp_lone_surrogate_server", [file(f"{KH}/mcp.json", '{"mcpServers": {"s": {"command": "\\ud800"}}}')]),
        case(
            "mcp_lone_surrogate_unused",
            [file(f"{KH}/mcp.json", '{"other": "\\ud800", "mcpServers": {"ok": {"command": "x"}}}')],
        ),
        case(
            "mcp_deep_nesting",
            [file(f"{KH}/mcp.json", '{"mcpServers": {}, "x": ' + "[" * 600 + "]" * 600 + "}")],
        ),
        case(
            "home_and_workspace",
            [
                file(f"{KH}/config.toml", 'hooks = [{ event = "Stop", command = "g.sh" }]\n'),
                file(f"{KW}/config.toml", 'hooks = [{ event = "Stop", command = "p.sh" }]\n'),
                doc(f"{KH}/mcp.json", {"mcpServers": {"g": {"command": "g"}}}),
                doc(f"{KW}/mcp.json", {"mcpServers": {"p": {"url": "https://p"}}}),
            ],
        ),
        case(
            "kimi_home_env",
            [
                file("kh/.kimi-code/config.toml", 'hooks = [{ event = "Stop", command = "env.sh" }]\n'),
                doc("kh/.kimi-code/mcp.json", {"mcpServers": {"e": {"command": "e"}}}),
                file(f"{KH}/config.toml", 'hooks = [{ event = "Stop", command = "ignored.sh" }]\n'),
            ],
            env={"KIMI_CODE_HOME": "<ROOT>/kh"},
        ),
        case(
            "kimi_home_env_symlink",
            [file("real/.kimi-code/config.toml", 'hooks = [{ event = "Stop", command = "r.sh" }]\n')],
            [link("linkhome", "<ROOT>/real")],
            env={"KIMI_CODE_HOME": "<ROOT>/linkhome"},
        ),
        case(
            "workspace_is_home",
            [
                file(f"{KH}/config.toml", 'hooks = [{ event = "Stop", command = "s.sh" }]\n'),
                doc(f"{KH}/mcp.json", {"mcpServers": {"s": {"command": "s"}}}),
            ],
            workspace="home",
        ),
        case(
            "relative_context",
            [
                file(f"{KH}/config.toml", 'hooks = [{ event = "Stop", command = "s.sh" }]\n'),
                doc(f"{KW}/mcp.json", {"mcpServers": {"w": {"command": "w"}}}),
            ],
            relative=True,
        ),
        case(
            "home_is_cwd",
            [file(".kimi-code/config.toml", 'hooks = [{ event = "Stop", command = "s.sh" }]\n')],
            home=".",
            workspace=None,
            relative=True,
        ),
        case(
            "kimi_root_unsearchable",
            [file(f"{KH}/config.toml", 'hooks = [{ command = "x" }]\n')],
            dir_modes={KH: 0o000},
        ),
    ]
