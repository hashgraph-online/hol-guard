"""Cursor fixture cases for `record_adapter_vectors.py`: the MCP servers of
the global and project editor configs. Paths are relative to the fixture
root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

from adapter_vector_cases import case, doc, file

HOME = "home/.cursor/mcp.json"
WORK = "work/.cursor/mcp.json"
PROXY = ["guard", "mcp-proxy", "--server", "x"]

SERVERS = {
    "local": {"command": "node", "args": ["a", 1, None, "b"], "env": {"A": "1", " B ": "2", "": "x", "C": 3}},
    "remote": {"url": "https://mcp.example/x", "headers": {"Authorization": "t", " X ": "y", "N": 1}},
    "environment": {"command": "uvx", "environment": {"Z": "z", "A": "a"}},
    "env_not_dict": {"command": "uvx", "env": ["x"], "environment": {"E": "e"}},
    "both": {"command": "c", "env": {"K": "env"}, "environment": {"K": "environment"}},
    "dup_keys": {"command": "c", "env": {"K": "1", " K": "2", "K ": "3"}},
    "args_str": {"command": "c", "args": "abc"},
    "args_dict": {"command": "c", "args": {"x": 1, "y": 2}},
    "args_empty": {"command": "c", "args": []},
    "non_str_command": {"command": 5, "url": 7},
    "url_and_command": {"command": "c", "url": "https://mcp.example/y"},
    "guard_proxy": {"command": "hol-guard", "args": PROXY},
    "bare": {},
    "not_dict": "x",
    "list_config": ["y"],
}


def cursor_cases() -> list[dict]:
    return [
        case("nothing"),
        case("global_servers", [doc(HOME, {"mcpServers": SERVERS})]),
        case("project_servers", [doc(WORK, {"mcpServers": SERVERS})]),
        case(
            "both_configs",
            [
                doc(HOME, {"mcpServers": {"same": {"command": "g"}}}),
                doc(WORK, {"mcpServers": {"same": {"command": "p"}}}),
            ],
        ),
        case(
            "no_workspace",
            [doc(HOME, {"mcpServers": {"g": {"command": "g"}}}), doc(WORK, {"mcpServers": {}})],
            workspace=None,
        ),
        case(
            "workspace_inside_home",
            [doc("home/proj/.cursor/mcp.json", {"mcpServers": {"p": {"command": "p"}}})],
            workspace="home/proj",
        ),
        case(
            "home_inside_workspace",
            [doc("work/h/.cursor/mcp.json", {"mcpServers": {"h": {"command": "h"}}})],
            home="work/h",
        ),
        case("args_null", [doc(HOME, {"mcpServers": {"n": {"command": "c", "args": None}}})]),
        case("args_number", [doc(HOME, {"mcpServers": {"n": {"command": "c", "args": 4}}})]),
        case("servers_not_dict", [doc(HOME, {"mcpServers": ["x"]}), doc(WORK, {"other": 1})]),
        case("empty_servers", [doc(HOME, {"mcpServers": {}})]),
        case("invalid_json", [file(HOME, "{nope"), file(WORK, "")]),
        case("empty_object", [doc(HOME, {})]),
        case("list_top_level", [doc(HOME, [{"mcpServers": {}}])]),
        case("unreadable", [file(HOME, '{"mcpServers": {"x": {"command": "c"}}}', mode=0o000)]),
        case(
            "relative_paths",
            [doc(HOME, {"mcpServers": {"r": {"command": "r"}}}), doc(WORK, {"mcpServers": {"w": {"url": "u"}}})],
            relative=True,
        ),
        case("lone_surrogate_name", [file(HOME, '{"mcpServers": {"bad\\ud800": {"command": "x"}}}')]),
        case("lone_surrogate_env", [file(HOME, '{"mcpServers": {"s": {"command": "x", "env": {"K": "\\udc80"}}}}')]),
        case("unicode", [doc(HOME, {"mcpServers": {"Ä": {"command": "ü", "args": ["é"], "env": {"Ö": "ß"}}}})]),
        case(
            "nested_values",
            [doc(HOME, {"mcpServers": {"n": {"command": "c", "extra": {"a": [1.5, True]}, "env": {"A": {"x": 1}}}}})],
        ),
        case(
            "big_numbers",
            [
                file(
                    HOME,
                    '{"mcpServers": {"n": {"command": "c", "args": [1e400, 123456789012345678901234567890, "ok"]}}}',
                )
            ],
        ),
        case(
            "duplicate_server_keys",
            [file(HOME, '{"mcpServers": {"d": {"command": "first"}, "e": {}, "d": {"command": "last"}}}')],
        ),
        case(
            "many_servers", [doc(HOME, {"mcpServers": {f"s{index}": {"command": f"c{index}"} for index in range(12)}})]
        ),
        case(
            "list_command",
            [doc(HOME, {"mcpServers": {"l": {"command": ["node", "x"], "args": ["y"]}, "u": {"url": ["x"]}}})],
        ),
        case("proxy_in_workspace", [doc(WORK, {"mcpServers": {"guarded": {"command": "hol-guard", "args": PROXY}}})]),
    ]
