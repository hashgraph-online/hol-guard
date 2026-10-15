"""Fixture cases for `record_claude_code_vectors.py`: settings parsing, MCP
servers, hooks and the project agent, skill, command and rule directories.
Paths are relative to the fixture root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

import json

HOME_SETTINGS = "home/.claude/settings.json"
HOME_LOCAL = "home/.claude/settings.local.json"
PROJECT_SETTINGS = "work/.claude/settings.json"
PROJECT_LOCAL = "work/.claude/settings.local.json"
PROJECT_MCP = "work/.mcp.json"


def file(path: str, text: str = "x", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def raw(path: str, data: bytes) -> dict:
    return {"path": path, "hex": data.hex(), "mode": 0o644}


def doc(path: str, value: object) -> dict:
    return file(path, json.dumps(value))


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def case(
    name: str,
    files: list[dict] | None = None,
    symlinks: list[dict] | None = None,
    *,
    dirs: list[str] | None = None,
    dir_modes: dict[str, int] | None = None,
    home: str = "home",
    workspace: str | None = "work",
    relative: bool = False,
) -> dict:
    return {
        "name": name,
        "files": files or [],
        "symlinks": symlinks or [],
        "dirs": dirs or [],
        "dir_modes": dir_modes or {},
        "home": home,
        "workspace": workspace,
        "relative": relative,
    }


def servers(path: str, value: object) -> dict:
    return doc(path, {"mcpServers": value})


def hooks(path: str, value: object) -> dict:
    return doc(path, {"hooks": value})


def settings_cases() -> list[dict]:
    return [
        case("nothing"),
        case("settings_empty_object", [doc(HOME_SETTINGS, {})]),
        case("settings_unused_keys", [doc(HOME_SETTINGS, {"model": "x"})]),
        case("settings_invalid_json", [file(HOME_SETTINGS, "{not json")]),
        case("settings_empty_file", [file(HOME_SETTINGS, "")]),
        case("settings_top_level_list", [doc(HOME_SETTINGS, [{"mcpServers": {}}])]),
        case("settings_bom", [raw(HOME_SETTINGS, b'\xef\xbb\xbf{"model": "x"}')]),
        case("settings_invalid_utf8", [raw(HOME_SETTINGS, b'{"model": "\xff"}')]),
        case("settings_huge_integer", [file(HOME_SETTINGS, '{"n": ' + "9" * 5000 + "}")]),
        case("settings_unreadable", [file(HOME_SETTINGS, '{"model": "x"}', mode=0o000)]),
        case("settings_is_directory", dirs=[HOME_SETTINGS]),
        case(
            "settings_symlink_to_file",
            [doc("elsewhere/settings.json", {"model": "x"})],
            [link(HOME_SETTINGS, "<ROOT>/elsewhere/settings.json")],
        ),
        case("settings_dangling_symlink", symlinks=[link(HOME_SETTINGS, "<ROOT>/missing.json")]),
        case("settings_crlf", [file(HOME_SETTINGS, '{\r\n"model": "x"\r\n}\r\n')]),
        case("settings_deep_nesting", [file(HOME_SETTINGS, '{"x": ' + "[" * 600 + "]" * 600 + "}")]),
        case("unused_key_lone_surrogate", [file(HOME_SETTINGS, '{"other": "\\ud800", "model": "x"}')]),
        case(
            "every_candidate",
            [
                servers(HOME_SETTINGS, {"a": {"command": "a"}}),
                servers(HOME_LOCAL, {"b": {"command": "b"}}),
                servers(PROJECT_SETTINGS, {"c": {"command": "c"}}),
                servers(PROJECT_LOCAL, {"d": {"command": "d"}}),
                servers(PROJECT_MCP, {"e": {"url": "https://e.example/mcp"}}),
                servers("home/.mcp.json", {"ignored": {"command": "x"}}),
            ],
        ),
        case(
            "no_workspace",
            [servers(HOME_SETTINGS, {"a": {"command": "a"}}), servers(PROJECT_MCP, {"e": {"command": "e"}})],
            dirs=["work/.claude/agents"],
            workspace=None,
        ),
        case(
            "workspace_is_home",
            [servers(HOME_SETTINGS, {"a": {"command": "a"}}), servers("home/.mcp.json", {"m": {"command": "m"}})],
            workspace="home",
        ),
        case(
            "home_inside_workspace", [servers("work/h/.claude/settings.json", {"a": {"command": "a"}})], home="work/h"
        ),
        case(
            "relative_paths",
            [
                servers(HOME_SETTINGS, {"a": {"command": "a"}}),
                servers(PROJECT_MCP, {"e": {"command": "e"}}),
                file("work/.claude/agents/one.md"),
            ],
            relative=True,
        ),
    ]


def mcp_cases() -> list[dict]:
    return [
        case(
            "mcp_matrix",
            [
                servers(
                    HOME_SETTINGS,
                    {
                        "stdio": {
                            "command": "npx",
                            "args": ["-y", 5, None, "pkg", ["n"], ""],
                            "env": {" A ": "1", "A": "2", "": "x", "  ": "y", "B": 3, "C": None, "D": "d"},
                            "headers": {" H ": "v", "": "e", "N": 1},
                        },
                        "http": {"url": "https://h.example/mcp", "headers": {"Authorization": "Bearer t", "X": "y"}},
                        "both": {"command": "run", "url": "https://b.example"},
                        "neither": {},
                        "list_command": {"command": ["a", "b"], "url": 5},
                        "not_object": "x",
                        "null_config": None,
                    },
                )
            ],
        ),
        case("mcp_args_string", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": "abc"}})]),
        case("mcp_args_object", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": {"k1": 1, "k2": 2}}})]),
        case("mcp_args_null", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": None}})]),
        case("mcp_args_integer", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": 3}})]),
        case("mcp_args_bool", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": True}})]),
        case("mcp_args_empty_string", [servers(HOME_SETTINGS, {"s": {"command": "c", "args": ""}})]),
        case("mcp_env_not_object", [servers(HOME_SETTINGS, {"s": {"command": "c", "env": ["A=1"], "headers": "x"}})]),
        case("mcp_servers_not_object", [doc(HOME_SETTINGS, {"mcpServers": [{"command": "c"}]})]),
        case(
            "mcp_duplicate_names",
            [file(HOME_SETTINGS, '{"mcpServers": {"a": {"command": "one"}, "b": {}, "a": {"command": "two"}}}')],
        ),
        case(
            "mcp_duplicate_env_keys",
            [file(HOME_SETTINGS, '{"mcpServers": {"a": {"command": "c", "env": {"K": "1", "J": "2", "K": "3"}}}}')],
        ),
        case("mcp_unicode_names", [servers(HOME_SETTINGS, {"café": {"command": "ü"}, "😀": {"url": "https://x"}})]),
        case("mcp_name_lone_surrogate", [file(HOME_SETTINGS, '{"mcpServers": {"\\ud800": {"command": "c"}}}')]),
        case("mcp_env_value_lone_surrogate", [file(HOME_SETTINGS, '{"mcpServers": {"a": {"env": {"K": "\\udc00"}}}}')]),
        case(
            "mcp_arg_lone_surrogate_dropped_type",
            [file(HOME_SETTINGS, '{"mcpServers": {"a": {"command": "c", "args": ["ok", "\\ud800"]}}}')],
        ),
        case(
            "mcp_unused_field_lone_surrogate",
            [file(HOME_SETTINGS, '{"mcpServers": {"a": {"command": "c", "extra": "\\ud800"}}}')],
        ),
        case("mcp_escaped_pair", [file(HOME_SETTINGS, '{"mcpServers": {"a": {"command": "\\ud83d\\ude00"}}}')]),
        case(
            "mcp_whitespace_keys",
            [servers(HOME_SETTINGS, {"w": {"command": "c", "env": {"\u00a0K\u2003": "v", "\x1cL": "w"}}})],
        ),
        case("mcp_project_scope", [servers(PROJECT_MCP, {"p": {"command": "p", "env": {"T": "1"}}})]),
    ]


def hook_cases() -> list[dict]:
    flat = {"command": "guard", "args": ["hook", "--x"]}
    return [
        case(
            "hooks_flat",
            [
                hooks(
                    HOME_SETTINGS,
                    {
                        "PreToolUse": [
                            flat,
                            {"command": "bare"},
                            {"command": "mixed", "args": ["a", 1]},
                            {"command": "notlist", "args": "a"},
                            {"command": "with_hooks", "hooks": [{"command": "ignored"}]},
                            "string",
                            None,
                        ],
                    },
                )
            ],
        ),
        case(
            "hooks_grouped",
            [
                hooks(
                    HOME_SETTINGS,
                    {
                        "  PostToolUse ": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {"type": "command", "command": "a", "args": ["1"], "timeout": 5, "if": "x"},
                                    {"type": "http", "url": "http://127.0.0.1/h", "timeout": True},
                                    {"type": 1, "url": 2, "timeout": 1.5, "if": 3, "command": 4},
                                    {"command": "b", "timeout": "5"},
                                    {"timeout": 12345678901234567890},
                                    {"timeout": -1},
                                    {"timeout": 10**30},
                                    {},
                                    "skip",
                                ],
                            },
                            {"matcher": 7, "hooks": [{"command": "c"}]},
                            {"hooks": {"command": "d"}},
                            {"matcher": "m"},
                        ],
                    },
                )
            ],
        ),
        case(
            "hooks_shapes",
            [
                hooks(
                    HOME_SETTINGS,
                    {"Stop": {"command": "x"}, "SessionStart": [], "ÜBER": [{"command": "u"}], "": [{"command": "e"}]},
                )
            ],
        ),
        case("hooks_not_object", [doc(HOME_SETTINGS, {"hooks": [{"command": "x"}]})]),
        case("hooks_lone_surrogate_command", [file(HOME_SETTINGS, '{"hooks": {"Stop": [{"command": "\\ud800"}]}}')]),
        case(
            "hooks_lone_surrogate_unused",
            [file(HOME_SETTINGS, '{"hooks": {"Stop": [{"command": "c", "note": "\\ud800"}]}}')],
        ),
        case(
            "hooks_and_mcp_project",
            [
                doc(
                    PROJECT_LOCAL,
                    {"hooks": {"Stop": [{"hooks": [{"command": "s"}]}]}, "mcpServers": {"m": {"command": "m"}}},
                )
            ],
        ),
        case("hooks_final_sigma", [hooks(HOME_SETTINGS, {"ΟΔΟΣ": [{"command": "x"}], "İx": [{"command": "y"}]})]),
    ]


def markdown(base: str) -> list[dict]:
    return [
        file(f"{base}/a.md", "alpha"),
        file(f"{base}/B.MD"),
        file(f"{base}/.hidden.md", "hidden"),
        file(f"{base}/.md", "dot"),
        file(f"{base}/notes.txt"),
        file(f"{base}/sub/nested.md"),
        file(f"{base}/locked.md", "secret", mode=0o000),
        file(f"{base}/z b.md"),
        file(f"{base}/a-b.md"),
        file(f"{base}/é.md"),
        file("outside/out.md", "outside"),
        file("work/inside.md", "inside"),
    ]


def markdown_links(base: str) -> list[dict]:
    return [
        link(f"{base}/linked_in.md", "<ROOT>/work/inside.md"),
        link(f"{base}/linked_out.md", "<ROOT>/outside/out.md"),
        link(f"{base}/dangling.md", "<ROOT>/work/missing.md"),
    ]


def directory_cases() -> list[dict]:
    skills = ".claude/skills"
    return [
        case(
            "agents",
            markdown("work/.claude/agents"),
            markdown_links("work/.claude/agents"),
            dirs=["work/.claude/agents/dir.md"],
        ),
        case("commands", markdown("work/.claude/commands"), markdown_links("work/.claude/commands")),
        case("rules", markdown("work/.claude/rules"), markdown_links("work/.claude/rules")),
        case("empty_agents_dir", dirs=["work/.claude/agents"]),
        case("agents_is_file", [file("work/.claude/agents")]),
        case(
            "agents_dir_link_inside",
            [file("work/real-agents/x.md")],
            [link("work/.claude/agents", "<ROOT>/work/real-agents")],
        ),
        case(
            "agents_dir_link_outside",
            [file("outside/agents/x.md")],
            [
                link("work/.claude/agents", "<ROOT>/outside/agents"),
                link("work/.claude/commands", "<ROOT>/outside/agents"),
            ],
        ),
        case("agents_dir_dangling", symlinks=[link("work/.claude/agents", "<ROOT>/nowhere")]),
        case("agents_dir_unreadable", [file("work/.claude/agents/x.md")], dir_modes={"work/.claude/agents": 0o000}),
        case(
            "skills_tree",
            [
                file(f"work/{skills}/SKILL.md", "root"),
                file(f"work/{skills}/alpha/SKILL.md", "a"),
                file(f"work/{skills}/alpha/beta/SKILL.md", "b"),
                file(f"work/{skills}/.hidden/SKILL.md", "h"),
                file(f"work/{skills}/gamma/skill.md"),
                file(f"work/{skills}/a/SKILL.md"),
                file(f"work/{skills}/a-b/SKILL.md"),
                file(f"work/{skills}/a b/SKILL.md"),
                file(f"work/{skills}/a.b/SKILL.md"),
                file(f"work/{skills}/Z/SKILL.md"),
                file(f"work/{skills}/é/SKILL.md"),
                file(f"work/{skills}/locked/SKILL.md", mode=0o000),
                file(f"work/{skills}/sealed/inner/SKILL.md"),
                file("work/elsewhere/linked/SKILL.md", "linked"),
                file("outside/skill/SKILL.md"),
            ],
            [
                link(f"work/{skills}/dirlink", "<ROOT>/work/elsewhere/linked"),
                link(f"work/{skills}/filelink/SKILL.md", "<ROOT>/work/elsewhere/linked/SKILL.md"),
                link(f"work/{skills}/outlink/SKILL.md", "<ROOT>/outside/skill/SKILL.md"),
                link(f"work/{skills}/dangle/SKILL.md", "<ROOT>/nowhere"),
            ],
            dirs=[f"work/{skills}/isdir/SKILL.md"],
            dir_modes={f"work/{skills}/sealed": 0o000},
        ),
        case("skills_dir_link_outside", [file("outside/s/SKILL.md")], [link(f"work/{skills}", "<ROOT>/outside/s")]),
        case(
            "workspace_is_link",
            [file("real-work/.claude/agents/x.md"), file("real-work/.claude/skills/s/SKILL.md")],
            [link("work", "<ROOT>/real-work")],
        ),
    ]


def cases() -> list[dict]:
    return [*settings_cases(), *mcp_cases(), *hook_cases(), *directory_cases()]
