"""Fixture cases for `record_adapter_vectors.py devin`: Devin's JSONC config
files, hooks, MCP servers, skill roots and the Claude Code hook overlap.
Paths are relative to the fixture root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

from adapter_vector_cases import SKILL, case, doc, file, link, raw

D_HOME = "home/.config/devin"
D_USER = f"{D_HOME}/config.json"
D_USER_MCP = f"{D_HOME}/mcp_config.json"
D_WORK = "work/.devin"
CLAUDE_HOOK = "python -m codex_plugin_scanner.cli guard hook --harness claude-code"

HOOKS = {
    "PreToolUse": [
        {
            "matcher": "exec",
            "hooks": [
                {"type": "command", "command": "a.sh", "timeout": 30},
                {"command": "b.sh", "timeout": 2.5, "type": ""},
                {"command": "   "},
                {"command": 7},
                "not-a-dict",
                {"command": "c.sh", "timeout": True, "type": 3},
            ],
        },
        {"matcher": "", "hooks": [{"command": "d.sh", "timeout": "30"}]},
        {"matcher": 5, "hooks": [{"command": "e.sh"}]},
        {"hooks": "not-a-list"},
        {"command": "group-level.sh"},
        "not-a-dict",
    ],
    "Stop": [{"hooks": [{"command": " spaced.sh "}]}],
    "ÉVÉNEMENT": [{"hooks": [{"command": "accent.sh"}]}],
    "İstanbul": [{"hooks": [{"command": "dotted.sh"}]}],
    "NotAList": {"hooks": []},
    "Empty": [],
}

MANAGED_HOOKS = {
    "PreToolUse": [
        {
            "matcher": "exec",
            "hooks": [
                {"command": "run HOL_GUARD_MANAGED_DEVIN=1 guard"},
                {"command": "python -m codex_plugin_scanner.cli ['guard', 'hook', '--harness', 'devin']"},
                {"command": "python -m codex_plugin_scanner.cli ['guard', 'hook', '--harness', 'codex']"},
                {"command": 'python bounded_cli_hook_bridge {\\"harness\\":\\"devin\\"}'},
                {"command": 'python bounded_cli_hook_bridge {"harness":"devin"}'},
                {"command": 'python bounded_cli_hook_bridge {"harness":"codex"}'},
                {"command": 'guard __guard-bounded-hook {"harness":"devin"}'},
                {"command": "guard __guard-bounded-hook harness devin"},
                {"command": "py C:\\guard\\managed\\bounded-hooks\\devin.py"},
                {"command": "py /g/managed/bounded-hooks/devin.py"},
                {"command": "py /g/managed/bounded-hooks/codex.py"},
                {"command": "kept.sh"},
            ],
        }
    ]
}

SERVERS = {
    "local": {"command": "node", "args": ["a", 1, 1.5, 1e20, True, False, None, ["x"], {"k": 1}]},
    "remote": {"url": "https://mcp.example/x", "command": 5},
    "blank_url": {"url": "   ", "command": "c"},
    "explicit": {"command": "c", "transport": " sse ", "url": "https://x"},
    "blank_transport": {"command": "c", "transport": "  ", "url": "https://x"},
    "transport_not_str": {"command": "c", "transport": 3},
    "args_not_list": {"command": "c", "args": "abc"},
    "env": {
        "command": "c",
        "env": {" API_KEY ": "secret", "": "x", "  ": "y", "NUM": 3, "B": "1", " B": "2", "A": "z"},
    },
    "env_not_dict": {"command": "c", "env": ["A"]},
    "environment_ignored": {"command": "c", "environment": {"X": "1"}},
    "bare": {},
    "only_args": {"args": ["a"]},
    "not_dict": "x",
    "list_config": ["y"],
}


def overlap_files(prefix: str) -> list[dict]:
    return [doc(f"{prefix}/.claude/settings.json", {"hooks": {"PreToolUse": [{"hooks": [{"command": CLAUDE_HOOK}]}]}})]


def devin_cases() -> list[dict]:
    return [
        case("empty"),
        case("no_workspace", [doc(D_USER, {"hooks": HOOKS, "mcpServers": SERVERS})], workspace=None),
        case("user_hooks", [doc(D_USER, {"hooks": HOOKS})]),
        case("managed_hooks_skipped", [doc(D_USER, {"hooks": MANAGED_HOOKS})]),
        case("hooks_not_dict", [doc(D_USER, {"hooks": ["x"], "mcpServers": "y"})]),
        case("legacy_mcp_in_config", [doc(D_USER, {"mcpServers": SERVERS})]),
        case(
            "every_config_file",
            [
                doc(
                    D_USER,
                    {"hooks": {"Stop": [{"hooks": [{"command": "u.sh"}]}]}, "mcpServers": {"u": {"command": "u"}}},
                ),
                doc(f"{D_WORK}/config.json", {"hooks": {"Stop": [{"hooks": [{"command": "p.sh"}]}]}}),
                doc(f"{D_WORK}/config.local.json", {"mcpServers": {"l": {"url": "https://l"}}}),
                doc(f"{D_WORK}/hooks.v1.json", {"PreToolUse": [{"matcher": "read", "hooks": [{"command": "v1.sh"}]}]}),
                doc(
                    D_USER_MCP,
                    {"mcpServers": {"g": {"command": "g"}}, "hooks": {"Stop": [{"hooks": [{"command": "x"}]}]}},
                ),
                doc(f"{D_WORK}/mcp_config.json", {"mcpServers": {"w": {"command": "w"}}}),
                doc(f"{D_WORK}/mcp_config.local.json", {"mcpServers": {"wl": {"command": "wl", "env": {"T": "1"}}}}),
            ],
        ),
        case(
            "workspace_files_without_workspace",
            [doc(f"{D_WORK}/config.json", {"hooks": {"Stop": [{"hooks": [{"command": "p.sh"}]}]}})],
            workspace=None,
        ),
        case("empty_config_objects", [doc(D_USER, {}), doc(D_USER_MCP, {}), doc(f"{D_WORK}/hooks.v1.json", {})]),
        case("hooks_v1_not_object", [file(f"{D_WORK}/hooks.v1.json", "[1, 2]")]),
        case("hooks_v1_list_events", [doc(f"{D_WORK}/hooks.v1.json", {"Stop": "x", "hooks": {"Stop": []}})]),
        case(
            "jsonc_comments_and_commas",
            [
                file(
                    D_USER,
                    "// leading comment\n{\n  /* block */ "
                    '"hooks": {"Stop": [{"hooks": [{"command": "a // not a comment", },],},],},\n'
                    '  "mcpServers": {"s": {"command": "c", "args": ["x", /* gap */ ], }, // trailing\n },\n}\n',
                ),
            ],
        ),
        case(
            "jsonc_comma_before_comment_close",
            [file(D_USER_MCP, '{"mcpServers": {"s": {"command": "c"}, // note\n /* x */ }}')],
        ),
        case(
            "jsonc_escaped_quote_in_string", [file(D_USER_MCP, '{"mcpServers": {"q\\"//x": {"command": "c\\\\"}, }}')]
        ),
        case("jsonc_unterminated_block", [file(D_USER_MCP, '{"mcpServers": {}} /* never closed')]),
        case("jsonc_unterminated_block_only", [file(D_USER_MCP, "/* only")]),
        case("jsonc_comment_only", [file(D_USER, "// nothing here\n/* or here */\n")]),
        case("jsonc_slash_alone", [file(D_USER, '{"a": 1} /')]),
        case("jsonc_strip_keeps_invalid", [file(D_USER, "{,}")]),
        case("jsonc_top_level_list", [file(D_USER, "[1,]")]),
        case("strict_top_level_list", [file(D_USER, "[1]")]),
        case("strict_top_level_string", [file(D_USER, '"x"')]),
        case("whitespace_only", [file(D_USER, " \n\t\x0b\x0c\x1c\u3000")]),
        case("empty_file", [file(D_USER, "")]),
        case("invalid_json", [file(D_USER, "{"), file(f"{D_WORK}/hooks.v1.json", "{"), file(D_USER_MCP, "nope")]),
        case("bom", [raw(D_USER, b'\xef\xbb\xbf{"hooks": {}}')]),
        case("invalid_utf8", [raw(D_USER, b'{"hooks": {"\xff": []}}')]),
        case("unreadable", [file(D_USER, '{"hooks": {}}', mode=0o000)]),
        case("config_is_directory", dirs=[D_USER, D_USER_MCP]),
        case(
            "config_symlink",
            [doc("elsewhere/config.json", {"hooks": {"Stop": [{"hooks": [{"command": "l.sh"}]}]}})],
            [link(D_USER, "<ROOT>/elsewhere/config.json"), link(D_USER_MCP, "<ROOT>/missing.json")],
        ),
        case(
            "nan_and_infinity_args",
            [file(D_USER_MCP, '{"mcpServers": {"n": {"command": "c", "args": [NaN, Infinity, -Infinity, -0.0]}}}')],
        ),
        case("integer_limit", [file(D_USER, '{"x": ' + "9" * 5000 + "}")]),
        case("integer_limit_after_strip", [file(D_USER, '{"x": ' + "9" * 5000 + ",}")]),
        case("integer_limit_in_claude_settings", [file("home/.claude/settings.json", '{"x": ' + "9" * 5000 + "}")]),
        case(
            "duplicate_keys",
            [file(D_USER_MCP, '{"mcpServers": {"d": {"command": "first"}, "e": {}, "d": {"command": "last"}}}')],
        ),
        case(
            "unicode_names", [file(D_USER_MCP, '{"mcpServers": {"caf\\u00e9 \\ud83d\\ude00": {"command": "\\u00e9"}}}')]
        ),
        case("lone_surrogate_server", [file(D_USER_MCP, '{"mcpServers": {"\\ud800": {"command": "c"}}}')]),
        case(
            "lone_surrogate_env_key",
            [file(D_USER_MCP, '{"mcpServers": {"s": {"command": "c", "env": {"\\udc80": "v"}}}}')],
        ),
        case(
            "lone_surrogate_unused", [file(D_USER_MCP, '{"other": "\\ud800", "mcpServers": {"s": {"command": "c"}}}')]
        ),
        case("lone_surrogate_hook", [file(D_USER, '{"hooks": {"Stop": [{"hooks": [{"command": "\\udc80"}]}]}}')]),
        case(
            "lone_surrogate_managed_hook",
            [file(D_USER, '{"hooks": {"Stop": [{"hooks": [{"command": "HOL_GUARD_MANAGED_DEVIN \\udc80"}]}]}}')],
        ),
        case("lone_surrogate_jsonc", [file(D_USER, '{"hooks": {"Stop": [{"hooks": [{"command": "\\ud800x"},]}]}}')]),
        case("overlap_user_settings", overlap_files("home")),
        case("overlap_disabled", [*overlap_files("home"), doc(D_USER, {"read_config_from": {"claude": False}})]),
        case(
            "overlap_disabled_falsy_not_false",
            [*overlap_files("home"), doc(D_USER, {"read_config_from": {"claude": 0}})],
        ),
        case("overlap_read_config_not_dict", [*overlap_files("home"), doc(D_USER, {"read_config_from": False})]),
        case(
            "overlap_disabled_in_project_config_only",
            [*overlap_files("home"), doc(f"{D_WORK}/config.json", {"read_config_from": {"claude": False}})],
        ),
        case(
            "overlap_user_config_unparsed",
            [*overlap_files("home"), file(D_USER, '{"read_config_from": {"claude": false}')],
        ),
        case(
            "overlap_user_config_jsonc",
            [*overlap_files("home"), file(D_USER, '{"read_config_from": {"claude": false,},}')],
        ),
        case("overlap_workspace_settings", overlap_files("work")),
        case("overlap_workspace_without_workspace", overlap_files("work"), workspace=None),
        case(
            "overlap_workspace_claude_json_ignored",
            [doc("work/.claude.json", {"hooks": {"S": [{"command": CLAUDE_HOOK}]}})],
        ),
        case(
            "overlap_markers",
            [
                doc(
                    "home/.claude/settings.local.json",
                    {"hooks": {"S": [{"hooks": [{"command": "x HOL_GUARD_CLAUDE_DAEMON_HOOK"}]}]}},
                ),
            ],
        ),
        case(
            "overlap_session_marker_group_command",
            [doc("home/.claude.json", {"hooks": {"S": [{"command": "HOL_GUARD_CLAUDE_SESSION_START_HOOK=1 g"}]}})],
        ),
        case(
            "overlap_quoted_harness_marker",
            [
                doc(
                    "work/.claude/settings.local.json",
                    {"hooks": {"S": [{"hooks": [{"command": "['--harness', 'claude-code']"}]}]}},
                )
            ],
        ),
        case(
            "overlap_near_misses",
            [
                doc(
                    "home/.claude/settings.json",
                    {
                        "hooks": {
                            "S": [
                                {"hooks": [{"command": "--harness codex"}, {"command": 4}, "x"]},
                                {"command": ["--harness claude-code"]},
                                "y",
                            ],
                            "T": {"command": "--harness claude-code"},
                        },
                        "command": "--harness claude-code",
                    },
                ),
                file("home/.claude/settings.local.json", "{"),
                file("home/.claude.json", '["--harness claude-code"]'),
            ],
        ),
        case("overlap_claude_invalid_utf8", [raw("home/.claude/settings.json", b'{"\xff": 1}')]),
        case("overlap_claude_unreadable", [file("home/.claude/settings.json", "{}", mode=0o000)]),
        case("overlap_claude_directory", dirs=["home/.claude/settings.json"]),
        case(
            "skills_every_root",
            [
                file(f"{D_HOME}/skills/a/SKILL.md", SKILL),
                file("home/.agents/skills/b/SKILL.md", SKILL),
                file(f"{D_WORK}/skills/c/SKILL.md", SKILL),
                file("work/.agents/skills/d/nested/SKILL.md", SKILL),
            ],
        ),
        case("skills_without_workspace", [file(f"{D_WORK}/skills/c/SKILL.md", SKILL)], workspace=None),
        case("skill_at_root", [file(f"{D_HOME}/skills/SKILL.md", SKILL)]),
        case(
            "skill_identity_incomplete",
            [file(f"{D_HOME}/skills/a/SKILL.md", SKILL), file(f"{D_HOME}/skills/a/data.bin", "d", mode=0o000)],
        ),
        case(
            "skill_discovery_issues",
            [file("home/.agents/skills/ok/SKILL.md", SKILL), file("pack/s/SKILL.md", SKILL)],
            [link("home/.agents/skills/linked", "<ROOT>/pack/s")],
            dirs=["home/.agents/skills/locked"],
            dir_modes={"home/.agents/skills/locked": 0o000},
        ),
        case("skill_root_symlink", [file("pack/s/SKILL.md", SKILL)], [link(f"{D_WORK}/skills", "<ROOT>/pack")]),
        case(
            "relative_context",
            [doc(D_USER, {"hooks": {"Stop": [{"hooks": [{"command": "r.sh"}]}]}}), *overlap_files("work")],
            relative=True,
        ),
        case("relative_context_with_skills", [file("home/.agents/skills/a/SKILL.md", SKILL)], relative=True),
        case(
            "everything",
            [
                doc(D_USER, {"hooks": HOOKS, "mcpServers": SERVERS}),
                file(f"{D_WORK}/config.json", "{"),
                doc(f"{D_WORK}/hooks.v1.json", MANAGED_HOOKS),
                doc(f"{D_WORK}/mcp_config.json", {"mcpServers": SERVERS}),
                file(f"{D_HOME}/skills/a/SKILL.md", SKILL),
                file(f"{D_WORK}/skills/b/SKILL.md", SKILL),
                *overlap_files("home"),
            ],
        ),
    ]
