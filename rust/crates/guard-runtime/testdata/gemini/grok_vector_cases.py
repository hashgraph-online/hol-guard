"""Grok fixture cases for `record_adapter_vectors.py`: the `~/.grok` config
files with their permission rules, MCP servers and degraded-mode signals, the
global and project hook directories, the surfaces only listed as found, the
workspace instruction files, and the readable system policy files. Paths are
relative to the fixture root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

from adapter_vector_cases import case, doc, file, link, raw

GH = "home/.grok"
GW = "work/.grok"
SYSTEM = "etc/grok"

PERMISSIONS = """\
[permission]
allow = ["Read(*)"]
deny = []
ask = ["Bash(*)", "Edit(*)"]
rules = [1]
other = ["x"]
"""

SERVERS = """\
"mcp_servers.dotted" = { command = "dotted-cmd" }
"mcp_servers.dup" = { command = "second" }
"mcp_servers.x.y" = { url = "https://xy" }
"mcp_servers." = { command = "empty-name" }
"mcp_servers.str" = "not-a-table"
mcp_other = { command = "ignored" }

[mcp_servers.dup]
command = "first"

[mcp_servers.local]
command = "node"
args = ["a", 1, 2.5, true, false, -0.0, inf, nan, 1e20, 1e-5, 0x10]
environment = { A = "1", " B " = "2", C = 3, "" = "e", " " = "s" }
env = { A = "override", D = "4" }
headers = { Authorization = "Bearer x", " X-Pad " = "p", N = 1 }

[mcp_servers.remote]
url = "https://mcp.example/x"
command = 5
args = "not-a-list"

[mcp_servers.both]
command = "c"
url = "https://both"
transport = "sse"

[mcp_servers.bare]
x = 1

[mcp_servers.envonly]
command = "e"
env = { K = "v" }
environment = "nope"
"""

HOOKS = {
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {"type": "command", "command": "a.sh"},
                    {"command": "  "},
                    {"command": 5},
                    "not-a-dict",
                    {"command": "b.sh", "timeout": 3},
                ],
            },
            {"hooks": "not-a-list"},
            {"command": "direct.sh"},
            "not-a-dict",
            {"matcher": "", "hooks": [{"command": "empty-matcher.sh"}]},
            {"matcher": None, "hooks": [{"command": "null-matcher.sh"}]},
            {"matcher": ["a", 1], "hooks": [{"command": "list-matcher.sh"}]},
            {"matcher": 2.5, "hooks": [{"command": "float-matcher.sh"}]},
        ],
        "Stop": {"hooks": [{"command": "x"}]},
        "ÄUpper": [{"hooks": [{"command": "u.sh"}], "matcher": 5}],
        "SessionStart": [{"hooks": [{"command": "é \u2028 s.sh"}]}],
    }
}


def grok_cases() -> list[dict]:
    return [
        case("nothing"),
        case("no_workspace", [file(f"{GH}/config.toml", PERMISSIONS)], workspace=None),
        case("config_permissions", [file(f"{GH}/config.toml", PERMISSIONS)]),
        case("permission_not_table", [file(f"{GH}/config.toml", 'permission = "x"\n')]),
        case("permission_empty_lists", [file(f"{GH}/config.toml", "[permission]\nallow = []\ndeny = []\n")]),
        case("config_servers", [file(f"{GH}/config.toml", SERVERS)]),
        case(
            "mcp_servers_not_table", [file(f"{GH}/config.toml", 'mcp_servers = "x"\n"mcp_servers.a" = { url = "u" }\n')]
        ),
        case(
            "all_three_configs",
            [
                file(f"{GH}/config.toml", '[mcp_servers.s]\ncommand = "c1"\n[permission]\ndeny = ["a"]\n'),
                file(f"{GH}/managed_config.toml", '[permission]\nallow = ["b"]\n[mcp_servers.s]\ncommand = "c2"\n'),
                file(f"{GH}/requirements.toml", '[permission]\nask = ["c"]\nsandbox = "off"\n'),
            ],
        ),
        case(
            "degraded_markers",
            [
                file(
                    f"{GH}/config.toml",
                    'mode = "always-approve"\n[x]\ndefaultMode = "bypassPermissions"\n',
                )
            ],
        ),
        case(
            "degraded_serialized_only",
            [file(f"{GH}/managed_config.toml", 'xdefaultMode = "bypassPermissionsZ"\nk = "a\\"b"\n')],
        ),
        case("degraded_sandbox_strip", [file(f"{GH}/config.toml", 'sandbox = " OFF "\n')]),
        case("degraded_sandbox_compact", [file(f"{GH}/requirements.toml", 'sandbox="off"\n')]),
        case("degraded_sandbox_not_string", [file(f"{GH}/config.toml", "sandbox = false\n")]),
        case("degraded_comment_marker", [file(f"{GH}/config.toml", "# BYPASS_PERMISSIONS here\na = 1\n")]),
        case("degraded_comment_only", [file(f"{GH}/config.toml", "# always-approve\n")]),
        case(
            "degraded_unicode",
            [
                file(
                    f"{GH}/config.toml",
                    '"éclé" = "café \U0001f600 \\u0007 \\u007f"\n'
                    "n = [1.5, -0.0, inf, -inf, nan, 1e300, 12]\n"
                    'm = "\u212aEEP always\u2010approve"\n',
                )
            ],
        ),
        case("degraded_kelvin_raw", [file(f"{GH}/config.toml", 'a = 1\n# \u212a sandbox = "OFF"\n')]),
        case("datetime_refused", [file(f"{GH}/config.toml", "when = 1979-05-27\n")]),
        case("toml_invalid", [file(f"{GH}/config.toml", "[[\n")]),
        case("toml_bom", [raw(f"{GH}/config.toml", b'\xef\xbb\xbf[permission]\nallow = ["a"]\n')]),
        case("toml_invalid_utf8", [raw(f"{GH}/config.toml", b'a = "\xff"\n')]),
        case("toml_unreadable", [file(f"{GH}/config.toml", '[permission]\nallow = ["a"]\n', mode=0o000)]),
        case("config_is_directory", dirs=[f"{GH}/config.toml"]),
        case(
            "config_symlink",
            [file("elsewhere/c.toml", '[permission]\ndeny = ["z"]\n')],
            [link(f"{GH}/config.toml", "<ROOT>/elsewhere/c.toml")],
        ),
        case(
            "system_policy",
            [
                file(f"{SYSTEM}/managed_config.toml", "x = 1\n"),
                file(f"{SYSTEM}/requirements.toml", "x = 1\n"),
                file(f"{GH}/config.toml", 'sandbox = "off"\n'),
            ],
        ),
        case(
            "system_policy_unreadable",
            [
                file(f"{SYSTEM}/managed_config.toml", "x = 1\n", mode=0o000),
                file(f"{SYSTEM}/requirements.toml", "x = 1\n"),
            ],
        ),
        case(
            "hooks_dir",
            [
                doc(f"{GH}/hooks/a.json", HOOKS),
                doc(f"{GH}/hooks/b.json", {}),
                file(f"{GH}/hooks/c.json", "{"),
                doc(f"{GH}/hooks/d.json", {"hooks": ["x"]}),
                doc(f"{GH}/hooks/e.json", [{"hooks": {}}]),
                doc(f"{GH}/hooks/z.JSON", {"hooks": {"Stop": [{"hooks": [{"command": "upper"}]}]}}),
                doc(f"{GH}/hooks/.hidden.json", {"hooks": {"Stop": [{"hooks": [{"command": "hidden"}]}]}}),
                doc(f"{GH}/hooks/.json", {"hooks": {"Stop": [{"hooks": [{"command": "bare"}]}]}}),
                doc(f"{GH}/hooks/notes.txt", {"hooks": {"Stop": [{"hooks": [{"command": "txt"}]}]}}),
                doc(f"{GH}/hooks/nested/n.json", {"hooks": {"Stop": [{"hooks": [{"command": "nested"}]}]}}),
            ],
            dirs=[f"{GH}/hooks/dir.json"],
        ),
        case(
            "hooks_sort_order",
            [
                doc(f"{GH}/hooks/{name}.json", {"hooks": {"Stop": [{"hooks": [{"command": name}]}]}})
                for name in ["b", "C", "a-b", "a.b", "a", "é", "_", "10", "9"]
            ],
        ),
        case(
            "hooks_symlinks",
            [doc("pack/h.json", {"hooks": {"Stop": [{"hooks": [{"command": "linked"}]}]}})],
            [
                link(f"{GH}/hooks/linked.json", "<ROOT>/pack/h.json"),
                link(f"{GH}/hooks/dangling.json", "<ROOT>/pack/missing.json"),
            ],
        ),
        case("hooks_dir_is_file", [file(f"{GH}/hooks")]),
        case(
            "hooks_dir_unlistable",
            [doc(f"{GH}/hooks/a.json", {"hooks": {"Stop": [{"hooks": [{"command": "x"}]}]}})],
            dir_modes={f"{GH}/hooks": 0o300},
        ),
        case(
            "hooks_duplicate_keys",
            [
                file(
                    f"{GH}/hooks/a.json",
                    '{"hooks": {"Stop": [{"hooks": [{"command": "one"}]}], "Stop": [{"hooks": [{"command": "two"}]}]}}',
                )
            ],
        ),
        case("hooks_invalid_utf8", [raw(f"{GH}/hooks/a.json", b'{"hooks": {"\xff": []}}')]),
        case(
            "hooks_lone_surrogate_command",
            [file(f"{GH}/hooks/a.json", '{"hooks": {"Stop": [{"hooks": [{"command": "\\udc80"}]}]}}')],
        ),
        case(
            "project_root",
            [
                file(f"{GW}/config.toml", '[permission]\nallow = ["not-parsed"]\nsandbox = "off"\n'),
                doc(f"{GW}/hooks/p.json", {"hooks": {"PreToolUse": [{"hooks": [{"command": "project.sh"}]}]}}),
                doc(f"{GH}/hooks/g.json", {"hooks": {"PreToolUse": [{"hooks": [{"command": "global.sh"}]}]}}),
            ],
            dirs=[f"{GW}/skills", f"{GW}/agents"],
        ),
        case(
            "surfaces",
            [
                file(f"{GH}/hooks-paths", "x"),
                doc(f"{GH}/plugins/known_marketplaces.json", {"a": {"source": "x"}, "b": 1}),
                file(f"{GH}/sandbox.toml"),
                file(f"{GH}/trusted_folders.toml"),
                file(f"{GW}/sandbox.toml"),
                file("work/AGENTS.md"),
                file("work/CLAUDE.md"),
            ],
            [link(f"{GH}/agents", "<ROOT>/missing"), link(f"{GW}/personas", "<ROOT>/home")],
            dirs=[
                f"{GH}/skills",
                f"{GH}/plugins/marketplaces",
                f"{GH}/sessions",
                f"{GH}/personas",
                f"{GH}/workflows",
                f"{GW}/plugins",
                f"{GW}/hooks",
                f"{GW}/workflows",
                "home/.agents/skills",
                "home/.agents/commands",
            ],
        ),
        case("marketplace_empty", [doc(f"{GH}/plugins/known_marketplaces.json", {})]),
        case("marketplace_list", [doc(f"{GH}/plugins/known_marketplaces.json", [1, 2])]),
        case("marketplace_invalid", [file(f"{GH}/plugins/known_marketplaces.json", "{")]),
        case("marketplace_invalid_utf8", [raw(f"{GH}/plugins/known_marketplaces.json", b'{"\xff": 1}')]),
        case(
            "marketplace_duplicate_keys",
            [file(f"{GH}/plugins/known_marketplaces.json", '{"a": 1, "b": 2, "a": 3}')],
        ),
        case("instruction_directories", dirs=["work/AGENTS.md", "work/CLAUDE.md"]),
        case("instructions_no_workspace", [file("work/AGENTS.md")], workspace=None),
        case(
            "grok_home_env",
            [
                file("gh/.grok/config.toml", '[permission]\ndeny = ["g"]\n'),
                doc("gh/.grok/hooks/a.json", {"hooks": {"Stop": [{"hooks": [{"command": "gh.sh"}]}]}}),
                file(f"{GH}/config.toml", '[permission]\ndeny = ["ignored"]\n'),
            ],
            dirs=["home/.agents/skills", "gh/.agents/commands"],
            env={"GROK_HOME": "<ROOT>/gh"},
        ),
        case(
            "grok_home_env_symlink",
            [file("real/.grok/config.toml", '[permission]\ndeny = ["r"]\n')],
            [link("linkhome", "<ROOT>/real")],
            env={"GROK_HOME": "<ROOT>/linkhome"},
        ),
        case(
            "workspace_is_home",
            [
                doc(f"{GH}/hooks/a.json", {"hooks": {"Stop": [{"hooks": [{"command": "a.sh"}]}]}}),
                file(f"{GH}/config.toml", "a = 1\n"),
                file("home/AGENTS.md"),
            ],
            dirs=[f"{GH}/skills"],
            workspace="home",
        ),
        case(
            "relative_context",
            [
                file(f"{GH}/config.toml", '[permission]\ndeny = ["r"]\n'),
                doc(f"{GW}/hooks/a.json", {"hooks": {"Stop": [{"hooks": [{"command": "a.sh"}]}]}}),
                file("work/AGENTS.md"),
            ],
            dirs=[f"{GH}/skills"],
            relative=True,
        ),
        case(
            "home_is_cwd",
            [file(".grok/config.toml", '[permission]\ndeny = ["r"]\n'), doc(".grok/hooks/a.json", HOOKS)],
            dirs=[".agents/skills"],
            home=".",
            workspace=None,
            relative=True,
        ),
        case(
            "grok_root_unsearchable",
            [file(f"{GH}/config.toml", "a = 1\n")],
            dir_modes={GH: 0o000},
        ),
    ]
