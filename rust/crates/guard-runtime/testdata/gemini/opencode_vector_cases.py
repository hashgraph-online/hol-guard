"""OpenCode fixture cases for `record_adapter_vectors.py`: the MCP servers,
plugins and commands of each config, the command and plugin directories, the
`OPENCODE_CONFIG`/`OPENCODE_CONFIG_DIR` overrides and the skill roots. A case
with `snapshot` runs the install snapshot (normalized payloads, Guard
companions kept) instead of `detect`. Paths are relative to the fixture root;
`<ROOT>` stands for it in contents and the environment.
"""

from __future__ import annotations

from adapter_vector_cases import SKILL, case, doc, file, link

OC = "home/.config/opencode"
PROXY = ["hol-guard", "opencode-mcp-proxy", "--server", "x"]

MCP = {
    "list_command": {"command": ["node", "server.js", 3, "--flag"], "args": ["ignored"]},
    "empty_list": {"command": [1, None]},
    "str_command": {"command": "uvx", "args": ["tool", 2, "x"], "environment": {"A": "1", "B": 2, "C": None}},
    "args_not_list": {"command": "uvx", "args": "abc", "environment": ["x"]},
    "no_command": {"command": 7, "url": 5},
    "remote": {"type": "remote", "url": "https://mcp.example/x", "enabled": False},
    "url_only": {"url": "https://mcp.example/y", "enabled": 0},
    "blank_type": {"type": "", "command": "c", "enabled": ""},
    "type_local": {"type": "local", "command": ["c"], "enabled": [1]},
    "enabled_null": {"command": "c", "enabled": None},
    "hol-guard::companion": {"command": PROXY},
    "hol-guard::plain": {"command": "node"},
    "guard_proxy": {"command": "/usr/bin/hol-guard", "args": ["opencode-mcp-proxy"]},
    "module_proxy": {"command": "python", "args": ["-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]},
    "not_dict": "x",
    "list_config": ["y"],
}

PLUGINS = [
    "plain-plugin",
    "@acme/scoped",
    "@noslash",
    ["with-options", {"b": 1, "a": [1.5, True, None], "nested": {"z": "q"}}],
    ["bad-options", "x"],
    [1, {}],
    ["too", {}, "long"],
    5,
    None,
]

COMMANDS = {
    "review": {"template": "Review $ARGUMENTS", "description": "d", "agent": "build", "model": None, "subtask": True},
    "numbers": {"template": " t ", "description": 3, "model": [1, "m"], "agent": {"k": "v"}},
    "blank": {"template": "   "},
    "no_template": {"description": "x"},
    "bad_template": {"template": 4},
    "not_dict": "x",
}

CONFIG = {"mcp": MCP, "plugin": PLUGINS, "plugins": ["first-list"], "command": COMMANDS}

JSONC = """{
  // a comment
  "mcp": {"commented": {"command": ["node"]}},
  /* block */
  "plugin": ["jsonc-plugin"]
}
"""


def opencode_cases() -> list[dict]:
    return [
        case("nothing"),
        case("global_config", [doc(f"{OC}/opencode.json", CONFIG)]),
        case("no_workspace", [doc(f"{OC}/opencode.json", CONFIG)], workspace=None),
        case("workspace_config", [doc("work/opencode.json", {"mcp": {"w": {"command": "w"}}})]),
        case(
            "jsonc_files",
            [file(f"{OC}/opencode.jsonc", JSONC), file("work/opencode.json", '{"plugin": ["x"]} // tail\n')],
        ),
        case(
            "skipped_configs",
            [
                file(f"{OC}/opencode.json", "{not json"),
                doc(f"{OC}/opencode.jsonc", {}),
                doc("work/opencode.json", ["list"]),
                file("work/opencode.jsonc", ""),
            ],
        ),
        case(
            "non_dict_sections",
            [doc(f"{OC}/opencode.json", {"mcp": ["x"], "plugin": {"a": 1}, "plugins": "p", "command": ["c"]})],
        ),
        case(
            "duplicate_ids",
            [
                doc(
                    f"{OC}/opencode.json",
                    {"mcp": {"plugin:dup": {"command": "a"}}, "plugin": ["dup", "other"], "plugins": ["other"]},
                ),
                doc(f"{OC}/opencode.jsonc", {"mcp": {"plugin:dup": {"command": "b"}}}),
            ],
        ),
        case(
            "config_env_relative",
            [doc("work/custom/oc.json", {"mcp": {"env": {"command": "e"}}})],
            env={"OPENCODE_CONFIG": "custom/oc.json"},
        ),
        case(
            "config_env_absolute",
            [doc("elsewhere/oc.json", {"plugin": ["abs"]})],
            env={"OPENCODE_CONFIG": "<ROOT>/elsewhere/oc.json"},
        ),
        case(
            "config_env_duplicates_home",
            [doc(f"{OC}/opencode.json", {"plugin": ["dup-path"]})],
            env={"OPENCODE_CONFIG": f"<ROOT>/{OC}/opencode.json"},
        ),
        case(
            "directories",
            [
                file(f"{OC}/commands/top.md", "top"),
                file(f"{OC}/commands/nested/deep/inner.md", "inner"),
                file(f"{OC}/commands/notes.txt"),
                file(f"{OC}/commands/.md"),
                file(f"{OC}/commands/two.dots.md"),
                file(f"{OC}/commands/Z.md"),
                file(f"{OC}/commands/a.md"),
                file(f"{OC}/plugins/a.ts", "ts"),
                file(f"{OC}/plugins/b.js"),
                file(f"{OC}/plugins/c.mjs"),
                file(f"{OC}/plugins/d.cjs"),
                file(f"{OC}/plugins/e.tsx"),
                file(f"{OC}/plugins/.ts"),
                file(f"{OC}/plugins/hol-guard-pretool.ts", "guard"),
                file(f"{OC}/plugins/sub/hol-guard-pretool.ts", "nested guard"),
                file(f"{OC}/plugin/legacy.js"),
                file("work/.opencode/commands/proj.md"),
                file("work/.opencode/plugins/proj.ts"),
                file("work/.opencode/plugin/old.cjs"),
                file("outside/linked.md", "linked"),
            ],
            [
                link(f"{OC}/commands/linked-dir", "<ROOT>/outside"),
                link(f"{OC}/commands/linked.md", "<ROOT>/outside/linked.md"),
                link(f"{OC}/commands/broken.md", "<ROOT>/missing.md"),
            ],
        ),
        case(
            "directory_is_symlink",
            [file("outside/cmds/viadir.md", "v")],
            [link(f"{OC}/commands", "<ROOT>/outside/cmds")],
        ),
        case(
            "directory_is_file",
            [file(f"{OC}/commands", "not a dir"), file("work/.opencode/plugins", "nope")],
        ),
        case(
            "unreadable_entries",
            [
                file(f"{OC}/commands/locked.md", "secret", mode=0o000),
                file(f"{OC}/commands/closed/inside.md"),
                file(f"{OC}/commands/open.md"),
            ],
            dir_modes={f"{OC}/commands/closed": 0o000},
        ),
        case(
            "config_dir_project",
            [file("work/conf/commands/c.md"), file("work/conf/plugins/p.ts"), file("work/conf/plugin/q.js")],
            env={"OPENCODE_CONFIG_DIR": "conf"},
        ),
        case(
            "config_dir_global",
            [file("cfg/commands/c.md"), file("cfg/plugins/p.ts")],
            env={"OPENCODE_CONFIG_DIR": "<ROOT>/cfg"},
        ),
        case(
            "config_dir_duplicates_workspace",
            [file("work/.opencode/commands/same.md", "s"), file("work/.opencode/plugins/same.ts")],
            env={"OPENCODE_CONFIG_DIR": "<ROOT>/work/.opencode"},
        ),
        case(
            "skills",
            [
                file(f"{OC}/skills/alpha/SKILL.md", SKILL),
                file(f"{OC}/skills/SKILL.md", SKILL),
                file(f"{OC}/skills/group/beta/SKILL.md", SKILL),
                file(f"{OC}/skills/alpha/notes.md"),
                file(f"{OC}/skill/legacy/SKILL.md", SKILL),
                file("home/.claude/skills/c/SKILL.md", SKILL),
                file("home/.agents/skills/a/SKILL.md", SKILL),
                file("home/.agents/skills/lower/skill.md", SKILL),
                file("work/.opencode/skills/p/SKILL.md", SKILL),
                file("work/.opencode/skill/q/SKILL.md", SKILL),
                file("work/.claude/skills/c/SKILL.md", SKILL),
                file("work/.agents/skills/a/SKILL.md", "x", mode=0o000),
            ],
        ),
        case(
            "skills_no_workspace",
            [file(f"{OC}/skills/alpha/SKILL.md", SKILL), file("work/.opencode/skills/p/SKILL.md", SKILL)],
            workspace=None,
        ),
        case(
            "workspace_inside_home",
            [file("home/proj/.claude/skills/x/SKILL.md", SKILL), file("home/.claude/skills/y/SKILL.md", SKILL)],
            workspace="home/proj",
        ),
        case(
            "relative_paths",
            [
                doc(f"{OC}/opencode.json", {"plugin": ["rel"]}),
                file(f"{OC}/commands/r.md"),
                file("work/.opencode/skills/s/SKILL.md", SKILL),
            ],
            relative=True,
        ),
        case(
            "lone_surrogate_name",
            [file(f"{OC}/opencode.json", '{"mcp": {"bad\\ud800": {"command": "x"}}}')],
        ),
        case(
            "unicode_names",
            [
                doc(f"{OC}/opencode.json", {"mcp": {"ÄServer": {"command": "ü"}}, "plugin": ["@äcme/p"]}),
                file(f"{OC}/commands/é.md"),
                file(f"{OC}/commands/e.md"),
            ],
        ),
        snapshot_case(
            "snapshot_companions",
            [
                doc(
                    f"{OC}/opencode.json",
                    {"mcp": {"hol-guard::companion": {"command": PROXY}, "plain": {"command": "p"}}},
                )
            ],
        ),
        snapshot_case("snapshot_full", [doc(f"{OC}/opencode.json", CONFIG), file(f"{OC}/commands/s.md")]),
    ]


def snapshot_case(name: str, files: list[dict]) -> dict:
    spec = case(name, files)
    spec["snapshot"] = True
    return spec
