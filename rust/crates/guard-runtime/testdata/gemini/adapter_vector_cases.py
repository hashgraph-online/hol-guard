"""Fixture cases for `record_adapter_vectors.py`: Gemini extensions, settings,
hooks and skills, and Antigravity's extension index, MCP bridges, skills and
editor settings; the Grok and Kimi cases live in their own modules. Paths are
relative to the fixture root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

import json

G_HOME = "home/.gemini"
G_WORK = "work/.gemini"
A_INDEX = "home/.antigravity/extensions/extensions.json"
A_BRIDGE = "home/.gemini/antigravity/mcp_config.json"
A_WORK_BRIDGE = "work/.gemini/antigravity/mcp_config.json"
A_MACOS = "home/Library/Application Support/Antigravity/User/settings.json"
A_XDG = "home/.config/Antigravity/User/settings.json"
A_WINDOWS = "home/AppData/Roaming/Antigravity/User/settings.json"
A_VSCODE = "work/.vscode/settings.json"
SKILL = "---\nname: s\ndescription: A skill\n---\nbody\n"


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
    env: dict[str, str] | None = None,
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
        "env": env or {},
    }


SERVERS = {
    "local": {"command": "node", "args": ["a", 1, None, "b"]},
    "remote": {"url": "https://mcp.example/x", "command": 5},
    "args_not_list": {"command": "c", "args": "abc"},
    "bare": {},
    "not_dict": "x",
    "list_config": ["y"],
}

HOOKS = {
    "BeforeTool": [
        {"command": "direct.sh"},
        {"hooks": [{"type": "command", "command": "a.sh"}, {"command": 4}, "x", {"command": "b.sh"}]},
        {"command": "both.sh", "hooks": [{"command": "nested.sh"}], "matcher": "write_file", "timeout": 30},
        {"type": "other", "n": 1.5, "flag": True, "none": None},
        {"hooks": []},
        "not-a-dict",
        7,
    ],
    "AfterAgent": {"command": "x"},
    "SessionStart": [{"command": 42}],
    "ÄUpper": [{"command": "u.sh"}],
}


def skills(base: str) -> list[dict]:
    return [
        file(f"{base}/alpha/SKILL.md", SKILL),
        file(f"{base}/alpha/notes.txt", "n"),
        file(f"{base}/group/beta/SKILL.md", SKILL),
        file(f"{base}/.hidden/SKILL.md", SKILL),
        file(f"{base}/plain/readme.md", "r"),
    ]


def gemini_cases() -> list[dict]:
    return [
        case("nothing"),
        case("no_workspace", [doc(f"{G_HOME}/settings.json", {"mcpServers": SERVERS})], workspace=None),
        case("settings_servers", [doc(f"{G_HOME}/settings.json", {"mcpServers": SERVERS})]),
        case("settings_hooks", [doc(f"{G_WORK}/settings.json", {"hooks": HOOKS})]),
        case("settings_hooks_not_dict", [doc(f"{G_HOME}/settings.json", {"hooks": ["x"], "mcpServers": []})]),
        case("settings_empty_object", [doc(f"{G_HOME}/settings.json", {})]),
        case("settings_invalid_json", [file(f"{G_HOME}/settings.json", "{nope")]),
        case("settings_top_level_list", [doc(f"{G_HOME}/settings.json", [{"mcpServers": SERVERS}])]),
        case("settings_bom", [raw(f"{G_HOME}/settings.json", b'\xef\xbb\xbf{"mcpServers": {"b": {}}}')]),
        case("settings_invalid_utf8", [raw(f"{G_HOME}/settings.json", b'{"mcpServers": {"\xff": {}}}')]),
        case("settings_unreadable", [file(f"{G_HOME}/settings.json", '{"mcpServers": {"u": {}}}', mode=0o000)]),
        case("settings_is_directory", dirs=[f"{G_HOME}/settings.json"]),
        case(
            "settings_duplicate_keys",
            [
                file(
                    f"{G_HOME}/settings.json",
                    '{"mcpServers": {"d": {"command": "one"}, "e": {}, "d": {"command": "two"}}}',
                )
            ],
        ),
        case(
            "settings_escaped_text",
            [file(f"{G_HOME}/settings.json", '{"mcpServers": {"caf\\u00e9 \\ud83d\\ude00": {"command": "\\u00e9"}}}')],
        ),
        case(
            "settings_lone_surrogate_server",
            [file(f"{G_HOME}/settings.json", '{"mcpServers": {"\\ud800": {}}}')],
        ),
        case(
            "settings_lone_surrogate_unused",
            [file(f"{G_HOME}/settings.json", '{"other": "\\ud800", "mcpServers": {"ok": {}}}')],
        ),
        case(
            "settings_deep_nesting",
            [file(f"{G_HOME}/settings.json", '{"mcpServers": {}, "x": ' + "[" * 600 + "]" * 600 + "}")],
        ),
        case(
            "settings_symlink",
            [doc("elsewhere/settings.json", {"mcpServers": {"linked": {"command": "l"}}})],
            [link(f"{G_HOME}/settings.json", "<ROOT>/elsewhere/settings.json")],
        ),
        case(
            "extensions_matrix",
            [
                doc(
                    f"{G_HOME}/extensions/zeta/gemini-extension.json",
                    {
                        "name": "Zeta Ext",
                        "publisher": "acme",
                        "contextFileName": "GEMINI.md",
                        "mcpServers": SERVERS,
                    },
                ),
                doc(f"{G_HOME}/extensions/alpha/gemini-extension.json", {"version": "1", "publisher": 3}),
                doc(f"{G_HOME}/extensions/.hidden/gemini-extension.json", {"name": 7, "contextFileName": ["a", 1]}),
                doc(f"{G_HOME}/extensions/Beta/gemini-extension.json", {"contextFileName": {"k": [1, 2.5, None]}}),
                doc(f"{G_HOME}/extensions/empty/gemini-extension.json", {}),
                file(f"{G_HOME}/extensions/broken/gemini-extension.json", "{"),
                doc(f"{G_HOME}/extensions/listy/gemini-extension.json", ["x"]),
                file(f"{G_HOME}/extensions/nomanifest/readme.md"),
                doc(f"{G_HOME}/extensions/deep/inner/gemini-extension.json", {"name": "deep"}),
                doc(f"{G_HOME}/extensions/gemini-extension.json", {"name": "root-level"}),
                doc(f"{G_HOME}/extensions/servers-bad/gemini-extension.json", {"name": "sb", "mcpServers": ["x"]}),
            ],
        ),
        case(
            "extensions_workspace_and_home",
            [
                doc(f"{G_HOME}/extensions/one/gemini-extension.json", {"name": "one"}),
                doc(f"{G_WORK}/extensions/two/gemini-extension.json", {"name": "two", "mcpServers": {"s": {}}}),
                doc(f"{G_WORK}/settings.json", {"mcpServers": {"w": {"url": "http://w"}}}),
            ],
        ),
        case(
            "extensions_symlinks",
            [doc("pack/linked/gemini-extension.json", {"name": "linked"}), file("pack/file.txt")],
            [
                link(f"{G_HOME}/extensions/linked", "<ROOT>/pack/linked"),
                link(f"{G_HOME}/extensions/afile", "<ROOT>/pack/file.txt"),
                link(f"{G_HOME}/extensions/dangling", "<ROOT>/pack/missing"),
                link(f"{G_HOME}/extensions/real/gemini-extension.json", "<ROOT>/pack/linked/gemini-extension.json"),
            ],
        ),
        case(
            "extensions_root_is_symlink",
            [doc("pack/e/gemini-extension.json", {"name": "via-root"})],
            [link(f"{G_HOME}/extensions", "<ROOT>/pack")],
        ),
        case("extensions_root_is_file", [file(f"{G_HOME}/extensions")]),
        case(
            "extensions_unreadable_root",
            [doc(f"{G_HOME}/extensions/x/gemini-extension.json", {"name": "x"})],
            dir_modes={f"{G_HOME}/extensions": 0o300},
        ),
        case(
            "extensions_unreadable_child",
            [
                doc(f"{G_HOME}/extensions/x/gemini-extension.json", {"name": "x"}),
                doc(f"{G_HOME}/extensions/y/gemini-extension.json", {"name": "y"}),
            ],
            dir_modes={f"{G_HOME}/extensions/x": 0o000},
        ),
        case(
            "extensions_sort_order",
            [
                doc(f"{G_HOME}/extensions/{name}/gemini-extension.json", {"publisher": name})
                for name in ["b", "C", "a-b", "a.b", "a", "é", "_", "10", "9"]
            ],
        ),
        case(
            "extensions_duplicate_names",
            [
                doc(f"{G_HOME}/extensions/a/gemini-extension.json", {"name": "same", "mcpServers": {"s": {}}}),
                doc(f"{G_HOME}/extensions/b/gemini-extension.json", {"name": "same", "mcpServers": {"s": {}}}),
            ],
        ),
        case("skills_home_and_workspace", [*skills(f"{G_HOME}/skills"), *skills(f"{G_WORK}/skills")]),
        case("skill_at_root", [file(f"{G_HOME}/skills/SKILL.md", SKILL), file(f"{G_HOME}/skills/x.md")]),
        case(
            "skills_symlinked",
            [file("pack/s/SKILL.md", SKILL), file(f"{G_HOME}/skills/ok/SKILL.md", SKILL)],
            [
                link(f"{G_HOME}/skills/linked", "<ROOT>/pack/s"),
                link(f"{G_HOME}/skills/ok/extra.md", "<ROOT>/pack/s/SKILL.md"),
            ],
        ),
        case(
            "skills_root_symlinked",
            [file("pack/s/SKILL.md", SKILL)],
            [link(f"{G_HOME}/skills", "<ROOT>/pack")],
        ),
        case(
            "skills_unreadable",
            [
                file(f"{G_HOME}/skills/a/SKILL.md", SKILL),
                file(f"{G_HOME}/skills/a/data.bin", "d", mode=0o000),
                file(f"{G_HOME}/skills/locked/b/SKILL.md", SKILL),
            ],
            dir_modes={f"{G_HOME}/skills/locked": 0o000},
        ),
        case(
            "workspace_is_home",
            [
                *skills(f"{G_HOME}/skills"),
                doc(f"{G_HOME}/settings.json", {"mcpServers": {"h": {}}}),
                doc(f"{G_HOME}/extensions/e/gemini-extension.json", {"name": "e"}),
            ],
            workspace="home",
        ),
        case(
            "workspace_inside_home",
            [
                doc("home/proj/.gemini/settings.json", {"mcpServers": {"p": {}}}),
                doc(f"{G_HOME}/settings.json", {"mcpServers": {"h": {}}}),
            ],
            workspace="home/proj",
        ),
        case(
            "everything",
            [
                doc(
                    f"{G_HOME}/settings.json",
                    {"mcpServers": {"s": {"command": "c"}}, "hooks": {"Notification": [{"command": "n"}]}},
                ),
                doc(f"{G_HOME}/extensions/e/gemini-extension.json", {"name": "e", "mcpServers": {"m": {"url": "u"}}}),
                *skills(f"{G_HOME}/skills"),
                doc(f"{G_WORK}/settings.json", {"hooks": {"BeforeModel": [{"hooks": [{"command": "x"}]}]}}),
                *skills(f"{G_WORK}/skills"),
            ],
        ),
        case(
            "relative_context",
            [
                doc(f"{G_HOME}/settings.json", {"mcpServers": {"r": {}}}),
                doc(f"{G_WORK}/extensions/e/gemini-extension.json", {"name": "e"}),
            ],
            relative=True,
        ),
        case("relative_context_with_skills", [file(f"{G_HOME}/skills/a/SKILL.md", SKILL)], relative=True),
        case(
            "hook_config_huge_integer_unused", [file(f"{G_HOME}/settings.json", '{"hooks": {}, "n": ' + "9" * 30 + "}")]
        ),
    ]


def antigravity_cases() -> list[dict]:
    index_items = [
        {
            "identifier": {"id": "acme.full"},
            "location": {"path": "<ROOT>/ext/full"},
            "metadata": {"publisherDisplayName": "Acme Inc"},
        },
        {
            "identifier": {"id": "acme.fallback"},
            "location": {"path": "<ROOT>/ext/fallback"},
            "metadata": {"publisherDisplayName": "Fallback Co"},
        },
        {"identifier": {"id": "acme.blank"}, "location": {"path": "<ROOT>/ext/blank"}},
        {"identifier": {"id": "acme.missing"}, "location": {"path": "<ROOT>/ext/missing"}, "metadata": "x"},
        {"identifier": {"id": "acme.relative"}, "location": {"path": "ext/relative"}},
        {"identifier": {"id": "acme.dup"}, "location": {"path": "<ROOT>/ext/full"}},
        {"identifier": {"id": 5}, "location": {"path": "<ROOT>/ext/full"}},
        {"identifier": "acme.str", "location": {"path": "<ROOT>/ext/full"}},
        {"identifier": {"id": "acme.nopath"}, "location": {"fsPath": "<ROOT>/ext/full"}},
        "not-a-dict",
        {"identifier": {"id": "acme.empty-path"}, "location": {"path": ""}},
    ]
    return [
        case("nothing"),
        case(
            "index_matrix",
            [
                doc(A_INDEX, index_items),
                doc("ext/full/package.json", {"displayName": "Full", "description": "D", "publisher": "acme"}),
                doc("ext/fallback/package.json", {"displayName": 3, "description": None, "publisher": None}),
                doc("ext/blank/package.json", {"displayName": "", "description": "only"}),
                doc("ext/relative/package.json", {"displayName": "Rel"}),
                doc("package.json", {"displayName": "Cwd"}),
            ],
        ),
        case("index_empty_list", [doc(A_INDEX, [])]),
        case("index_object", [doc(A_INDEX, {"identifier": {"id": "x"}})]),
        case("index_invalid_json", [file(A_INDEX, "[")]),
        case("index_invalid_utf8", [raw(A_INDEX, b'["\xff"]')]),
        case("index_is_directory", dirs=[A_INDEX]),
        case("index_only_junk", [doc(A_INDEX, [1, None, "x"])]),
        case(
            "index_manifest_invalid",
            [
                doc(A_INDEX, [{"identifier": {"id": "a.b"}, "location": {"path": "<ROOT>/ext/x"}}]),
                file("ext/x/package.json", "{"),
            ],
        ),
        case(
            "index_location_nul",
            [doc(A_INDEX, [{"identifier": {"id": "a.b"}, "location": {"path": "<ROOT>/ext/x\u0000y"}}])],
        ),
        case(
            "bridges",
            [
                doc(
                    A_BRIDGE,
                    {"mcpServers": {"g": {"command": "gc", "args": ["1", 2]}, "u": {"url": "https://u"}, "bad": 1}},
                ),
                doc(A_WORK_BRIDGE, {"mcpServers": {"w": {}}}),
            ],
        ),
        case("bridge_empty", [doc(A_BRIDGE, {})]),
        case("skills", [*skills("home/.gemini/antigravity/skills"), *skills("work/.gemini/antigravity/skills")]),
        case(
            "settings_owned",
            [
                doc(A_MACOS, {"mcpServers": {"mac": {"command": "m"}}}),
                doc(A_XDG, {"editor.fontSize": 12}),
                doc(A_WINDOWS, {"mcpServers": {"win": {"url": "https://w"}}}),
            ],
        ),
        case("vscode_without_signal", [doc(A_VSCODE, {"mcpServers": {"v": {}}})]),
        case("vscode_with_antigravity_key", [doc(A_VSCODE, {"antigravity.enabled": True, "mcpServers": {"v": {}}})]),
        case("vscode_with_bridge_signal", [doc(A_BRIDGE, {"x": 1}), doc(A_VSCODE, {"mcpServers": {"v": {}}})]),
        case("vscode_with_owned_signal", [doc(A_XDG, {"a": 1}), doc(A_VSCODE, {"mcpServers": {"v": {}}})]),
        case("vscode_empty", [doc(A_BRIDGE, {"x": 1}), doc(A_VSCODE, {})]),
        case("vscode_no_workspace", [doc(A_MACOS, {"x": 1})], workspace=None),
        case(
            "vscode_with_skill_signal",
            [file("home/.gemini/antigravity/skills/a/SKILL.md", SKILL), doc(A_VSCODE, {"mcpServers": {"v": {}}})],
        ),
        case(
            "same_server_names",
            [
                doc(A_BRIDGE, {"mcpServers": {"same": {}}}),
                doc(A_MACOS, {"mcpServers": {"same": {}}}),
                doc(A_XDG, {"mcpServers": {"same": {}}}),
                doc(A_VSCODE, {"mcpServers": {"same": {}}}),
            ],
        ),
        case(
            "workspace_is_home",
            [
                doc(A_BRIDGE, {"mcpServers": {"h": {}}}),
                *skills("home/.gemini/antigravity/skills"),
                doc("home/.vscode/settings.json", {"mcpServers": {"v": {}}}),
            ],
            workspace="home",
        ),
        case(
            "relative_context",
            [
                doc(A_BRIDGE, {"mcpServers": {"r": {}}}),
                doc(A_VSCODE, {"mcpServers": {"v": {}}}),
                doc(A_XDG, {"mcpServers": {"x": {}}}),
            ],
            relative=True,
        ),
        case(
            "home_is_cwd",
            [
                doc(".gemini/antigravity/mcp_config.json", {"mcpServers": {"r": {}}}),
                doc("Library/Application Support/Antigravity/User/settings.json", {"mcpServers": {"m": {}}}),
                doc(".config/Antigravity/User/settings.json", {"mcpServers": {"x": {}}}),
                doc("AppData/Roaming/Antigravity/User/settings.json", {"mcpServers": {"w": {}}}),
            ],
            home=".",
            workspace=None,
            relative=True,
        ),
        case(
            "workspace_is_cwd",
            [doc(".vscode/settings.json", {"antigravity.x": 1, "mcpServers": {"v": {}}})],
            workspace=".",
            relative=True,
        ),
        case("lone_surrogate_server", [file(A_BRIDGE, '{"mcpServers": {"\\udc80": {}}}')]),
    ]


def gemini_extra() -> list[dict]:
    return [
        case(
            "home_is_cwd",
            [
                doc(".gemini/settings.json", {"mcpServers": {"r": {}}}),
                doc(".gemini/extensions/e/gemini-extension.json", {"name": "e"}),
            ],
            home=".",
            workspace=None,
            relative=True,
        ),
        case("hook_lone_surrogate", [file(f"{G_HOME}/settings.json", '{"hooks": {"X": [{"command": "\\udc80"}]}}')]),
        case(
            "extension_name_lone_surrogate",
            [file(f"{G_HOME}/extensions/e/gemini-extension.json", '{"name": "\\ud800"}')],
        ),
    ]


def cases(harness: str) -> list[dict]:
    if harness == "devin":
        from devin_vector_cases import devin_cases

        return devin_cases()
    if harness == "grok":
        from grok_vector_cases import grok_cases

        return grok_cases()
    if harness == "opencode":
        from opencode_vector_cases import opencode_cases

        return opencode_cases()
    if harness == "cursor":
        from cursor_vector_cases import cursor_cases

        return cursor_cases()
    if harness == "kimi":
        from kimi_vector_cases import kimi_cases

        return kimi_cases()
    return gemini_cases() + gemini_extra() if harness == "gemini" else antigravity_cases()
