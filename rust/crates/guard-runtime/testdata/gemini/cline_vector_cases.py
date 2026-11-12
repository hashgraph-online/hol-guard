"""Cline fixture cases for `record_adapter_vectors.py`: the VS Code and
JetBrains host installs, the MCP servers of the settings files Python names
and the hook and plugin directories. Paths are relative to the fixture root;
`<ROOT>` stands for it in contents and in a case's environment.
"""

from __future__ import annotations

import json

from adapter_vector_cases import case, doc, file, link, raw

HOME = "home"
CURRENT = "home/.cline/data/settings/cline_mcp_settings.json"
LEGACY = "home/.cline/settings/cline_mcp_settings.json"
MACOS = "home/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
LINUX = "home/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
WINDOWS = "home/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
PROXY = ["hol-guard", "mcp-proxy", "--server", "x"]

SERVERS = {
    "local": {"command": "node", "args": ["a", 1, None, "b", True], "env": {"A": "1", " B ": "2", "": "x", "C": 3}},
    "remote": {"url": "https://mcp.example/x?token=abc", "headers": {"Authorization": "t", " X ": "y", "N": 1}},
    "endpoint": {"endpoint": "https://mcp.example/e", "type": " SSE "},
    "environment": {"command": "uvx", "environment": {"Z": "z", "A": "a"}},
    "env_not_dict": {"command": "uvx", "env": ["x"], "environment": {"E": "e"}},
    "env_null": {"command": "uvx", "env": None, "environment": {"E": "e"}},
    "both": {"command": "c", "env": {"K": "env"}, "environment": {"K": "environment"}},
    "dup_keys": {"command": "c", "env": {"K": "1", " K": "2", "K ": "3"}},
    "args_str": {"command": "c", "args": "abc"},
    "args_dict": {"command": "c", "args": {"x": 1}},
    "non_str_command": {"command": 5, "url": 7},
    "url_and_command": {"command": "c", "url": "https://mcp.example/y"},
    "guard_proxy": {"command": "hol-guard", "args": PROXY},
    "disabled": {"command": "c", "disabled": True},
    "disabled_text": {"command": "c", "disabled": "true"},
    "enabled": {"command": "c", "disabled": False},
    "bare": {},
    "not_dict": "x",
    "list_config": ["y"],
}

TRANSPORTS = {
    "type_wins": {"command": "c", "type": "STDIO", "transport": "sse", "url": "https://x"},
    "transport_second": {"command": "c", "type": "", "transport": " Streamable-HTTP "},
    "type_not_str": {"url": "https://x", "type": 5, "transport": "sse"},
    "type_blank": {"command": "c", "type": "   "},
    "url_blank": {"command": "c", "url": "   "},
    "url_empty_endpoint": {"command": "c", "url": "", "endpoint": "https://e"},
    "url_empty_endpoint_empty": {"command": "c", "url": "", "endpoint": ""},
    "url_not_str_endpoint": {"command": "c", "url": 3, "endpoint": "https://e"},
    "url_null": {"command": "c", "url": None, "endpoint": 5},
    "type_null_transport": {"command": "c", "type": None, "transport": "local"},
}

REDACTION = {
    "secrets": {
        "command": "python",
        "args": [
            "--token=abc123",
            "Authorization: Bearer abcdefghijklmnop",
            "bearer xyz",
            "--api-key=k",
            "api-key: k",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "password=hunter2",
            "secret=s",
            "plain",
        ],
    },
}


def manifest(version: object) -> str:
    return json.dumps({"name": "claude-dev", "version": version})


def extension(editor: str, name: str, version: object = "3.1.0") -> dict:
    return file(f"home/{editor}/extensions/{name}/package.json", manifest(version))


def plugin(root: str, ide: str, name: str) -> dict:
    return file(f"home/{root}/JetBrains/{ide}/plugins/{name}/plugin.xml", "<idea-plugin/>")


def cline_cases() -> list[dict]:
    return [
        case("nothing"),
        case("no_workspace", [doc(CURRENT, {"mcpServers": SERVERS})], workspace=None),
        # MCP settings
        case("current_servers", [doc(CURRENT, {"mcpServers": SERVERS})]),
        case("legacy_servers", [doc(LEGACY, {"mcpServers": SERVERS})]),
        case("macos_servers", [doc(MACOS, {"mcpServers": {"m": {"command": "m"}}})]),
        case("linux_servers", [doc(LINUX, {"mcpServers": {"l": {"command": "l"}}})]),
        case("windows_servers", [doc(WINDOWS, {"mcpServers": {"w": {"command": "w"}}})]),
        case(
            "every_candidate",
            [
                doc(CURRENT, {"mcpServers": {"same": {"command": "current"}}}),
                doc(LEGACY, {"mcpServers": {"same": {"command": "legacy"}}}),
                doc(MACOS, {"mcpServers": {"mac": {"command": "mac"}}}),
                doc(LINUX, {"mcpServers": {}}),
                doc(WINDOWS, {"mcpServers": {"win": {"command": "win"}}}),
            ],
        ),
        case("transports", [doc(CURRENT, {"mcpServers": TRANSPORTS})]),
        case("redaction", [doc(CURRENT, {"mcpServers": REDACTION})]),
        case("mcp_key", [doc(CURRENT, {"mcp": {"viaMcp": {"command": "x"}}})]),
        case(
            "mcp_servers_wins",
            [doc(CURRENT, {"mcpServers": {"first": {"command": "a"}}, "mcp": {"second": {"command": "b"}}})],
        ),
        case(
            "mcp_servers_empty_dict_wins",
            [doc(CURRENT, {"mcpServers": {}, "mcp": {"second": {"command": "b"}}})],
        ),
        case(
            "mcp_servers_not_dict_falls_back",
            [doc(CURRENT, {"mcpServers": ["x"], "mcp": {"second": {"command": "b"}}})],
        ),
        case("mcp_servers_null_falls_back", [doc(CURRENT, {"mcpServers": None, "mcp": {"s": {"command": "b"}}})]),
        case("no_servers_key", [doc(CURRENT, {"other": 1})]),
        case("settings_empty_object", [doc(CURRENT, {})]),
        case("settings_top_level_list", [doc(CURRENT, [{"mcpServers": SERVERS}])]),
        case("settings_invalid_json", [file(CURRENT, "{nope")]),
        case("settings_bom", [raw(CURRENT, b'\xef\xbb\xbf{"mcpServers": {"b": {}}}')]),
        case("settings_invalid_utf8", [raw(CURRENT, b'{"mcpServers": {"\xff": {}}}')]),
        case("settings_unreadable", [file(CURRENT, '{"mcpServers": {"u": {}}}', mode=0o000)]),
        case("settings_is_directory", dirs=[CURRENT]),
        case(
            "settings_symlink",
            [doc("elsewhere/mcp.json", {"mcpServers": {"linked": {"command": "l"}}})],
            [link(CURRENT, "<ROOT>/elsewhere/mcp.json")],
        ),
        case("settings_dangling_symlink", symlinks=[link(CURRENT, "<ROOT>/elsewhere/missing.json")]),
        case(
            "settings_duplicate_keys",
            [file(CURRENT, '{"mcpServers": {"d": {"command": "one"}, "e": {}, "d": {"command": "two"}}}')],
        ),
        case(
            "settings_escaped_text",
            [file(CURRENT, '{"mcpServers": {"caf\\u00e9 \\ud83d\\ude00": {"command": "\\u00e9", "args": ["\\u00e9"]}}}')],
        ),
        case("settings_lone_surrogate_name", [file(CURRENT, '{"mcpServers": {"\\ud800": {}}}')]),
        case(
            "settings_lone_surrogate_env_value",
            [file(CURRENT, '{"mcpServers": {"s": {"command": "c", "env": {"K": "\\udc80"}}}}')],
        ),
        case(
            "settings_lone_surrogate_unused",
            [file(CURRENT, '{"other": "\\ud800", "mcpServers": {"ok": {}}}')],
        ),
        case(
            "settings_nan_args",
            [file(CURRENT, '{"mcpServers": {"n": {"command": "x", "args": [NaN, Infinity, "ok"]}}}')],
        ),
        case(
            "settings_deep_nesting",
            [file(CURRENT, '{"mcpServers": {}, "x": ' + "[" * 600 + "]" * 600 + "}")],
        ),
        case(
            "explicit_settings_path",
            [doc("elsewhere/explicit.json", {"mcpServers": {"explicit": {"command": "e"}}})],
            env={"CLINE_MCP_SETTINGS_PATH": "<ROOT>/elsewhere/explicit.json"},
        ),
        case(
            "explicit_settings_path_duplicates_default",
            [doc(CURRENT, {"mcpServers": {"once": {"command": "e"}}})],
            env={"CLINE_MCP_SETTINGS_PATH": f"<ROOT>/{CURRENT}"},
        ),
        case(
            "explicit_settings_path_relative",
            [doc("elsewhere/explicit.json", {"mcpServers": {"explicit": {"command": "e"}}})],
            relative=True,
            env={"CLINE_MCP_SETTINGS_PATH": "elsewhere/explicit.json"},
        ),
        case(
            "data_dir_inside_home",
            [doc("home/custom/data/settings/cline_mcp_settings.json", {"mcpServers": {"d": {"command": "d"}}})],
            env={"CLINE_DATA_DIR": "<ROOT>/home/custom"},
        ),
        case(
            "data_dir_outside_home",
            [doc("elsewhere/data/settings/cline_mcp_settings.json", {"mcpServers": {"d": {"command": "d"}}})],
            env={"CLINE_DATA_DIR": "<ROOT>/elsewhere"},
        ),
        case("relative_home", [doc(CURRENT, {"mcpServers": {"r": {"command": "r"}}})], relative=True),
        # hook and plugin directories
        case("hooks_dir", dirs=["home/.cline/hooks"]),
        case("plugins_dir", dirs=["home/.cline/plugins"]),
        case("documents_hooks", dirs=["home/Documents/Cline/Hooks"]),
        case("documents_plugins", dirs=["home/Documents/Cline/Plugins"]),
        case(
            "every_directory",
            [doc(CURRENT, {"mcpServers": {"s": {"command": "c"}}})],
            dirs=[
                "home/.cline/hooks",
                "home/.cline/plugins",
                "home/Documents/Cline/Hooks",
                "home/Documents/Cline/Plugins",
            ],
        ),
        case("hooks_is_file", [file("home/.cline/hooks", "x")]),
        case("hooks_dangling_symlink", symlinks=[link("home/.cline/hooks", "<ROOT>/elsewhere/missing")]),
        case("hooks_symlink", dirs=["elsewhere/hooks"], symlinks=[link("home/.cline/hooks", "<ROOT>/elsewhere/hooks")]),
        case("hooks_parent_unsearchable", dirs=["home/.cline/hooks"], dir_modes={"home/.cline": 0o000}),
        case("home_unsearchable", dirs=["home/.cline/hooks"], dir_modes={"home": 0o000}),
        # VS Code hosts
        case("vscode_extension", [extension(".vscode", "saoudrizwan.claude-dev-3.1.0")]),
        case(
            "vscode_every_editor",
            [
                extension(".vscode", "saoudrizwan.claude-dev-3.1.0", "3.1.0"),
                extension(".vscode-insiders", "saoudrizwan.claude-dev-3.2.0", "3.2.0"),
                extension(".cursor", "saoudrizwan.claude-dev-3.3.0", "3.3.0"),
            ],
        ),
        case(
            "vscode_duplicate_versions",
            [
                extension(".vscode", "saoudrizwan.claude-dev-3.1.0-arm64", "3.1.0"),
                extension(".vscode", "saoudrizwan.claude-dev-3.1.0-x64", "3.1.0"),
                extension(".cursor", "saoudrizwan.claude-dev-3.1.0", "3.1.0"),
                extension(".cursor", "saoudrizwan.claude-dev-9.9.9", "9.9.9"),
            ],
        ),
        case(
            "vscode_name_order",
            [
                extension(".vscode", "saoudrizwan.claude-dev-3.10.0", "3.10.0"),
                extension(".vscode", "saoudrizwan.claude-dev-3.2.0", "3.2.0"),
                extension(".vscode", "saoudrizwan.claude-dev-3.9.0", "3.9.0"),
                extension(".vscode", "saoudrizwan.claude-dev-Z", "4.0.0"),
                extension(".vscode", "saoudrizwan.claude-dev-a", "4.1.0"),
            ],
        ),
        case("vscode_padded_version", [extension(".vscode", "saoudrizwan.claude-dev-1", "  3.1.0\t\n")]),
        case("vscode_blank_version", [extension(".vscode", "saoudrizwan.claude-dev-1", "   ")]),
        case("vscode_empty_version", [extension(".vscode", "saoudrizwan.claude-dev-1", "")]),
        case("vscode_numeric_version", [extension(".vscode", "saoudrizwan.claude-dev-1", 3)]),
        case("vscode_null_version", [extension(".vscode", "saoudrizwan.claude-dev-1", None)]),
        case(
            "vscode_other_extensions",
            [
                extension(".vscode", "saoudrizwan.claude-dev", "3.1.0"),
                extension(".vscode", "other.saoudrizwan.claude-dev-3.1.0", "3.1.0"),
                extension(".vscode", "Saoudrizwan.Claude-Dev-3.1.0", "3.1.0"),
                extension(".vscode", "saoudrizwan.claude-dev-", "7.7.7"),
            ],
        ),
        case("vscode_package_not_object", [file("home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json", "[]")]),
        case("vscode_package_invalid", [file("home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json", "{nope")]),
        case(
            "vscode_package_invalid_utf8",
            [raw("home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json", b'{"version": "\xff"}')],
        ),
        case(
            "vscode_package_bom",
            [raw("home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json", b'\xef\xbb\xbf{"version": "1.0.0"}')],
        ),
        case(
            "vscode_package_unreadable",
            [file("home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json", '{"version": "1.0.0"}', mode=0o000)],
        ),
        case("vscode_package_is_directory", dirs=["home/.vscode/extensions/saoudrizwan.claude-dev-1/package.json"]),
        case("vscode_no_package", dirs=["home/.vscode/extensions/saoudrizwan.claude-dev-1"]),
        case("vscode_extension_is_file", [file("home/.vscode/extensions/saoudrizwan.claude-dev-1", "x")]),
        case(
            "vscode_extension_symlink",
            [file("elsewhere/ext/package.json", '{"version": "5.0.0"}')],
            [link("home/.vscode/extensions/saoudrizwan.claude-dev-5.0.0", "<ROOT>/elsewhere/ext")],
        ),
        case(
            "vscode_extension_dangling_symlink",
            symlinks=[link("home/.vscode/extensions/saoudrizwan.claude-dev-5.0.0", "<ROOT>/elsewhere/missing")],
        ),
        case(
            "vscode_extensions_root_symlink",
            [file("elsewhere/exts/saoudrizwan.claude-dev-6.0.0/package.json", '{"version": "6.0.0"}')],
            [link("home/.vscode/extensions", "<ROOT>/elsewhere/exts")],
        ),
        case("vscode_extensions_root_is_file", [file("home/.vscode/extensions", "x")]),
        case(
            "vscode_extensions_root_unreadable",
            [extension(".vscode", "saoudrizwan.claude-dev-3.1.0")],
            dir_modes={"home/.vscode/extensions": 0o000},
        ),
        case(
            "vscode_extensions_root_unlistable",
            [extension(".vscode", "saoudrizwan.claude-dev-3.1.0")],
            dir_modes={"home/.vscode/extensions": 0o311},
        ),
        case(
            "vscode_extension_unsearchable",
            [extension(".vscode", "saoudrizwan.claude-dev-3.1.0")],
            dir_modes={"home/.vscode/extensions/saoudrizwan.claude-dev-3.1.0": 0o000},
        ),
        case(
            "vscode_second_root_after_unreadable",
            [extension(".vscode", "saoudrizwan.claude-dev-3.1.0"), extension(".cursor", "saoudrizwan.claude-dev-3.5.0", "3.5.0")],
            dir_modes={"home/.vscode/extensions": 0o000},
        ),
        # JetBrains hosts
        case("jetbrains_local_share", [plugin(".local/share", "IntelliJIdea2024.1", "cline-plugin")]),
        case("jetbrains_library", [plugin("Library/Application Support", "PyCharm2024.1", "Cline")]),
        case("jetbrains_config", [plugin(".config", "WebStorm2024.1", "my-CLINE-assistant")]),
        case(
            "jetbrains_every_root",
            [
                plugin(".local/share", "A", "cline"),
                plugin("Library/Application Support", "B", "cline"),
                plugin(".config", "C", "cline"),
            ],
        ),
        case(
            "jetbrains_two_plugins",
            [plugin(".config", "IDE", "cline-a"), plugin(".config", "IDE", "cline-b"), plugin(".config", "IDE", "other")],
        ),
        case(
            "jetbrains_two_ides",
            [plugin(".config", "IDE-a", "cline"), plugin(".config", "IDE-b", "cline")],
        ),
        case("jetbrains_no_match", [plugin(".config", "IDE", "other-plugin")]),
        case("jetbrains_plugin_is_file", [file("home/.config/JetBrains/IDE/plugins/cline.jar", "x")]),
        case("jetbrains_ide_is_file", [file("home/.config/JetBrains/readme-cline", "x")]),
        case("jetbrains_plugins_is_file", [file("home/.config/JetBrains/IDE/plugins", "x")]),
        case("jetbrains_no_plugins_dir", dirs=["home/.config/JetBrains/IDE"]),
        case("jetbrains_root_is_file", [file("home/.config/JetBrains", "x")]),
        case("jetbrains_nested_too_deep", [file("home/.config/JetBrains/IDE/plugins/x/cline/plugin.xml", "x")]),
        case("jetbrains_too_shallow", [file("home/.config/JetBrains/plugins/cline/plugin.xml", "x")]),
        case(
            "jetbrains_dangling_plugin",
            dirs=["home/.config/JetBrains/IDE/plugins"],
            symlinks=[link("home/.config/JetBrains/IDE/plugins/cline", "<ROOT>/elsewhere/missing")],
        ),
        case(
            "jetbrains_plugin_symlink",
            dirs=["elsewhere/plugin"],
            symlinks=[link("home/.config/JetBrains/IDE/plugins/cline", "<ROOT>/elsewhere/plugin")],
        ),
        case(
            "jetbrains_ide_symlink",
            [file("elsewhere/ide/plugins/cline/plugin.xml", "x")],
            [link("home/.config/JetBrains/IDE", "<ROOT>/elsewhere/ide")],
        ),
        case(
            "jetbrains_root_symlink",
            [file("elsewhere/jb/IDE/plugins/cline/plugin.xml", "x")],
            [link("home/.config/JetBrains", "<ROOT>/elsewhere/jb")],
        ),
        case(
            "jetbrains_hidden_ide",
            [plugin(".config", ".hidden-ide", "cline")],
        ),
        case(
            "jetbrains_plugins_unsearchable",
            [plugin(".config", "IDE", "cline")],
            dir_modes={"home/.config/JetBrains/IDE/plugins": 0o000},
        ),
        case(
            "jetbrains_ide_unsearchable",
            [plugin(".config", "IDE", "cline")],
            dir_modes={"home/.config/JetBrains/IDE": 0o000},
        ),
        case(
            "jetbrains_root_unreadable",
            [plugin(".config", "IDE", "cline")],
            dir_modes={"home/.config/JetBrains": 0o000},
        ),
        case(
            "jetbrains_root_unlistable",
            [plugin(".config", "IDE", "cline")],
            dir_modes={"home/.config/JetBrains": 0o311},
        ),
        case(
            "jetbrains_plugins_unlistable",
            [plugin(".config", "IDE", "cline")],
            dir_modes={"home/.config/JetBrains/IDE/plugins": 0o311},
        ),
        case(
            "jetbrains_second_root_after_unreadable",
            [plugin(".local/share", "A", "cline"), plugin(".config", "C", "cline")],
            dir_modes={"home/.local/share/JetBrains": 0o000},
        ),
        case(
            "everything",
            [
                doc(CURRENT, {"mcpServers": {"s": {"command": "c", "args": ["--token=t"], "env": {"K": "v"}}}}),
                extension(".vscode", "saoudrizwan.claude-dev-3.1.0"),
                plugin(".config", "IDE", "cline"),
            ],
            dirs=["home/.cline/hooks", "home/Documents/Cline/Plugins"],
        ),
    ]
