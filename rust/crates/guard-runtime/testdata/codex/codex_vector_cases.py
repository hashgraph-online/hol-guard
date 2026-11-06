# ruff: noqa: E501
"""Fixture cases for the Codex detection vectors (see record_codex_vectors.py).

`<CMD>` stands for the exact managed hook command an install writes; the
recorder expands it for the Python run and the vectors keep the placeholder.
"""

from __future__ import annotations

import json

HOME = "home"
WORK = "work"
HC = f"{HOME}/.codex/config.toml"
HH = f"{HOME}/.codex/hooks.json"
WC = f"{WORK}/.codex/config.toml"
WH = f"{WORK}/.codex/hooks.json"
PRE = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
POST = "Bash|Read|mcp__.*"
LEGACY_STATUS = "HOL Guard checking tool action"
LEGACY_POST_STATUS = "HOL Guard checking tool result"
TRUSTED = "sha256:" + "ab" * 32


def file(path: str, text: str = "", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def raw(path: str, data: bytes) -> dict:
    return {"path": path, "hex": data.hex(), "mode": 0o644}


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def case(name: str, files=(), symlinks=(), dirs=(), dir_modes=None, **options) -> dict:
    return {
        "name": name,
        "files": list(files),
        "symlinks": list(symlinks),
        "dirs": list(dirs),
        "dir_modes": dir_modes or {},
        **options,
    }


def hooks_json(hooks: object, **extra: object) -> str:
    return json.dumps({"hooks": hooks, **extra}, ensure_ascii=False)


def toml_hook(event: str, body: str = "", matcher: str | None = None, extra: str = "") -> str:
    group = f'matcher = "{matcher}"\n' if matcher is not None else ""
    return f"[[hooks.{event}]]\n{group}{extra}\n[[hooks.{event}.hooks]]\n{body}\n"


LEGACY_BODY = f'type = "command"\ncommand = "<CMD>"\nstatusMessage = "{LEGACY_STATUS}"\ntimeout = 30\n'
LEGACY_JSON = {"type": "command", "command": "<CMD>", "statusMessage": LEGACY_STATUS, "timeout": 30}
LEGACY_POST_JSON = {"type": "command", "command": "<CMD>", "statusMessage": LEGACY_POST_STATUS, "timeout": 30}
SCRIPT = {"type": "command", "command": "/usr/bin/env python3 /opt/audit.py --flag", "timeout": 20}


def mcp_cases() -> list[dict]:
    out = [
        case("empty"),
        case("empty_config_file", [file(HC, "")]),
        case("comment_only_config", [file(HC, "# nothing\n")]),
        case(
            "stdio_server",
            [
                file(
                    HC,
                    '[mcp_servers.alpha]\ncommand = "npx"\nargs = ["-y", "pkg", 3, 1.5, true]\nenabled = false\n'
                    '[mcp_servers.alpha.env]\nTOKEN = "sk-abcdefghijklmnop"\n" PAD " = "x"\nEMPTY = ""\nNUM = 4\n"" = "z"\n',
                )
            ],
        ),
        case(
            "http_server",
            [file(HC, '[mcp_servers.web]\nurl = "https://example.invalid/mcp"\ncommand = "ignored"\nargs = []\n')],
        ),
        case("empty_url_is_http", [file(HC, '[mcp_servers.web]\nurl = ""\n')]),
        case(
            "server_without_command_or_url",
            [file(HC, '[mcp_servers.bare]\nnote = "x"\n[mcp_servers.listy]\nargs = "oops"\ncommand = "ls"\n')],
        ),
        case(
            "non_table_servers",
            [
                file(
                    HC,
                    'mcp_servers.one = "text"\nmcp_servers.two = 2\n[mcp_servers.three]\ncommand = 7\nargs = [1, "a"]\n',
                )
            ],
        ),
        case("mcp_servers_not_table", [file(HC, 'mcp_servers = "x"\n')]),
        case(
            "env_collisions",
            [file(HC, '[mcp_servers.s]\ncommand = "c"\n[mcp_servers.s.env]\n" A" = "1"\n"A " = "2"\nB = "3"\n')],
        ),
        case(
            "implicit_table_order",
            [
                file(
                    HC,
                    '[mcp_servers.b.env]\nK = "v"\n[mcp_servers.a]\ncommand = "a"\n[mcp_servers.b]\ncommand = "b"\n'
                    '[mcp_servers.c]\ncommand = "c"\n',
                )
            ],
        ),
        case(
            "unicode_names",
            [file(HC, '[mcp_servers."naïve srv"]\ncommand = "caf\\u00e9"\nargs = ["\\u2603", "\\ud7ff"]\n')],
        ),
        case(
            "global_and_project",
            [
                file(HC, '[mcp_servers.g]\ncommand = "g"\n'),
                file(WC, '[mcp_servers.p]\ncommand = "p"\n[mcp_servers.g]\nurl = "https://x.invalid"\n'),
            ],
        ),
        case("no_workspace", [file(HC, '[mcp_servers.g]\ncommand = "g"\n')], workspace=None),
        case(
            "home_under_workspace",
            [
                file(HC, '[mcp_servers.g]\ncommand = "g"\n'),
                file(f"{HOME}/.codex/hooks.json", hooks_json({"Stop": [{"hooks": [SCRIPT]}]})),
            ],
            workspace="root",
        ),
        case(
            "toml_dotted_and_inline", [file(HC, 'mcp_servers.a = { command = "x", args = ["1"], env = { K = "v" } }\n')]
        ),
        case(
            "toml_multiline_strings",
            [file(HC, "[mcp_servers.m]\ncommand = \"\"\"\nline\\\n   two\"\"\"\nargs = ['''lit\\n''', 'raw\\']\n")],
        ),
        case(
            "toml_numeric_forms",
            [file(HC, '[mcp_servers.n]\ncommand = "c"\nweight = 0xff\nratio = 1_0.5e+1\nx = inf\ny = nan\n')],
        ),
        case("toml_invalid_syntax", [file(HC, '[mcp_servers.a\ncommand = "x"\n')]),
        case("toml_malformed_digits_in_word", [file(HC, '[mcp_servers.a]\ncommand = "x"\nfile123 = = 1\n')]),
        case(
            "toml_malformed_representable_long_number",
            [file(HC, '[mcp_servers.a]\ncommand = "x"\nn = 1000000000000000000 =\n')],
        ),
        case(
            "toml_malformed_hash_text",
            [file(HC, '[mcp_servers.a]\ncommand = "x"\nsha = "sha256:0123456789abcdef0123456789abcdef" trailing\n')],
        ),
        case(
            "toml_malformed_overflow_beside_syntax_error",
            [file(HC, '[mcp_servers.a]\ncommand = "x"\nbig = 99999999999999999999 junk\n')],
        ),
        case(
            "toml_malformed_radix_hash",
            [file(HC, '[mcp_servers.a]\ncommand = "x"\nh = 0x00112233445566778899aabb junk\n')],
        ),
        case("toml_surrogate_escape", [file(HC, '[mcp_servers.a]\ncommand = "x\\ud800"\n')]),
        case("toml_duplicate_key", [file(HC, "a = 1\na = 2\n")]),
        case("toml_bom", [raw(HC, b'\xef\xbb\xbf[mcp_servers.a]\ncommand = "x"\n')]),
        case("toml_invalid_utf8", [raw(HC, b'[mcp_servers.a]\ncommand = "\xff"\n')]),
        case("toml_crlf", [raw(HC, b'[mcp_servers.a]\r\ncommand = "x"\r\nargs = ["y"]\r\n')]),
        case("config_directory", dirs=[HC]),
        case(
            "config_symlink",
            [file("elsewhere/real.toml", '[mcp_servers.s]\ncommand = "x"\n')],
            symlinks=[link(HC, "../../elsewhere/real.toml")],
        ),
        case("config_dangling_symlink", symlinks=[link(HC, "../../missing.toml")]),
        case("config_unreadable", [file(HC, '[mcp_servers.a]\ncommand = "x"\n', 0)]),
    ]
    return out


def proxy_cases() -> list[dict]:
    full = [
        "codex-mcp-proxy",
        "--command",
        "npx",
        "--arg",
        "-y",
        "--arg=pkg",
        "--server-name",
        "wrapped",
        "--source-scope",
        "project",
        "--config-path",
        "/x/y.toml",
        "--transport",
        "sse",
        "--server-env-key",
        "B",
        "--server-env-key=A",
        "--unknown=1",
    ]

    def server(
        command: str, args: list[str], env: str = '[mcp_servers.p.env]\nA = "1"\nB = 2\nC = "3"\n'
    ) -> list[dict]:
        text = f"[mcp_servers.p]\ncommand = {json.dumps(command)}\nargs = {json.dumps(args)}\n{env}"
        return [file(HC, text)]

    return [
        case("proxy_full", server("/usr/local/bin/HOL-Guard.exe", full)),
        case(
            "proxy_module_prefix",
            server("hol-guard", ["-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy", "--command", "node"]),
        ),
        case("proxy_guard_prefix", server("current-hol-guard.cmd", ["guard", "cursor-mcp-proxy", "--command", "node"])),
        case(
            "proxy_python_module",
            server("python3", ["-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy", "--command", "node"]),
        ),
        case("proxy_windows_path", server("C:\\bin\\hol-guard.bat", ["copilot-mcp-proxy", "--command", "x"])),
        case("proxy_trailing_slash_dot", server("/opt/hol-guard/.", ["codex-mcp-proxy", "--command", "x"])),
        case("proxy_no_command", server("hol-guard", ["codex-mcp-proxy", "--server-name", "n"])),
        case("proxy_empty_command", server("hol-guard", ["codex-mcp-proxy", "--command="])),
        case("proxy_not_a_proxy_tail", server("hol-guard", ["status", "codex-mcp-proxy", "--command", "x"])),
        case(
            "proxy_python_without_guard",
            server("python3", ["-m", "codex_plugin_scanner.cli", "codex-mcp-proxy", "--command", "x"]),
        ),
        case(
            "proxy_grammar_edges",
            server(
                "hol-guard",
                [
                    "codex-mcp-proxy",
                    "--",
                    "stray",
                    "--command",
                    "a",
                    "--command",
                    "b",
                    "--flag",
                    "--arg",
                    "--server-env-key",
                ],
            ),
        ),
        case(
            "proxy_value_with_equals",
            server("hol-guard", ["codex-mcp-proxy", "--command=a=b", "--arg", "--not-a-flag", "--arg", "-x"]),
        ),
        case(
            "proxy_env_missing_and_dup",
            server(
                "hol-guard",
                [
                    "codex-mcp-proxy",
                    "--command",
                    "x",
                    "--server-env-key",
                    "A",
                    "--server-env-key",
                    "A",
                    "--server-env-key",
                    " A",
                    "--server-env-key",
                    "Z",
                ],
                '[mcp_servers.p.env]\nA = "1"\n" A" = "pad"\n',
            ),
        ),
        case(
            "proxy_env_not_table",
            server("hol-guard", ["codex-mcp-proxy", "--command", "x", "--server-env-key", "A"], 'env = "x"\n'),
        ),
    ]


def hook_cases() -> list[dict]:
    def one(name: str, hooks: object, **options) -> dict:
        return case(name, [file(HH, hooks_json(hooks))], **options)

    handler = {"type": "command", "command": "echo hi", "timeout": 5}
    cases = [
        one("json_script_hook", {"PreToolUse": [{"matcher": "Bash", "hooks": [SCRIPT]}]}),
        one("json_hooks_null", None),
        one("json_hooks_not_object", [1, 2]),
        one("json_event_not_list", {"Stop": {"hooks": []}, "Other": 3, "Third": None}),
        one("json_group_not_object", {"Stop": [1, "x", None, [], {"hooks": [handler]}]}),
        one(
            "json_group_bad_matcher",
            {"Stop": [{"matcher": 3, "hooks": [handler]}, {"matcher": None, "hooks": [handler]}]},
        ),
        one("json_group_bad_activation", {"Stop": [{"enabled": "yes", "disabled": None, "hooks": [handler]}]}),
        one("json_handlers_not_list", {"Stop": [{"hooks": {"a": 1}}, {"hooks": None}, {"hooks": "x"}, {}]}),
        one("json_handler_not_object", {"Stop": [{"hooks": [1, "x", None, [], handler]}]}),
        one(
            "json_handler_unknown_type",
            {"Stop": [{"hooks": [{"type": "prompt", "prompt": "hi"}, {"type": "agent"}, {"type": "  "}, {"type": 4}]}]},
        ),
        one(
            "json_handler_no_command",
            {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command"},
                            {"command": "   "},
                            {"command": 5},
                            {"command": None, "type": "command"},
                            {"timeout": 1},
                        ]
                    }
                ]
            },
        ),
        one(
            "json_handler_activation",
            {
                "Stop": [
                    {
                        "hooks": [
                            {"command": "a", "enabled": False},
                            {"command": "b", "disabled": True},
                            {"command": "c", "enabled": 1},
                            {"command": "d", "disabled": "no"},
                        ]
                    }
                ]
            },
        ),
        one(
            "json_group_disabled",
            {"Stop": [{"enabled": False, "hooks": [handler]}, {"disabled": True, "hooks": [{"command": "z"}]}]},
        ),
        one(
            "json_timeouts",
            {
                "Stop": [
                    {
                        "hooks": [
                            {"command": "t1", "timeout": 0},
                            {"command": "t2", "timeout": 2.5},
                            {"command": "t3", "timeout": 1e2},
                            {"command": "t4", "timeout": -1},
                            {"command": "t5", "timeout": True},
                            {"command": "t6", "timeout": "5"},
                            {"command": "t7", "timeout": None},
                            {"command": "t8", "timeout": 9223372036854775807},
                            {"command": "t9", "timeout": 18446744073709551615},
                            {"command": "t10", "timeout": 1e308},
                            {"command": "t11", "timeout": 0.1},
                        ]
                    }
                ]
            },
        ),
        one(
            "json_environments",
            {
                "Stop": [
                    {
                        "hooks": [
                            {"command": "e1", "env": {"B": "1", "A": "2"}},
                            {"command": "e2", "environment": {"K": "v"}},
                            {"command": "e3", "env": None, "environment": {"K": 1}},
                            {"command": "e4", "env": {"K": 1}},
                            {"command": "e5", "env": []},
                            {"command": "e6", "environment": "x"},
                            {"type": "prompt", "env": 3},
                        ]
                    }
                ]
            },
        ),
        one(
            "json_argv_forms",
            {
                "Stop": [
                    {
                        "hooks": [
                            {"command": "plain  one\ttwo"},
                            {"command": "  lead trail  "},
                            {"command": "quote 'a b'"},
                            {"command": 'double "x"'},
                            {"command": "env VAR=1 run"},
                            {"command": "a;b"},
                            {"command": "a\nb"},
                            {"command": "a\rb"},
                            {"command": "~/bin/x"},
                            {"command": "x\u00a0y"},
                            {"command": "x\u000by"},
                            {"command": "caf\u00e9 \u2603"},
                            {"command": "back\\slash"},
                            {"command": "glob*"},
                            {"command": "# comment"},
                            {"command": "a #b"},
                            {"command": "a&b"},
                            {"command": "${HOME}/x"},
                        ]
                    }
                ]
            },
        ),
        one(
            "json_value_forms",
            {
                "Stop": [
                    {
                        "matcher": "m",
                        "extra": [
                            1,
                            2.0,
                            2.5,
                            -0.0,
                            1e22,
                            1e-7,
                            123456789012345678901,
                            True,
                            None,
                            "s",
                            {"z": 1, "a": [{"k": "v"}]},
                        ],
                        "hooks": [
                            {
                                "command": "c",
                                "meta": {
                                    "big": 9007199254740993,
                                    "neg": -5,
                                    "float": 0.30000000000000004,
                                    "tiny": 5e-324,
                                    "caf\u00e9": "\u2603\U0001f600",
                                    "ctl": "\u0001\u001f\u007f\u2028",
                                },
                            }
                        ],
                    }
                ]
            },
        ),
        one(
            "json_identity_ignores_coordinates",
            {
                "Stop": [{"hooks": [handler]}, {"hooks": [handler]}, {"matcher": "x", "hooks": [handler]}],
                "PreToolUse": [{"hooks": [handler]}],
            },
        ),
        one(
            "json_many_groups_sorted_coordinates",
            {"Stop": [{"hooks": [handler]} for _ in range(12)]},
        ),
        one(
            "json_duplicate_handlers_in_group",
            {"Stop": [{"hooks": [handler, dict(handler), {**handler, "timeout": 5.0}]}]},
        ),
        case(
            "json_features_hooks_false",
            [file(HC, "[features]\nhooks = false\n"), file(HH, hooks_json({"Stop": [{"hooks": [handler]}]}))],
        ),
        case(
            "json_features_hooks_true",
            [file(HC, "[features]\nhooks = true\n"), file(HH, hooks_json({"Stop": [{"hooks": [handler]}]}))],
        ),
        case(
            "json_features_not_table",
            [file(HC, 'features = "x"\n'), file(HH, hooks_json({"Stop": [{"hooks": [handler]}]}))],
        ),
        case(
            "json_features_hooks_other",
            [file(HC, "[features]\nhooks = 0\n"), file(HH, hooks_json({"Stop": [{"hooks": [handler]}]}))],
        ),
        case(
            "json_workspace_features_independent",
            [file(HC, "[features]\nhooks = false\n"), file(WH, hooks_json({"Stop": [{"hooks": [handler]}]}))],
        ),
        case(
            "json_both_scopes",
            [
                file(HH, hooks_json({"Stop": [{"hooks": [handler]}]})),
                file(WH, hooks_json({"Stop": [{"hooks": [handler]}]})),
            ],
        ),
        case("json_invalid_syntax", [file(HH, "{not json")]),
        case("json_top_level_array", [file(HH, "[1, 2]")]),
        case("json_top_level_scalar", [file(HH, '"text"')]),
        case("json_empty_file", [file(HH, "")]),
        case("json_bom", [raw(HH, b"\xef\xbb\xbf" + hooks_json({"Stop": [{"hooks": [handler]}]}).encode())]),
        case("json_invalid_utf8", [raw(HH, b'{"hooks": {"Stop": [{"hooks": [{"command": "\xff"}]}]}}')]),
        case(
            "json_duplicate_keys_last_wins",
            [
                file(
                    HH,
                    '{"hooks": {"Stop": [{"hooks": [{"command": "first"}]}]}, "hooks": {"Stop": [{"hooks": [{"command": "last"}]}]}}',
                )
            ],
        ),
        case(
            "json_duplicate_inner_keys",
            [
                file(
                    HH,
                    '{"hooks": {"Stop": [{"hooks": [{"command": "a", "command": "b", "timeout": 1, "timeout": 2}]}]}}',
                )
            ],
        ),
        case(
            "json_nan_and_infinity",
            [
                file(
                    HH,
                    '{"hooks": {"Stop": [{"hooks": [{"command": "a", "timeout": NaN}, {"command": "b", "timeout": Infinity}, {"command": "c", "meta": -Infinity}]}]}}',
                )
            ],
        ),
        case(
            "json_nested_values",
            [file(HH, '{"hooks": {"Stop": [{"hooks": [{"command": "n", "deep": ' + "[" * 200 + "]" * 200 + "}]}]}}")],
        ),
        case(
            "json_escaped_surrogate_pair",
            [file(HH, '{"hooks": {"Stop": [{"hooks": [{"command": "x\\ud83d\\ude00"}]}]}}')],
        ),
        case(
            "json_lone_surrogate_command",
            [file(HH, '{"hooks": {"Stop": [{"hooks": [{"command": "x\\ud800"}]}]}}')],
        ),
        case(
            "json_lone_surrogate_status_message",
            [file(HH, '{"hooks": {"Stop": [{"hooks": [{"command": "a", "statusMessage": "s\\udc00"}]}]}}')],
        ),
        case(
            "json_lone_surrogate_outside_hooks",
            [file(HH, '{"note": "\\ud800", "hooks": {"Stop": [{"hooks": [{"command": "a"}]}]}}')],
        ),
        case("json_directory", dirs=[HH]),
        case(
            "json_symlink",
            [file("elsewhere/real.json", hooks_json({"Stop": [{"hooks": [handler]}]}))],
            symlinks=[link(HH, "../../elsewhere/real.json")],
        ),
        case("json_dangling_symlink", symlinks=[link(HH, "../../missing.json")]),
        case("json_unreadable", [file(HH, hooks_json({"Stop": [{"hooks": [handler]}]}), 0)]),
        case("json_without_config", [file(HH, hooks_json({"SessionStart": [{"hooks": [handler]}]}))]),
    ]
    return cases


def toml_hook_cases() -> list[dict]:
    plain = 'type = "command"\ncommand = "audit --now"\ntimeout = 12\n'
    return [
        case("toml_script_hook", [file(HC, toml_hook("PreToolUse", plain, "Bash"))]),
        case("toml_hooks_not_table", [file(HC, "hooks = 3\n")]),
        case("toml_hooks_empty_table", [file(HC, "[hooks]\n")]),
        case("toml_event_not_list", [file(HC, "[hooks.Stop]\nhooks = []\n")]),
        case(
            "toml_state_table_skipped",
            [
                file(
                    HC,
                    f'[hooks.state."a:b:c"]\ntrusted_hash = "{TRUSTED}"\nenabled = false\n[hooks.state."d"]\ntrusted_hash = "{TRUSTED.upper().replace("SHA256", "sha256")}"\n',
                )
            ],
        ),
        case("toml_state_bad_hash", [file(HC, '[hooks.state."a"]\ntrusted_hash = "sha256:xyz"\n')]),
        case("toml_state_extra_field", [file(HC, f'[hooks.state."a"]\ntrusted_hash = "{TRUSTED}"\nnote = "x"\n')]),
        case("toml_state_bad_enabled", [file(HC, f'[hooks.state."a"]\ntrusted_hash = "{TRUSTED}"\nenabled = "x"\n')]),
        case("toml_state_empty", [file(HC, "[hooks.state]\n")]),
        case(
            "toml_state_with_events",
            [file(HC, f'[hooks.state."a"]\ntrusted_hash = "{TRUSTED}"\n' + toml_hook("Stop", plain))],
        ),
        case("json_state_table_not_skipped", [file(HH, hooks_json({"state": {"a": {"trusted_hash": TRUSTED}}}))]),
        case(
            "toml_temporal_values",
            [
                file(
                    HC,
                    toml_hook(
                        "Stop",
                        'command = "t"\nwhen = 1979-05-27T07:32:00-07:00\nutc = 1979-05-27T07:32:00.123456789Z\n'
                        "local = 1979-05-27T07:32:00.5\nday = 1979-05-27\nclock = 07:32:00.000001\nodd = 1979-05-27 00:32:00+05:30\n",
                    ),
                )
            ],
        ),
        case(
            "toml_float_forms",
            [
                file(
                    HC,
                    toml_hook(
                        "Stop",
                        'command = "f"\ntimeout = 2.5\na = inf\nb = -inf\nc = nan\nd = -0.0\ne = 6.02e23\nf = 5e-324\ng = 3.0\nh = +1.5\ni = 1_0.5\n',
                    ),
                )
            ],
        ),
        case(
            "toml_int_forms",
            [
                file(
                    HC,
                    toml_hook(
                        "Stop",
                        'command = "i"\ntimeout = 0x1f\na = 0o17\nb = 0b101\nc = 9223372036854775807\nd = -9223372036854775808\ne = 1_000\n',
                    ),
                )
            ],
        ),
        case("toml_float_timeout_inf", [file(HC, toml_hook("Stop", 'command = "i"\ntimeout = inf\n'))]),
        case("toml_float_timeout_nan", [file(HC, toml_hook("Stop", 'command = "i"\ntimeout = nan\n'))]),
        case(
            "toml_nested_and_arrays",
            [
                file(
                    HC,
                    toml_hook(
                        "Stop",
                        'command = "n"\narr = [1, "a", [2.5, true], { k = "v" }]\n[hooks.Stop.hooks.extra]\nx = 1\n',
                    ),
                )
            ],
        ),
        case(
            "toml_inline_event_tables",
            [file(HC, 'hooks.Stop = [{ matcher = "m", hooks = [{ command = "x", timeout = 3 }] }]\n')],
        ),
        case(
            "toml_env_table", [file(HC, toml_hook("Stop", 'command = "e"\n[hooks.Stop.hooks.env]\nB = "1"\nA = "2"\n'))]
        ),
        case(
            "toml_activation_fields",
            [file(HC, toml_hook("Stop", 'command = "e"\nenabled = false\n', extra="disabled = true"))],
        ),
        case(
            "toml_unicode_and_control",
            [
                file(
                    HC,
                    toml_hook("Stop", 'command = "u"\nmeta = "caf\\u00e9 \\U0001F600 \\u0001 \\u007f \\u2028 \\t"\n'),
                )
            ],
        ),
        case(
            "toml_matches_json_identity",
            [
                file(HC, toml_hook("Stop", 'type = "command"\ncommand = "echo hi"\ntimeout = 5\n')),
                file(HH, hooks_json({"Stop": [{"hooks": [{"type": "command", "command": "echo hi", "timeout": 5}]}]})),
            ],
        ),
        case(
            "toml_matches_json_identity_scope_differs",
            [
                file(HC, toml_hook("Stop", 'type = "command"\ncommand = "echo hi"\n')),
                file(WH, hooks_json({"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]})),
            ],
        ),
        case("toml_workspace_hooks", [file(WC, toml_hook("Stop", plain))]),
        case(
            "toml_key_order_matters_not",
            [
                file(HC, toml_hook("Stop", 'timeout = 1\ncommand = "o"\ntype = "command"\n')),
                file(HH, hooks_json({"Stop": [{"hooks": [{"type": "command", "command": "o", "timeout": 1}]}]})),
            ],
        ),
    ]


def ownership_cases() -> list[dict]:
    auth_pre = {"event": "PreToolUse", "group": {"matcher": PRE, "hooks": [LEGACY_JSON]}, "handler": LEGACY_JSON}
    pre_group = {"matcher": PRE, "hooks": [LEGACY_JSON]}
    return [
        case("legacy_json_excluded", [file(HH, hooks_json({"PreToolUse": [pre_group]}))]),
        case("legacy_toml_excluded", [file(HC, toml_hook("PreToolUse", LEGACY_BODY, PRE))]),
        case(
            "legacy_post_tool_excluded",
            [file(HH, hooks_json({"PostToolUse": [{"matcher": POST, "hooks": [LEGACY_POST_JSON]}]}))],
        ),
        case(
            "legacy_plus_foreign",
            [
                file(
                    HH,
                    hooks_json(
                        {
                            "PreToolUse": [pre_group, {"matcher": "Other", "hooks": [SCRIPT]}],
                            "Stop": [{"hooks": [SCRIPT]}],
                        }
                    ),
                )
            ],
        ),
        case(
            "legacy_wrong_matcher_not_adopted_other_command",
            [
                file(
                    HH,
                    hooks_json(
                        {
                            "PreToolUse": [
                                {"matcher": "Different", "hooks": [{**SCRIPT, "statusMessage": LEGACY_STATUS}]}
                            ]
                        }
                    ),
                )
            ],
        ),
        case(
            "legacy_wrong_status_other_command",
            [file(HH, hooks_json({"PreToolUse": [{"matcher": PRE, "hooks": [{**SCRIPT, "statusMessage": "other"}]}]}))],
        ),
        case(
            "legacy_first_matching_handler_only",
            [file(HH, hooks_json({"PreToolUse": [{"matcher": PRE, "hooks": [SCRIPT, LEGACY_JSON, LEGACY_JSON]}]}))],
        ),
        case(
            "legacy_second_group_matches",
            [
                file(
                    HH,
                    hooks_json(
                        {"PreToolUse": [{"matcher": "x", "hooks": [SCRIPT]}, {"matcher": PRE, "hooks": [LEGACY_JSON]}]}
                    ),
                )
            ],
        ),
        case(
            "legacy_only_first_group_per_event",
            [file(HH, hooks_json({"PreToolUse": [pre_group, {"matcher": PRE, "hooks": [LEGACY_JSON, SCRIPT]}]}))],
        ),
        case(
            "authenticated_exact",
            [file(HC, toml_hook("PreToolUse", 'type = "command"\ncommand = "echo hi"\ntimeout = 30\n', PRE))],
            authenticated=[
                {
                    "event": "PreToolUse",
                    "group": {"matcher": PRE},
                    "handler": {"type": "command", "command": "echo hi", "timeout": 30},
                }
            ],
        ),
        case(
            "authenticated_numeric_equality",
            [
                file(
                    HC,
                    toml_hook(
                        "PreToolUse", 'type = "command"\ncommand = "echo hi"\ntimeout = 30.0\nflag = true\n', PRE
                    ),
                )
            ],
            authenticated=[
                {
                    "event": "PreToolUse",
                    "group": {"matcher": PRE},
                    "handler": {"type": "command", "command": "echo hi", "timeout": 30, "flag": 1},
                }
            ],
        ),
        case(
            "authenticated_mismatch",
            [file(HC, toml_hook("PreToolUse", 'type = "command"\ncommand = "echo hi"\ntimeout = 31\n', PRE))],
            authenticated=[
                {
                    "event": "PreToolUse",
                    "group": {"matcher": PRE},
                    "handler": {"type": "command", "command": "echo hi", "timeout": 30},
                }
            ],
        ),
        case(
            "authenticated_wrong_matcher",
            [file(HC, toml_hook("PreToolUse", 'command = "echo hi"\n', "Other"))],
            authenticated=[{"event": "PreToolUse", "group": {"matcher": PRE}, "handler": {"command": "echo hi"}}],
        ),
        case(
            "authenticated_null_matcher",
            [file(HC, toml_hook("Stop", 'command = "echo hi"\n'))],
            authenticated=[{"event": "Stop", "group": {"matcher": None}, "handler": {"command": "echo hi"}}],
        ),
        case(
            "authenticated_missing_group",
            [file(HC, toml_hook("Stop", 'command = "echo hi"\n'))],
            authenticated=[{"event": "Stop", "handler": {"command": "echo hi"}}],
        ),
        case(
            "authenticated_only_home_toml",
            [
                file(HC, toml_hook("Stop", 'command = "echo hi"\n')),
                file(WC, toml_hook("Stop", 'command = "echo hi"\n')),
                file(HH, hooks_json({"Stop": [{"hooks": [{"command": "echo hi"}]}]})),
            ],
            authenticated=[{"event": "Stop", "group": {"matcher": None}, "handler": {"command": "echo hi"}}],
        ),
        case(
            "authenticated_nested_equality",
            [file(HC, toml_hook("Stop", 'command = "x"\nlist = [1, 2.0, "a"]\n[hooks.Stop.hooks.sub]\nk = 1\n'))],
            authenticated=[
                {
                    "event": "Stop",
                    "group": {"matcher": None},
                    "handler": {"command": "x", "list": [True, 2, "a"], "sub": {"k": 1.0}},
                }
            ],
        ),
        case(
            "authenticated_beats_legacy", [file(HH, hooks_json({"PreToolUse": [pre_group]}))], authenticated=[auth_pre]
        ),
    ]


def contents_cases() -> list[dict]:
    handler = {"type": "command", "command": "echo hi"}
    return [
        case(
            "contents_all",
            contents={
                HC: '[mcp_servers.s]\ncommand = "x"\n',
                HH: hooks_json({"Stop": [{"hooks": [handler]}]}),
                WC: None,
                WH: None,
            },
        ),
        case("contents_missing_hooks", contents={HC: '[mcp_servers.s]\ncommand = "x"\n', HH: None, WC: None, WH: None}),
        case("contents_all_missing", contents={HC: None, HH: None, WC: None, WH: None}),
        case(
            "contents_hooks_only",
            contents={HC: None, HH: hooks_json({"Stop": [{"hooks": [handler]}]}), WC: None, WH: None},
        ),
        case(
            "contents_workspace",
            contents={
                HC: None,
                HH: None,
                WC: '[mcp_servers.w]\nurl = "https://x.invalid"\n',
                WH: hooks_json({"Stop": [{"hooks": [handler]}]}),
            },
        ),
        case(
            "contents_ignore_disk",
            [file(HC, '[mcp_servers.disk]\ncommand = "d"\n')],
            contents={HC: '[mcp_servers.mem]\ncommand = "m"\n', HH: None, WC: None, WH: None},
        ),
        case(
            "contents_legacy",
            contents={
                HC: None,
                HH: hooks_json({"PreToolUse": [{"matcher": PRE, "hooks": [LEGACY_JSON]}]}),
                WC: None,
                WH: None,
            },
        ),
    ]


def cases() -> list[dict]:
    return [*mcp_cases(), *proxy_cases(), *hook_cases(), *toml_hook_cases(), *ownership_cases(), *contents_cases()]
