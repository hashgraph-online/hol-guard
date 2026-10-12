"""Scenarios for package-execution-context configuration collection and failure ordering."""

# ruff: noqa: E501

from __future__ import annotations

from typing import Any

from package_context_vector_scenarios import DEFAULT_ENV, R, d, ln, rep, repo, sc, sp, tool, w, wh

NPM = [*repo(), tool("npm")]
ENV = dict(DEFAULT_ENV)


def with_env(**extra: str) -> dict[str, str]:
    return {**ENV, **extra}


def npmrc_scenarios() -> list[dict[str, Any]]:
    variants = {
        "comments_and_case": "Registry=https://r.test/\n  ; c\n# c\n\nFoo = Bar \nnoequals\n=novalue\nA=b=c\nregistry=again\n",
        "globalconfig": "globalconfig=/etc/npmrc\n",
        "userconfig_spaced": "  UserConfig =/x\n",
        "userconfig_after_blank_lines": "a=b\n\n   \nuserconfig=/y\n",
        "userconfig_prefix_not_matched": "xuserconfig=1\nmyglobalconfig=2\n",
        "userconfig_in_comment": "# userconfig=/x\n; globalconfig=/y\n",
        "userconfig_unit_separator": "\x1fuserconfig\x1f=/x\n",
        "userconfig_nbsp": "\u00a0userconfig\u00a0=x\n",
        "non_utf8": None,
        "env_references": "//r/:_authToken=${NPM_TOKEN}\nx=${a_b} ${1bad} ${} ${ok1}\n",
        "unicode_values": "name=\u00e9\u4e2d\nk\u00e9y=v\n\U0001f600=1\n",
        "unicode_whitespace": "\u00a0a\u00a0=\u00a0b\u00a0\n\u3000c=d\u3000\n",
        "carriage_returns": "a=1\rb=2\r\nc=3\n",
        "exotic_line_breaks": "a=1\u2028b=2\u2029c=3\x85d=4\x0be=5\x0cf=6\x1cg=7\x1dh=8\x1ei=9\n",
        "empty": "",
        "only_comments": "#a\n;b\n",
        "equals_only": "=\n==\n",
        "bom": "\ufeffregistry=x\n",
        "tabs": "\tkey\t=\tvalue\t\n",
        "quotes_and_backslashes": 'k="v\\"w"\npath=C:\\x\\y\n',
        "control_characters": "a=\x01\x02\n",
        "duplicate_key_case": "KEY=1\nkey=2\nKey=3\n",
    }
    out = []
    for tag, text in variants.items():
        step = wh("ws/.npmrc", "ff fe 00".replace(" ", "")) if text is None else w("ws/.npmrc", text)
        out.append(sc(f"npmrc_{tag}", [*NPM, step], env=with_env(NPM_TOKEN="x")))
    out.append(sc("npmrc_oversize", [*NPM, sp("ws/.npmrc", 2 * 1024 * 1024 + 1)]))
    out.append(sc("npmrc_at_limit", [*NPM, sp("ws/.npmrc", 2 * 1024 * 1024)]))
    out.append(sc("npmrc_is_directory", [*NPM, d("ws/.npmrc")]))
    out.append(sc("npmrc_symlink", [*NPM, w("real.npmrc", "a=b\n"), ln("ws/.npmrc", f"{R}/real.npmrc")]))
    out.append(sc("npmrc_dangling_symlink_ignored", [*NPM, ln("ws/.npmrc", f"{R}/gone")]))
    out.append(
        sc(
            "npmrc_multi_level",
            [
                *repo(),
                tool("npm"),
                d("ws/a/b"),
                w("ws/.npmrc", "a=1\n"),
                w("ws/a/.npmrc", "b=2\n"),
                w("ws/a/b/.npmrc", "c=3\n"),
            ],
            workspace=f"{R}/ws/a/b",
        )
    )
    out.append(sc("npmrc_no_repository", [tool("npm"), w("ws/.npmrc", "a=1\n")]))
    out.append(
        sc(
            "npmrc_repo_failure_uses_workspace_label",
            [w("ws/.git", "bad"), tool("npm"), w("ws/.npmrc", "a=1\n"), w("ws/x/.npmrc", "b")],
            workspace=f"{R}/ws/x",
        )
    )
    return out


def hook_scenarios() -> list[dict[str, Any]]:
    out = []
    pnpm_variants = {
        "require": "const x = require('y')\n",
        "require_spaced": "require   (\n",
        "require_unit_separator": "require\x1f(1)\n",
        "import_call": "await import('x')\n",
        "import_nbsp": "import\u00a0(x)\n",
        "suffix_word": "my_require(x)\n",
        "required_not_matched": "required(x)\n",
        "static_import_not_matched": "import x from 'y'\nrequire.resolve\n",
        "non_utf8_skips_scan": None,
    }
    for tag, text in pnpm_variants.items():
        step = wh("ws/.pnpmfile.cjs", "ff00") if text is None else w("ws/.pnpmfile.cjs", text)
        out.append(sc(f"pnpmfile_{tag}", [*repo(), tool("pnpm"), step], metadata={"package_manager": "pnpm"}))
    out.append(sc("pnpmfile_second_name", [*repo(), tool("npm"), w("ws/pnpmfile.cjs", "require('x')")]))
    out.append(
        sc(
            "pnp_cjs_dynamic",
            [*repo(), tool("yarn"), w("ws/.pnp.cjs", "require('x')")],
            metadata={"package_manager": "yarn"},
        )
    )
    out.append(
        sc(
            "build_rs_not_scanned_for_non_hooks",
            [*repo(), tool("cargo"), w("ws/build.rs", "fn main(){ require(1) }")],
            metadata={"package_manager": "cargo"},
        )
    )
    out.append(sc("workspace_yaml_dynamic_text_not_scanned", [*NPM, w("ws/pnpm-workspace.yaml", "require(x)\n")]))
    return out


def package_json_scenarios() -> list[dict[str, Any]]:
    cases: dict[str, str | None] = {
        "plain": '{"name":"x","version":"1.0.0"}',
        "sections": '{"packageManager":"pnpm@9","workspaces":["a","b"],"overrides":{"x":"1"},"pnpm":{"o":{"y":"2"}},"resolutions":{"z":"3"}}',
        "workspaces_object": '{"workspaces":{"packages":["a"],"nohoist":["b"]}}',
        "scripts_non_lifecycle": '{"scripts":{"test":"t","start":"s","build":"b"}}',
        "scripts_postinstall": '{"scripts":{"postinstall":"node x.js","test":"t"}}',
        "scripts_each_lifecycle": '{"scripts":{"install":"a"}}',
        "scripts_prepare": '{"scripts":{"prepare":"a"}}',
        "scripts_prepublish_only": '{"scripts":{"prepublishOnly":"a"}}',
        "scripts_empty_value": '{"scripts":{"preinstall":""}}',
        "scripts_non_dict": '{"scripts":["postinstall"]}',
        "scripts_null": '{"scripts":null}',
        "invalid_json": "{not json",
        "empty_file": "",
        "array_top_level": "[1,2]",
        "string_top_level": '"x"',
        "bom": '\ufeff{"name":"x","workspaces":["a"]}',
        "floats": '{"workspaces":[1.0,1e5,0.1,-0.0,1.5e-7,123456789.123456789,1e22,1e16]}',
        "big_int": '{"workspaces":[12345678901234567890]}',
        "unicode": '{"packageManager":"p\u00e9","overrides":{"\u4e2d":"\U0001f600"}}',
        "escaped_unicode": '{"overrides":{"k":"\\u00e9\\ud83d\\ude00\\n\\t\\"\\\\/"}}',
        "duplicate_keys": '{"overrides":{"a":"1","a":"2"},"overrides":{"b":"3"}}',
        "key_order": '{"resolutions":{"b":1,"a":2},"packageManager":"x"}',
        "nested_types": '{"pnpm":{"a":[1,"2",null,true,false,{"b":{}}]}}',
        "null_sections": '{"overrides":null,"pnpm":null,"workspaces":null,"packageManager":null}',
        "deep_nesting": '{"pnpm":' + "[" * 40 + "]" * 40 + "}",
        "whitespace_formatting": '  {\n "overrides" :\t{ "a" : "1" }\n}\n',
        "nul_byte": '{"name":"x"}\x00',
        "trailing_garbage": '{"name":"x"} x',
        "utf8_invalid": None,
    }
    out = []
    for tag, text in cases.items():
        step = wh("ws/package.json", "7b22ff227d") if text is None else w("ws/package.json", text)
        out.append(sc(f"package_json_{tag}", [*repo(), tool("npm"), step]))
    out.append(
        sc(
            "package_json_ignored_for_python_manager",
            [*repo(), tool("pip"), w("ws/package.json", "{bad")],
            metadata={"package_manager": "pip"},
        )
    )
    out.append(sc("package_json_oversize", [*repo(), tool("npm"), sp("ws/package.json", 2 * 1024 * 1024 + 1)]))
    out.append(sc("package_json_is_directory", [*repo(), tool("npm"), d("ws/package.json")]))
    out.append(
        sc(
            "package_json_symlink",
            [*repo(), tool("npm"), w("real.json", "{}"), ln("ws/package.json", f"{R}/real.json")],
        )
    )
    out.append(
        sc(
            "package_json_multi_level",
            [
                *repo(),
                tool("npm"),
                d("ws/a"),
                w("ws/package.json", '{"workspaces":["a"]}'),
                w("ws/a/package.json", '{"name":"a"}'),
            ],
            workspace=f"{R}/ws/a",
        )
    )
    out.append(
        sc(
            "package_json_lifecycle_in_parent_stops_collection",
            [
                *repo(),
                tool("npm"),
                d("ws/a"),
                w("ws/package.json", '{"scripts":{"install":"x"}}'),
                w("ws/a/package.json", "{}"),
                w("ws/a/.npmrc", "a=b"),
            ],
            workspace=f"{R}/ws/a",
        )
    )
    return out


def tree_scenarios() -> list[dict[str, Any]]:
    out = []
    tree_cases: dict[str, list[dict[str, Any]]] = {
        "yarn_plugin_js": [w("ws/.yarn/plugins/p.js", "module.exports={}")],
        "yarn_plugin_dynamic_js": [w("ws/.yarn/plugins/p.js", "require('x')")],
        "yarn_plugin_dynamic_cjs": [w("ws/.yarn/plugins/p.cjs", "import('x')")],
        "yarn_plugin_dynamic_mjs": [w("ws/.yarn/plugins/p.mjs", "import ( 'x')")],
        "dynamic_in_non_js_ignored": [w("ws/patches/x.patch", "require('x')"), w("ws/patches/x.ts", "require('x')")],
        "dynamic_in_uppercase_suffix_ignored": [w("ws/patches/x.JS", "require('x')")],
        "dotfile_named_js_ignored": [w("ws/patches/.js", "require('x')")],
        "double_suffix": [w("ws/patches/x.js.bak", "require('x')"), w("ws/patches/y.tar.js", "ok")],
        "non_utf8_js_not_scanned": [wh("ws/patches/x.js", "ff7265717569726528")],
        "nested_patches": [
            w("ws/patches/a/b/c.patch", "1"),
            w("ws/patches/a/d.patch", "2"),
            w("ws/patches/e.patch", "3"),
        ],
        "component_order": [
            w("ws/patches/a-b.patch", "1"),
            w("ws/patches/a/b.patch", "2"),
            w("ws/patches/a.patch", "3"),
        ],
        "dotfiles_and_empty_dirs": [w("ws/patches/.hidden", "h"), d("ws/patches/empty"), w("ws/patches/z/.also", "a")],
        "symlink_entry": [w("real.patch", "x"), ln("ws/patches/link.patch", f"{R}/real.patch")],
        "symlink_dir_entry": [d("realdir"), ln("ws/patches/dirlink", f"{R}/realdir")],
        "dangling_symlink_entry": [ln("ws/patches/dangling", f"{R}/gone")],
        "root_is_file": [w("ws/patches", "not a dir")],
        "root_is_symlink_to_dir": [
            d("realpatches"),
            w("realpatches/a.patch", "1"),
            ln("ws/patches", f"{R}/realpatches"),
        ],
        "root_dangling_symlink": [ln("ws/patches", f"{R}/gone")],
        "oversize_entry": [sp("ws/patches/big", 2 * 1024 * 1024 + 1)],
        "entry_at_limit": [sp("ws/.yarn/patches/big", 2 * 1024 * 1024)],
        "entry_unicode_name": [w("ws/patches/\u00e9.patch", "x")],
        "all_three_trees": [
            w("ws/.yarn/plugins/a.cjs", "1"),
            w("ws/.yarn/patches/b.patch", "2"),
            w("ws/patches/c.patch", "3"),
        ],
    }
    for tag, steps in tree_cases.items():
        out.append(sc(f"tree_{tag}", [*NPM, *steps]))
    many = [w(f"ws/patches/f{index:04}.patch", str(index)) for index in range(513)]
    out.append(sc("tree_over_count_limit", [*NPM, *many]))
    out.append(sc("tree_at_count_limit_total_over", [*NPM, *many[:512]]))
    out.append(sc("tree_at_count_limit_minus_few", [*NPM, *many[:500]]))
    out.append(
        sc(
            "tree_multi_level",
            [*repo(), tool("npm"), d("ws/a"), w("ws/patches/r.patch", "1"), w("ws/a/patches/s.patch", "2")],
            workspace=f"{R}/ws/a",
        )
    )
    out.append(
        sc(
            "tree_ignored_for_python_manager",
            [*repo(), tool("uv"), w("ws/patches/x.js", "require(1)")],
            metadata={"package_manager": "uv"},
        )
    )
    return out


def user_config_scenarios() -> list[dict[str, Any]]:
    out = []
    home = f"{R}/home"
    out += [
        sc("user_npm_default_missing", [*NPM]),
        sc("user_npm_default", [*NPM, w("home/.npmrc", "registry=https://u.test/\n")]),
        sc("user_npm_default_dynamic", [*NPM, w("home/.npmrc", "userconfig=/x\n")]),
        sc("user_npm_default_is_directory", [*NPM, d("home/.npmrc")]),
        sc(
            "user_npm_env_absolute",
            [*NPM, w("custom/npmrc", "a=b\n")],
            env=with_env(NPM_CONFIG_USERCONFIG=f"{R}/custom/npmrc"),
        ),
        sc(
            "user_npm_env_relative_to_cwd",
            [*NPM, w("rel/npmrc", "a=b\n")],
            env=with_env(NPM_CONFIG_USERCONFIG="rel/npmrc"),
        ),
        sc(
            "user_npm_env_relative_cwd_ws",
            [*NPM, w("ws/rel/npmrc", "a=b\n")],
            env=with_env(NPM_CONFIG_USERCONFIG="rel/npmrc"),
            cwd=f"{R}/ws",
        ),
        sc(
            "user_npm_env_tilde",
            [*NPM, w("home/cfg/npmrc", "a=b\n")],
            env=with_env(NPM_CONFIG_USERCONFIG="~/cfg/npmrc"),
        ),
        sc("user_npm_env_empty", [*NPM, w("home/.npmrc", "a=b\n")], env=with_env(NPM_CONFIG_USERCONFIG="")),
        sc("user_npm_env_missing_file", [*NPM], env=with_env(NPM_CONFIG_USERCONFIG=f"{R}/nowhere/npmrc")),
        sc("user_npm_env_symlink", [*NPM, w("real.npmrc", "a"), ln("home/.npmrc", f"{R}/real.npmrc")]),
        sc(
            "user_home_env_override",
            [*NPM, w("envhome/.npmrc", "a=b\n"), w("home/.npmrc", "x=y\n")],
            env=with_env(HOME=f"{R}/envhome"),
        ),
        sc("user_home_env_empty_uses_process_home", [*NPM, w("home/.npmrc", "x=y\n")], env=with_env(HOME="")),
        sc("user_home_env_tilde", [*NPM, w("home/sub/.npmrc", "x=y\n")], env=with_env(HOME="~/sub")),
        sc("user_home_env_absent", [*NPM, w("home/.npmrc", "x=y\n")], env={"PATH": f"{R}/bin"}),
        sc(
            "user_pip_default_files",
            [*repo(), tool("pip"), w("home/.config/pip/pip.conf", "a\n"), w("home/.config/uv/uv.toml", "b\n")],
            metadata={"package_manager": "pip"},
        ),
        sc(
            "user_pip_config_file_env",
            [*repo(), tool("pip"), w("custom/pip.conf", "a\n"), w("home/.config/pip/pip.conf", "x\n")],
            metadata={"package_manager": "pip"},
            env=with_env(PIP_CONFIG_FILE=f"{R}/custom/pip.conf"),
        ),
        sc(
            "user_pip_config_file_tilde",
            [*repo(), tool("pip"), w("home/pip.conf", "a\n")],
            metadata={"package_manager": "pip"},
            env=with_env(PIP_CONFIG_FILE="~/pip.conf"),
        ),
        sc(
            "user_pip_config_file_empty",
            [*repo(), tool("pip"), w("home/.config/pip/pip.conf", "x\n")],
            metadata={"package_manager": "pip"},
            env=with_env(PIP_CONFIG_FILE=""),
        ),
        sc(
            "user_cargo_default",
            [*repo(), tool("cargo"), w("home/.cargo/config", "a\n"), w("home/.cargo/config.toml", "b\n")],
            metadata={"package_manager": "cargo"},
        ),
        sc(
            "user_cargo_home_env",
            [*repo(), tool("cargo"), w("ch/config", "a\n"), w("home/.cargo/config", "x\n")],
            metadata={"package_manager": "cargo"},
            env=with_env(CARGO_HOME=f"{R}/ch"),
        ),
        sc(
            "user_cargo_home_empty",
            [*repo(), tool("cargo"), w("ws/config", "a\n"), w("ws/config.toml", "b\n")],
            metadata={"package_manager": "cargo"},
            env=with_env(CARGO_HOME=""),
            cwd=f"{R}/ws",
        ),
        sc(
            "user_cargo_home_tilde",
            [*repo(), tool("cargo"), w("home/ch/config.toml", "b\n")],
            metadata={"package_manager": "cargo"},
            env=with_env(CARGO_HOME="~/ch"),
        ),
        sc(
            "user_composer_default",
            [*repo(), tool("composer"), w("home/.composer/config.json", "{}"), w("home/.composer/auth.json", "{}")],
            metadata={"package_manager": "composer"},
        ),
        sc(
            "user_composer_home_env",
            [*repo(), tool("composer"), w("ch/auth.json", "{}")],
            metadata={"package_manager": "composer"},
            env=with_env(COMPOSER_HOME=f"{R}/ch"),
        ),
        sc(
            "user_composer_home_empty",
            [*repo(), tool("composer"), w("ws/auth.json", "{}")],
            metadata={"package_manager": "composer"},
            env=with_env(COMPOSER_HOME=""),
            cwd=f"{R}/ws",
        ),
        sc(
            "user_ruby_default",
            [*repo(), tool("gem"), w("home/.gemrc", "---\n"), w("home/.bundle/config", "x: y\n")],
            metadata={"package_manager": "gem"},
        ),
        sc("user_go_has_none", [*repo(), tool("go"), w("home/.npmrc", "x=y\n")], metadata={"package_manager": "go"}),
        sc(
            "user_maven_has_none",
            [*repo(), tool("mvn"), w("home/.m2/settings.xml", "<x/>")],
            metadata={"package_manager": "mvn"},
        ),
        sc("user_workspace_is_home", [*repo("home"), tool("npm"), w("home/.npmrc", "a=b\n")], workspace=home),
        sc(
            "user_cargo_home_equals_workspace_cargo",
            [*repo(), tool("cargo"), w("ws/.cargo/config", "a\n")],
            metadata={"package_manager": "cargo"},
            env=with_env(CARGO_HOME=f"{R}/ws/.cargo"),
        ),
    ]
    return out


def failure_scenarios() -> list[dict[str, Any]]:
    return [
        sc("failure_dynamic_then_exec_missing", [*repo(), w("ws/.npmrc", "userconfig=x\n")]),
        sc(
            "failure_first_wins_dependency_then_config",
            [*NPM, w("ws/.npmrc", "userconfig=x\n")],
            metadata={"package_manager": "npm", "manifest_paths": ["gone.json"]},
        ),
        sc(
            "failure_symlinked_config_stops_later_files",
            [*NPM, w("real", "a"), ln("ws/.npmrc", f"{R}/real"), w("ws/.yarnrc", "x")],
        ),
        sc(
            "failure_lifecycle_after_npmrc",
            [*repo(), tool("npm"), w("ws/.npmrc", "a=b\n"), w("ws/package.json", '{"scripts":{"install":"x"}}')],
        ),
        sc(
            "failure_global_and_dynamic",
            [*NPM, w("ws/.npmrc", "globalconfig=x")],
            metadata={"package_manager": "npm", "flags": ["-g"]},
        ),
        sc(
            "failure_config_failure_with_env_refs_lost",
            [*NPM, w("ws/.yarnrc", "t=${A}"), w("ws/.npmrc", "globalconfig=x")],
        ),
        sc(
            "env_refs_collected",
            [*NPM, w("ws/.yarnrc", "t=${ALPHA} ${beta}"), w("ws/.npmrc", "a=${GAMMA}\n")],
            env=with_env(ALPHA="1", GAMMA="3"),
        ),
        sc(
            "env_policy_inputs",
            list(NPM),
            env=with_env(npm_config_registry="https://x.test/", HTTP_PROXY="http://p", NODE_OPTIONS="--x", FOO="bar"),
        ),
        sc("env_empty", [*NPM], env={}),
        sc("env_unicode_values", [*NPM], env=with_env(NPM_CONFIG_CACHE="/t\u00e9mp", EMOJI="\U0001f600")),
        sc(
            "many_files_budget_count",
            [
                *NPM,
                *[w(f"ws/patches/n{index:03}.patch", str(index)) for index in range(300)],
                *[w(f"ws/.yarn/patches/m{index:03}.patch", str(index)) for index in range(300)],
            ],
        ),
        sc("exec_reads_count_toward_budget", [*NPM, rep("ws/patches/p.patch", "x", 10)]),
    ]


def all_scenarios() -> list[dict[str, Any]]:
    from package_context_vector_scenarios import (
        dependency_scenarios,
        executable_scenarios,
        manager_scenarios,
        repository_scenarios,
    )

    return [
        *repository_scenarios(),
        *manager_scenarios(),
        *executable_scenarios(),
        *dependency_scenarios(),
        *npmrc_scenarios(),
        *hook_scenarios(),
        *package_json_scenarios(),
        *tree_scenarios(),
        *user_config_scenarios(),
        *failure_scenarios(),
    ]
