"""Local runner and package launch cases."""

from __future__ import annotations

from typing import Any

from exact_action_case_support import PROJECT, exact, execution


def runner_cases() -> list[dict[str, Any]]:
    node = f"{PROJECT}/node_modules"
    base_tree: dict[str, Any] = {
        "proj/package.json": '{"name": "app"}',
        "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "3.1.0", "bin": "bin/wrangler.js"}',
        "proj/node_modules/wrangler/bin/wrangler.js": "console.log(1)\n",
        "proj/node_modules/.bin/wrangler": {"symlink": f"{node}/wrangler/bin/wrangler.js"},
        "proj/node_modules/vitest/package.json": '{"name": "vitest", "version": "1.0.0", "bin": {"vitest": "vitest.mjs"}}',  # noqa: E501
        "proj/node_modules/vitest/vitest.mjs": "x",
        "proj/node_modules/.bin/vitest": {"symlink": f"{node}/vitest/vitest.mjs"},
        "bin/npx": "#!/bin/sh\n",
    }
    shim_tree = dict(base_tree)
    shim_tree["proj/node_modules/.bin/wrangler"] = "#!/bin/sh\nexec node ../wrangler/bin/wrangler.js\n"
    scoped_tree = dict(shim_tree)
    scoped_tree.update(
        {
            "proj/node_modules/@scope/tool/package.json": '{"name": "@scope/tool", "version": "2.0.0", "bin": {"tool": "cli.js"}}',  # noqa: E501
            "proj/node_modules/@scope/tool/cli.js": "x",
            "proj/node_modules/.bin/tool": "#!/bin/sh\n",
        }
    )

    def runner(name: str, command: str, tree: dict[str, Any], intent: Any, **extra: Any) -> dict[str, Any]:
        return exact(f"runner_{name}", command=command, tree=tree, intent=intent, **extra)

    one = [execution()]
    return [
        runner("npx_ok", "npx wrangler deploy", base_tree, one),
        runner("npx_yes", "npx -y wrangler deploy", base_tree, one),
        runner("npx_double_dash", "npx -- wrangler", base_tree, one),
        runner("npx_no_args", "npx", base_tree, one),
        runner("npx_selector", "npx --package x wrangler", base_tree, one),
        runner("npx_version", "npx wrangler@3 deploy", base_tree, one),
        runner("npx_no_intent", "npx wrangler", base_tree, None),
        runner("npx_empty_intent", "npx wrangler", base_tree, []),
        runner("npx_intent_raises", "npx wrangler", base_tree, "raise"),
        runner("npx_two_executions", "npx wrangler", base_tree, [execution(), execution()]),
        runner("npx_target_mismatch", "npx wrangler", base_tree, [execution(executable_name="other")]),
        runner(
            "npx_unavailable",
            "npx wrangler",
            base_tree,
            [execution(local_executable={"path": "p", "resolved_path": "p", "status": "missing", "content_hash": "h"})],
        ),
        runner("npx_no_local", "npx wrangler", base_tree, [execution(local_executable=None)]),
        runner("npx_no_manager", "npx wrangler", base_tree, [execution(manager=None)]),
        runner("npx_guard_shim", "npx wrangler", base_tree, [execution(manager_is_guard_shim=True)]),
        runner(
            "npx_no_hash",
            "npx wrangler",
            base_tree,
            [
                execution(
                    local_executable={"path": "p", "resolved_path": "p", "status": "available", "content_hash": None}
                )
            ],
        ),
        runner(
            "npx_empty_hash",
            "npx wrangler",
            base_tree,
            [
                execution(
                    local_executable={"path": "p", "resolved_path": "p", "status": "available", "content_hash": ""}
                )
            ],
        ),
        runner(
            "npx_no_resolved",
            "npx wrangler",
            base_tree,
            [
                execution(
                    local_executable={"path": "p", "resolved_path": None, "status": "available", "content_hash": "h"}
                )
            ],
        ),
        runner("npx_no_package_name", "npx wrangler", base_tree, [execution(package_name=None)]),
        runner("npx_wrong_package_name", "npx wrangler", base_tree, [execution(package_name="nope")]),
        runner("npx_bad_package_name", "npx wrangler", base_tree, [execution(package_name="Bad Name")]),
        runner(
            "npx_lockfiles",
            "npx wrangler",
            base_tree,
            [
                execution(
                    lockfiles=[
                        {
                            "path": f"{PROJECT}/pnpm-lock.yaml",
                            "resolved_path": None,
                            "status": "available",
                            "content_hash": "l1",
                        }
                    ]
                )
            ],
        ),
        runner("npx_no_manifests", "npx wrangler", base_tree, [execution(manifests=[])]),
        runner("npx_operand", "npx wrangler deploy a.txt", {**base_tree, "proj/a.txt": "x"}, one),
        runner("npx_sensitive", "npx wrangler deploy .env", {**base_tree, "proj/.env": "x"}, one),
        runner(
            "npx_vitest_mutable",
            "npx vitest",
            base_tree,
            [execution(bin=f"{node}/.bin/vitest", package_name="vitest", executable_name="vitest")],
        ),
        runner(
            "npx_missing_manifest",
            "npx wrangler",
            {k: v for k, v in base_tree.items() if "wrangler/package.json" not in k},
            one,
        ),
        runner(
            "npx_manifest_bad_json",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": "{oops"},
            one,
        ),
        runner(
            "npx_manifest_wrong_name",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": '{"name": "other", "version": "1"}'},
            one,
        ),
        runner(
            "npx_manifest_no_version",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": '{"name": "wrangler"}'},
            one,
        ),
        runner(
            "npx_manifest_empty_version",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": ""}'},
            one,
        ),
        runner(
            "npx_manifest_big",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": {"fill": 1_048_577}},
            one,
        ),
        runner(
            "npx_manifest_array", "npx wrangler", {**base_tree, "proj/node_modules/wrangler/package.json": "[1]"}, one
        ),
        runner("npx_shim_ok", "npx wrangler", shim_tree, one),
        runner(
            "npx_shim_no_script",
            "npx wrangler",
            {k: v for k, v in shim_tree.items() if "bin/wrangler.js" not in k},
            one,
        ),
        runner(
            "npx_shim_bin_string_mismatch",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": "x.js"}',
            },
            one,
        ),
        runner(
            "npx_shim_bin_dict",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": {"wrangler": "bin/wrangler.js"}}',  # noqa: E501
            },
            one,
        ),
        runner(
            "npx_shim_bin_dict_missing",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": {"other": "bin/wrangler.js"}}',  # noqa: E501
            },
            one,
        ),
        runner(
            "npx_shim_bin_blank",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": " "}',
            },
            one,
        ),
        runner(
            "npx_shim_bin_escape",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": "../../../outside.js"}',  # noqa: E501
                "outside.js": "x",
            },
            one,
        ),
        runner(
            "npx_shim_bin_dir",
            "npx wrangler",
            {
                **shim_tree,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1", "bin": "bin"}',
            },
            one,
        ),
        runner(
            "npx_shim_no_bin_field",
            "npx wrangler",
            {**shim_tree, "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "1"}'},
            one,
        ),
        runner(
            "npx_shim_scoped",
            "npx tool",
            scoped_tree,
            [execution(bin=f"{node}/.bin/tool", package_name="@scope/tool", executable_name="tool")],
        ),
        runner(
            "npx_scoped_not_shim",
            "npx tool",
            {**scoped_tree, "proj/node_modules/.bin/tool": {"symlink": f"{node}/@scope/tool/cli.js"}},
            [execution(bin=f"{node}/.bin/tool", package_name="@scope/tool", executable_name="tool")],
        ),
        runner("npx_non_shim_walk", "npx wrangler", base_tree, [execution(bin=f"{node}/wrangler/bin/wrangler.js")]),
        runner(
            "npx_non_shim_no_manifest",
            "npx wrangler",
            {**base_tree, "proj/node_modules/wrangler/package.json": None},
            [execution(bin=f"{node}/wrangler/bin/wrangler.js")],
        ),
        runner(
            "npx_non_shim_outer_package",
            "npx wrangler",
            {
                "proj/package.json": '{"name": "wrangler", "version": "9.9.9"}',
                "bin/npx": "x",
                "proj/tools/wrangler": "x",
            },
            [execution(bin=f"{PROJECT}/tools/wrangler")],
        ),
        runner("pnpm_exec", "pnpm exec wrangler", base_tree, one),
        runner("pnpm_x", "pnpm x wrangler", base_tree, one),
        runner("pnpm_direct", "pnpm wrangler", base_tree, one),
        runner("yarn_exec", "yarn exec wrangler", base_tree, one),
        runner("npm_exec", "npm exec wrangler", base_tree, one),
        runner("npm_exec_twice", "npm exec exec wrangler", base_tree, one),
        runner("npm_test", "npm test", base_tree, one),
        runner("npm_run", "npm run build", base_tree, one),
        runner("bunx", "bunx wrangler", base_tree, one),
        runner("pnpx", "pnpx wrangler", base_tree, one),
        runner("npx_in_compound", "cd sub && npx wrangler", {**base_tree, "proj/sub": {"dir": True}}, one),
        runner("npx_pipe", "npx wrangler | cat", base_tree, one),
        runner("npx_exe_suffix", "npx.exe wrangler", base_tree, one),
        runner("npx_upper", "NPX wrangler", base_tree, one),
        runner("npx_env_prefix", "FOO=1 npx wrangler", base_tree, one),
        runner("npx_flag_option", "npx --yes wrangler", base_tree, one),
        runner("npx_flag_other", "npx --no wrangler", base_tree, one),
    ]
