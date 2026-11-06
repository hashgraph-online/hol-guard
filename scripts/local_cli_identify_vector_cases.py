"""Case catalogue for the native ``local_cli_identify`` parity vectors.

Each case is a file tree under ``{ROOT}``, one command and the request flags.
``intent`` is the package-intent answer the fake engine returns for runner
commands (``None`` for no package intent, ``"raise"`` for a parser failure).
"""

from __future__ import annotations

from typing import Any

ROOT = "{ROOT}"
PROJECT = f"{ROOT}/proj"
HOME = f"{ROOT}/home"
PACKAGE = '{"name": "app", "devDependencies": {"wrangler": "^3"}}'
NO_DEPS = '{"name": "app"}'
BASE_TREE: dict[str, Any] = {
    "proj": {"dir": True},
    "home": {"dir": True},
    "proj/x.py": "print(1)\n",
    "proj/app.js": "console.log(1)\n",
    "proj/bin/tool.sh": "#!/bin/sh\necho tool\n",
    "proj/bin/notes.txt": "notes\n",
    "proj/scripts/a.sh": "echo a\n",
    "proj/scripts/b.sh": "echo b\n",
    "proj/scripts/env.rc": "export A=1\n",
    "proj/sub/run.sh": "echo run\n",
    "home/rc.sh": "export B=1\n",
}
WRANGLER_TREE: dict[str, Any] = {
    "proj/package.json": PACKAGE,
    "proj/node_modules/.bin/wrangler": "#!/usr/bin/env node\nrequire('../wrangler/bin.js')\n",
    "proj/node_modules/wrangler/package.json": (
        '{"name": "wrangler", "version": "3.1.0", "bin": {"wrangler": "bin.js"}}'
    ),
    "proj/node_modules/wrangler/bin.js": "console.log('wrangler')\n",
}


def execution(**fields: Any) -> dict[str, Any]:
    """A package-intent local execution resolving ``wrangler`` in the project."""

    local_path = fields.pop("bin", f"{PROJECT}/node_modules/.bin/wrangler")
    evidence = {
        "local_executable": {
            "path": local_path,
            "resolved_path": local_path,
            "status": "available",
            "content_hash": "sha256:" + "1" * 64,
        },
        "manager": {
            "path": f"{ROOT}/bin/npx",
            "resolved_path": f"{ROOT}/bin/npx",
            "status": "available",
            "content_hash": "sha256:" + "2" * 64,
        },
        "manager_is_guard_shim": False,
        "package_name": "wrangler",
        "executable_name": "wrangler",
        "manifests": [],
        "lockfiles": [],
    }
    evidence.update(fields)
    return evidence


def case(name: str, command: str, **options: Any) -> dict[str, Any]:
    tree = dict(BASE_TREE)
    tree.update(options.get("tree", {}))
    return {
        "name": name,
        "tree": tree,
        "intent": options.get("intent"),
        "request": {
            "command_text": command,
            "cwd": options.get("cwd", PROJECT),
            "home_dir": options.get("home_dir", HOME),
            "user_home": HOME,
            "compound": options.get("compound", False),
            "env": {"PATH": f"{ROOT}/bin:/usr/bin", "HOME": HOME},
            "budget_ms": 5_000,
        },
    }


def _single() -> list[dict[str, Any]]:
    return [
        case("python-script", "python3 x.py"),
        case("python-script-args", "python3 x.py --flag value"),
        case("python-missing-script", "python3 missing.py"),
        case("python-versioned-interpreter", "python3.11 x.py"),
        case("python-inline", "python3 -c 'print(1)'"),
        case("python-module", "python3 -m http.server"),
        case("node-script", "node app.js"),
        case("bash-script", "bash scripts/a.sh"),
        case("sh-script-absolute", f"sh {PROJECT}/bin/tool.sh"),
        case("direct-script", "./bin/tool.sh"),
        case("direct-script-missing", "./bin/missing.sh"),
        case("direct-script-absolute", f"{PROJECT}/bin/tool.sh run"),
        case("bare-executable", "mytool deploy"),
        case("bare-executable-unicode", "Tööl --help"),
        case("bare-executable-cmd-suffix", "mytool.cmd"),
        case("path-executable", "./bin/custom-cli serve"),
        case("owned-git", "git status"),
        case("owned-npm", "npm install"),
        case("common-utility", "ls -la"),
        case("common-utility-path", "/bin/ls"),
        case("reserved-guard", "guard status"),
        case("reserved-hol-guard", "hol-guard scan"),
        case("interpreter-bare", "python3"),
        case("interpreter-node-exe", "node.exe"),
        case("bun-package-script", "bun run build"),
        case("unreusable-launch", "unreusable-tool run"),
        case("unverified-executable", "unverifiable-tool"),
        case("pipeline", "echo hi | mytool"),
        case("and-chain", "mytool && othertool"),
        case("env-prefix", "FOO=1 mytool"),
        case("redirect", "mytool > out.txt"),
        case("wrapper-sudo", "sudo mytool"),
        case("wrapper-env", "env mytool"),
        case("subshell", "(mytool)"),
        case("command-substitution", "mytool $(whoami)"),
        case("blank", "   "),
        case("unterminated-quote", 'mytool "open'),
        case("leading-space", "  python3 x.py  "),
        case("home-dir-none", "python3 x.py", home_dir=None),
        case("cwd-subdir", "bash run.sh", cwd=f"{PROJECT}/sub"),
    ]


def _runners() -> list[dict[str, Any]]:
    local = {"tree": WRANGLER_TREE, "intent": [execution()]}
    return [
        case("npx-local-bin-direct-dependency", "npx wrangler deploy", **local),
        case(
            "npx-local-bin-transitive",
            "npx wrangler deploy",
            tree={**WRANGLER_TREE, "proj/package.json": NO_DEPS},
            intent=[execution()],
        ),
        case("npx-yes-local-bin", "npx --yes wrangler", **local),
        case("npx-double-dash", "npx -- wrangler", **local),
        case("npx-registry-fetch", "npx wrangler deploy"),
        case("bunx-registry-fetch", "bunx cowsay hi"),
        case("pnpx-registry-fetch", "pnpx create-thing"),
        case("npx-versioned", "npx wrangler@3 deploy", **local),
        case("npx-scoped", "npx @cloudflare/wrangler"),
        case("npx-scoped-versioned", "npx @cloudflare/wrangler@1.2.3"),
        case("npx-package-selector", "npx -p wrangler wrangler", **local),
        case("npx-bad-name", "npx Bad_Name"),
        case("npx-common-utility", "npx ls"),
        case("npx-interpreter", "npx python3"),
        case("npx-reserved", "npx guard"),
        case("npx-no-target", "npx"),
        case("pnpm-without-proof", "pnpm wrangler"),
        case("pnpm-exec-local-bin", "pnpm exec wrangler", **local),
        case("yarn-exec-local-bin", "yarn exec wrangler", **local),
        case("npm-exec-local-bin", "npm exec wrangler", **local),
        case("npm-run-script", "npm run build", **local),
        case("npx-cmd-suffix", "npx.cmd wrangler", **local),
        case("npx-intent-raises", "npx wrangler", tree=WRANGLER_TREE, intent="raise"),
        case("npx-intent-empty", "npx wrangler", tree=WRANGLER_TREE, intent=[]),
        case("npx-intent-two", "npx wrangler", tree=WRANGLER_TREE, intent=[execution(), execution()]),
        case(
            "npx-guard-shim-manager",
            "npx wrangler",
            tree=WRANGLER_TREE,
            intent=[execution(manager_is_guard_shim=True)],
        ),
        case(
            "npx-unavailable-bin",
            "npx wrangler",
            tree=WRANGLER_TREE,
            intent=[
                execution(
                    local_executable={
                        "path": f"{PROJECT}/node_modules/.bin/wrangler",
                        "resolved_path": None,
                        "status": "missing",
                        "content_hash": None,
                    }
                )
            ],
        ),
        case(
            "npx-name-mismatch",
            "npx wrangler",
            tree=WRANGLER_TREE,
            intent=[execution(executable_name="other")],
        ),
        case(
            "npx-package-name-override",
            "npx wrangler",
            tree={
                **WRANGLER_TREE,
                "proj/node_modules/@cf/wrangler/package.json": (
                    '{"name": "@cf/wrangler", "version": "2.0.0", "bin": {"wrangler": "cli.js"}}'
                ),
                "proj/node_modules/@cf/wrangler/cli.js": "console.log(2)\n",
            },
            intent=[execution(package_name="@cf/wrangler")],
        ),
        case(
            "npx-shim-missing-package",
            "npx wrangler",
            tree={**WRANGLER_TREE, "proj/node_modules/wrangler/package.json": None},
            intent=[execution()],
        ),
        case(
            "npx-shim-bin-string",
            "npx wrangler",
            tree={
                **WRANGLER_TREE,
                "proj/node_modules/wrangler/package.json": '{"name": "wrangler", "version": "3.1.0", "bin": "bin.js"}',
            },
            intent=[execution()],
        ),
        case(
            "npx-shim-bin-escapes-package",
            "npx wrangler",
            tree={
                **WRANGLER_TREE,
                "proj/node_modules/wrangler/package.json": (
                    '{"name": "wrangler", "version": "3.1.0", "bin": {"wrangler": "../../x.js"}}'
                ),
                "proj/node_modules/x.js": "x\n",
            },
            intent=[execution()],
        ),
        case(
            "npx-non-shim-bin",
            "npx wrangler",
            tree={**WRANGLER_TREE, "proj/tools/wrangler": "#!/bin/sh\n"},
            intent=[execution(bin=f"{PROJECT}/tools/wrangler")],
        ),
    ]


def _compound() -> list[dict[str, Any]]:
    local = {"tree": WRANGLER_TREE, "intent": [execution()]}
    return [
        case("compound-single", "python3 x.py", compound=True),
        case("compound-source-then-tool", "source ./scripts/env.rc && mytool", compound=True),
        case("compound-dot-home", ". ~/rc.sh && make", compound=True),
        case("compound-dot-home-default", ". ~/rc.sh && make", compound=True, home_dir=None),
        case("compound-two-shell-scripts", "bash scripts/a.sh; sh scripts/b.sh", compound=True),
        case("compound-shell-flags", "bash -e scripts/a.sh && echo ok", compound=True),
        case("compound-shell-inline", "bash -c 'echo hi' && echo ok", compound=True),
        case("compound-shell-lc", "bash -lc scripts/a.sh && echo ok", compound=True),
        case("compound-shell-non-script", "sh bin/notes.txt && echo ok", compound=True),
        case("compound-shell-missing", "sh scripts/zz.sh && echo ok", compound=True),
        case("compound-cd-blocks-relative", "cd sub && ./run.sh", compound=True),
        case("compound-cd-blocks-shell-relative", "cd sub && bash run.sh", compound=True),
        case("compound-cd-absolute-ok", f"cd sub && {PROJECT}/bin/tool.sh", compound=True),
        case("compound-direct-script", "./bin/tool.sh && echo done", compound=True),
        case("compound-dedup", "./bin/tool.sh && ./bin/tool.sh", compound=True),
        case("compound-runner", "npx wrangler deploy && echo ok", compound=True, **local),
        case("compound-runner-after-cd", "cd sub && npx wrangler", compound=True, **local),
        case("compound-runner-env", "FOO=1 npx wrangler && echo ok", compound=True, **local),
        case("compound-runner-selector", "npx -p x wrangler && echo ok", compound=True, **local),
        case("compound-pipeline-script", "cat x.py | python3 x.py", compound=True),
        case("compound-sudo-script", "sudo ./bin/tool.sh && echo ok", compound=True),
        case("compound-source-no-args", "source && echo ok", compound=True),
        case("compound-source-missing", "source ./nope.rc && echo ok", compound=True),
        case(
            "compound-symlink-script",
            "./link.sh && echo ok",
            compound=True,
            tree={"proj/link.sh": {"symlink": "bin/tool.sh"}},
        ),
        case("compound-quoted-path", "sh 'scripts/a.sh' && true", compound=True),
        case("compound-unparseable", 'echo "open && ./bin/tool.sh', compound=True),
        case("compound-blank", "  ", compound=True),
    ]


def all_cases() -> list[dict[str, Any]]:
    cases = [*_single(), *_runners(), *_compound()]
    names = [item["name"] for item in cases]
    assert len(names) == len(set(names)), "duplicate case names"
    return cases
