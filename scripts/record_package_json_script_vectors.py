#!/usr/bin/env python3
"""Record parity vectors for package.json script recognition.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_package_json_script_vectors.py [snapshot_src]

The reference snapshot must predate the move of package script recognition
to the native runtime. Each vector lays out a small project tree, runs the
reference Python on one pasted command, and stores the answer with the tree
root replaced by ``<ROOT>``. The Rust tests in rust/crates/guard-runtime
rebuild each tree and compare. Deterministic output.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.runtime import package_json_scripts as reference  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"
ROOT_TOKEN = "<ROOT>"


def _package(scripts: object, *, name: object = "demo-app", extra: dict[str, object] | None = None) -> str:
    payload: dict[str, object] = {"name": name, "scripts": scripts}
    payload.update(extra or {})
    return json.dumps(payload, indent=2)


BASIC = _package(
    {
        "build": "vite build",
        "build:web": "vite build --mode web",
        "prebuild": "rm -rf dist",
        "postinstall": "husky install",
        "test": "vitest   run\n --coverage",
        "lint": "eslint .",
        "db:migrate:up": "prisma migrate deploy",
        "root": "echo root",
        "other": "echo other",
    }
)
ODD_NAMES = _package(
    {
        "a:b:c:d:e": "x",
        "Build Web!": "x",
        "1abc": "x",
        "x::y": "x",
        "café": "x",
        "a" * 50: "x",
        "UPPER:case": "x",
        "  padded  ": "x",
        "postlint": "x",
        "lint": "x",
        "": "x",
        "number": 5,
        "dev": "x" * 400,
    }
)
MANY = _package({f"task{index:03d}": f"echo {index}" for index in range(100)})

# (name, files, cwd, home, command)
CASES: list[tuple[str, dict[str, str], str, str, str]] = [
    ("pnpm_run_build", {"app/package.json": BASIC, "app/pnpm-lock.yaml": ""}, "app", "", "pnpm run build"),
    ("pnpm_run_nested", {"app/package.json": BASIC, "app/pnpm-lock.yaml": ""}, "app", "", "pnpm run build:web"),
    ("npm_test_shorthand", {"app/package.json": BASIC}, "app", "", "npm test"),
    ("npm_start_unlisted", {"app/package.json": BASIC}, "app", "", "npm start"),
    ("yarn_shorthand_is_not_run", {"app/package.json": BASIC, "app/yarn.lock": ""}, "app", "", "yarn test"),
    ("yarn_cwd_flag", {"app/sub/package.json": BASIC, "app/sub/yarn.lock": ""}, "app", "", "yarn --cwd sub run lint"),
    ("npm_prefix_assigned", {"app/sub/package.json": BASIC}, "app", "", "npm --prefix=sub run lint"),
    ("npm_c_flag_no_script", {"app/sub/package.json": BASIC}, "app", "", "npm -C sub run"),
    (
        "pnpm_dir_flag",
        {"app/sub/package.json": BASIC, "app/sub/pnpm-lock.yaml": ""},
        "app",
        "",
        "pnpm --dir sub run test",
    ),
    (
        "pnpm_workspace_dir",
        {"app/sub/package.json": BASIC},
        "app",
        "",
        "pnpm --workspace-dir=sub run-script db:migrate:up",
    ),
    ("bun_lockb", {"app/package.json": BASIC, "app/bun.lockb": ""}, "app", "", "bun run build"),
    ("bun_not_a_run", {"app/package.json": BASIC}, "app", "", "bun build"),
    ("npm_run_silent", {"app/package.json": BASIC}, "app", "", "npm run --silent build"),
    ("npm_double_dash", {"app/package.json": BASIC}, "app", "", "npm -- run lint"),
    ("npm_missing_script", {"app/package.json": BASIC}, "app", "", "npm run missing"),
    ("npm_cmd_suffix", {"app/package.json": BASIC}, "app", "", "npm.cmd run build"),
    ("npm_exe_path", {"app/package.json": BASIC}, "app", "", "/usr/local/bin/NPM.EXE run build"),
    ("quoted_manager", {"app/package.json": BASIC}, "app", "", "'npm' run build"),
    ("env_prefix_refused", {"app/package.json": BASIC}, "app", "", "FOO=1 npm run build"),
    ("pipeline_refused", {"app/package.json": BASIC}, "app", "", "npm run build | cat"),
    ("wrapper_refused", {"app/package.json": BASIC}, "app", "", "sudo npm run build"),
    ("chain_refused", {"app/package.json": BASIC}, "app", "", "npm run build && npm test"),
    ("redirect_refused", {"app/package.json": BASIC}, "app", "", "npm run build > out.txt"),
    ("not_a_manager", {"app/package.json": BASIC}, "app", "", "make build"),
    ("empty_command", {"app/package.json": BASIC}, "app", "", "   "),
    (
        "walk_up",
        {"app/package.json": BASIC, "app/pnpm-lock.yaml": "", "app/src/lib/x.txt": ""},
        "app/src/lib",
        "",
        "npm run lint",
    ),
    ("stops_at_home", {"package.json": BASIC, "home/proj/x.txt": ""}, "home/proj", "home", "npm run lint"),
    ("walk_limit", {"package.json": BASIC, "a/b/c/d/e/f/g/h/i/x.txt": ""}, "a/b/c/d/e/f/g/h/i", "", "npm run lint"),
    ("prefix_missing_dir", {"app/package.json": BASIC}, "app", "", "npm --prefix nowhere run build"),
    ("path_manifest", {"app/package.json": BASIC, "app/yarn.lock": ""}, "", "", "app/package.json"),
    ("path_manifest_trailing_slash", {"app/package.json": BASIC}, "", "", "app/package.json/"),
    ("path_directory", {"app/package.json": BASIC}, "", "", "app"),
    ("path_dot", {"app/package.json": BASIC}, "app", "", "."),
    ("path_home_tilde", {"home/proj/package.json": BASIC}, "", "home", "~/proj"),
    ("path_absolute_root_token", {"app/package.json": BASIC}, "", "", "<ROOT>/app"),
    ("path_dir_without_manifest", {"app/x.txt": ""}, "", "", "app"),
    ("path_other_json", {"app/other.json": BASIC}, "", "", "app/other.json"),
    ("odd_script_names", {"app/package.json": ODD_NAMES}, "app", "", "npm run Build Web!"),
    ("odd_focused_nested", {"app/package.json": ODD_NAMES}, "app", "", "npm run UPPER:case"),
    ("many_scripts", {"app/package.json": MANY}, "app", "", "npm run task050"),
    ("scoped_name", {"app/package.json": _package({"dev": "x"}, name=" @scope/pkg ")}, "app", "", "npm run dev"),
    ("blank_name", {"proj-dir/package.json": _package({"dev": "x"}, name="  ")}, "proj-dir", "", "npm run dev"),
    ("numeric_name", {"proj-dir/package.json": _package({"dev": "x"}, name=7)}, "proj-dir", "", "npm run dev"),
    ("scripts_not_object", {"app/package.json": _package(["build"])}, "app", "", "npm run build"),
    ("manifest_not_object", {"app/package.json": "[1, 2]"}, "app", "", "npm run build"),
    ("manifest_invalid_json", {"app/package.json": "{nope"}, "app", "", "npm run build"),
    ("manifest_empty", {"app/package.json": ""}, "app", "", "npm run build"),
    (
        "lockfile_precedence",
        {"app/package.json": BASIC, "app/yarn.lock": "", "app/pnpm-lock.yaml": "", "app/package-lock.json": ""},
        "app",
        "",
        "npm run build",
    ),
    ("shrinkwrap_runner", {"app/package.json": BASIC, "app/npm-shrinkwrap.json": ""}, "app", "", "yarn run build"),
    (
        "pre_post_companions",
        {"app/package.json": _package({"test": "a", "pretest": "b", "posttest": "c", "prefix": "d", "post": "e"})},
        "app",
        "",
        "npm run test",
    ),
]


def _detokenize(text: str, root: Path) -> str:
    return text.replace(str(root), ROOT_TOKEN)


def _record(root: Path, cwd: Path, home: Path, command: str) -> dict[str, object] | None:
    invocation = reference.parse_package_script_invocation(command, cwd=cwd, home_dir=home)
    if invocation is None:
        return None
    manifest, runner, focused = invocation
    payload, digest = reference._read_package_payload(manifest)
    scripts = reference._read_scripts(manifest)
    merged = reference.commands_from_package_scripts(scripts, runner=runner, focused_script=focused)
    tokens = reference.package_script_command_tokens(command, cwd=cwd, home_dir=home)
    return {
        "manifest_path": _detokenize(str(manifest), root),
        "runner": runner,
        "focused_script": focused,
        "focused_listed": bool(focused and focused in scripts),
        "source": {
            "source": "package_json",
            "manifest_path": _detokenize(str(manifest.resolve()), root),
            "content_sha256": digest,
            "package_name": reference._package_name(payload, manifest.parent),
        },
        "commands": [
            {
                "command_id": command_item.command_id,
                "name": command_item.name,
                "usage": command_item.usage,
                "description": command_item.description,
                "parent_id": command_item.parent_id,
            }
            for command_item in (merged[1:-1] if scripts else ())
        ],
        "command_tokens": list(tokens or ()),
    }


def main() -> None:
    vectors: list[dict[str, object]] = []
    for name, files, cwd_rel, home_rel, command in CASES:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            cwd = root / cwd_rel if cwd_rel else root
            home = root / home_rel if home_rel else root / "no-home"
            live_command = command.replace(ROOT_TOKEN, str(root))
            vectors.append(
                {
                    "name": name,
                    "files": files,
                    "cwd": cwd_rel,
                    "home": home_rel,
                    "command": command,
                    "expected": _record(root, cwd, home, live_command),
                }
            )
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "package_json_script_vectors.json"
    target.write_text(json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {target}")


if __name__ == "__main__":
    main()
