"""Record local tool approval eligibility from the Python owner before it retires.

Run with the source tree whose ``local_tool_approval_eligibility``
(``guard/trusted_local_tools.py``) still derived eligibility in Python, with a
native runtime available for shell parsing and launch identities. The Python
owner was deleted when the resident ``local_tool_eligibility`` op replaced it,
so this script no longer runs against the current tree; it documents how
``vectors.json`` was produced.

Every vector runs against one fixture tree, which is recorded verbatim so the
Rust replay can rebuild it byte for byte. Paths below the fixture root become
``<root>``. Identity material is recorded with the per-machine stat fields
(device, inode and timestamps) replaced by ``<stat>``; ``material_sha256`` is
Python's canonical JSON digest of that normalized material, so the replay
checks both the material and its encoding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.runtime.routine_node_identity import routine_package_tree_digest

from codex_plugin_scanner.guard import trusted_local_tools
from codex_plugin_scanner.guard.runtime import routine_local_node

ROOT = "<root>"
INTEGRITY = "sha512-Zml4dHVyZS10ZXN0LWludGVncml0eQ=="
STAT_KEYS = frozenset({"device", "inode", "change_time_ns", "modified_time_ns"})
RUNNER_SCRIPT = "#!/usr/bin/env node\n"


def _file(path: str, content: str, mode: int = 0o644) -> dict[str, Any]:
    return {"path": path, "type": "file", "content": content, "mode": mode}


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2) + "\n"


def _routine_workspace(
    name: str,
    *,
    runner: str,
    package: str,
    version: str,
    specifier: str,
    target: str,
    lock: str = "npm",
    package_dependencies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    base = f"home/{name}"
    manifest: dict[str, object] = {"name": package, "version": version, "bin": {runner: target}}
    if package_dependencies:
        manifest["dependencies"] = package_dependencies
    entries = [
        _file(f"{base}/package.json", _json_text({"name": name, "devDependencies": {package: specifier}})),
        _file(f"{base}/node_modules/{package}/package.json", _json_text(manifest)),
        _file(f"{base}/node_modules/{package}/{target}", RUNNER_SCRIPT, 0o755),
        _file(f"{base}/node_modules/{package}/lib/index.js", f"module.exports = '{package}';\n"),
        {
            "path": f"{base}/node_modules/.bin/{runner}",
            "type": "symlink",
            "target": f"../{package}/{target}",
        },
    ]
    if lock == "npm":
        lock_payload = {
            "lockfileVersion": 3,
            "packages": {
                f"node_modules/{package}": {
                    "version": version,
                    "resolved": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
                    "integrity": INTEGRITY,
                }
            },
        }
        entries.append(_file(f"{base}/package-lock.json", _json_text(lock_payload)))
    else:
        entries.append(
            _file(
                f"{base}/bun.lock",
                '{\n  // bun lockfile\n  "lockfileVersion": 1,\n  "packages": {\n'
                f'    "{package}": ["{package}@{version}", "", {{}}, "{INTEGRITY}"],\n'
                "  },\n}\n",
            )
        )
    return entries


def _eslint_workspace(name: str) -> list[dict[str, Any]]:
    return [
        *_routine_workspace(
            name,
            runner="eslint",
            package="eslint",
            version="9.1.0",
            specifier="^9.0.0",
            target="bin/eslint.js",
            package_dependencies={"dep-a": "^1.0.0"},
        ),
        _file(f"home/{name}/node_modules/eslint/node_modules/.bin/inner", "inner\n", 0o755),
        _file(f"home/{name}/node_modules/dep-a/package.json", _json_text({"name": "dep-a", "version": "1.0.0"})),
        _file(f"home/{name}/node_modules/dep-a/index.js", "module.exports = 1;\n"),
        _file(f"home/{name}/src/index.js", "export const value = 1;\n"),
    ]


def fixture_entries() -> list[dict[str, Any]]:
    entries = [
        _file("bin/node", "fake node runtime\n", 0o755),
        _file("bin/python3", "fake python runtime\n", 0o755),
        _file("bin/jq", "fake jq processor\n", 0o755),
        _file("bin/npx", "fake npx runner\n", 0o755),
        _file("bin/bunx", "fake bunx runner\n", 0o755),
        _file("bin/xcli", "fake local cli\n", 0o755),
        _file("home/active/tool.mjs", "export const version = 1;\n"),
        _file("home/active/tool.py", "print('tool')\n"),
        _file("home/active/filter.jq", ".data\n"),
        _file("home/active/src/a.tsx", "export const A = () => null;\n"),
        _file("home/active/docs/context.md", "# Context\n"),
        _file("home/active/.env", "TOKEN=fixture\n"),
        _file("outside/report.txt", "outside\n"),
    ]
    entries += [
        *_routine_workspace(
            "ws-next",
            runner="next",
            package="next",
            version="16.3.0-preview.8",
            specifier="16.3.0-preview.8",
            target="dist/bin/next",
        ),
        _file("home/ws-next/next.config.mjs", "export default { reactStrictMode: true };\n"),
    ]
    entries += [
        *_eslint_workspace("ws-eslint"),
        _file(
            "home/ws-eslint/eslint.config.mjs",
            'import rules from "./config/rules.mjs";\nimport demo from "eslint-plugin-demo";\n'
            "export default [rules, demo];\n",
        ),
        _file("home/ws-eslint/config/rules.mjs", "export default { rules: {} };\n"),
        _file(
            "home/ws-eslint/node_modules/eslint-plugin-demo/package.json",
            _json_text(
                {
                    "name": "eslint-plugin-demo",
                    "version": "2.0.0",
                    "dependencies": {"dep-a": "1.0.0", "not-installed": "1.0.0"},
                }
            ),
        ),
        _file("home/ws-eslint/node_modules/eslint-plugin-demo/index.js", "module.exports = {};\n"),
    ]
    entries += [*_eslint_workspace("ws-yaml"), _file("home/ws-yaml/.eslintrc.yml", "root: true\n")]
    entries += [
        *_eslint_workspace("ws-computed"),
        _file("home/ws-computed/eslint.config.js", 'const name = "./rules";\nmodule.exports = require(name);\n'),
    ]
    entries += [
        *_routine_workspace(
            "ws-tsc",
            runner="tsc",
            package="typescript",
            version="5.4.5",
            specifier="~5.4.0",
            target="bin/tsc",
            lock="bun",
        ),
        _file(
            "home/ws-tsc/tsconfig.json",
            _json_text({"extends": "./tsconfig.base.json", "compilerOptions": {"strict": True}}),
        ),
        _file("home/ws-tsc/tsconfig.base.json", _json_text({"compilerOptions": {"target": "es2022"}})),
    ]
    entries += _routine_workspace(
        "ws-untrusted",
        runner="next",
        package="next",
        version="15.0.0",
        specifier="^15.0.0",
        target="dist/bin/next",
    )
    return entries


def build_fixture(root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        path = root / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if entry["type"] == "symlink":
            path.symlink_to(entry["target"])
            continue
        _ = path.write_bytes(entry["content"].encode("utf-8"))
        path.chmod(entry["mode"])
    for directory in ("home/active", "home"):
        (root / directory).mkdir(parents=True, exist_ok=True)


def trusted_trees(root: Path) -> list[list[str]]:
    trees = {
        ("next", "16.3.0-preview.8"): "home/ws-next/node_modules/next",
        ("eslint", "9.1.0"): "home/ws-eslint/node_modules/eslint",
        ("typescript", "5.4.5"): "home/ws-tsc/node_modules/typescript",
    }
    return [
        [package, version, INTEGRITY, routine_package_tree_digest(root / relative)]
        for (package, version), relative in trees.items()
    ]


ACTIVE = f"{ROOT}/home/active"
HOME = f"{ROOT}/home"

CASES: list[tuple[str, str, str, str | None]] = [
    # Routine local Node profiles.
    (
        "routine_next_env_and_tail",
        f"cd {ROOT}/home/ws-next && HOL_NEXT_BUILD_CPUS=4 NODE_OPTIONS=--max-old-space-size=4096 "
        "./node_modules/.bin/next build --webpack 2>&1 | tail -30",
        ACTIVE,
        HOME,
    ),
    ("routine_next_relative_cd_rejected", "cd ws-next && ./node_modules/.bin/next build --webpack", ACTIVE, HOME),
    ("routine_next_plain", f"cd {ROOT}/home/ws-next && ./node_modules/.bin/next build --webpack", ACTIVE, HOME),
    ("routine_next_missing_webpack", f"cd {ROOT}/home/ws-next && ./node_modules/.bin/next build", ACTIVE, HOME),
    (
        "routine_eslint_absolute_cd_head",
        f"cd {ROOT}/home/ws-eslint && ./node_modules/.bin/eslint src --max-warnings 0 --quiet 2>&1 | head -40",
        ACTIVE,
        HOME,
    ),
    ("routine_eslint_fix_rejected", f"cd {ROOT}/home/ws-eslint && ./node_modules/.bin/eslint --fix src", ACTIVE, HOME),
    (
        "routine_eslint_external_target",
        f"cd {ROOT}/home/ws-eslint && ./node_modules/.bin/eslint ../other",
        ACTIVE,
        HOME,
    ),
    (
        "routine_eslint_superscript_warnings",
        f"cd {ROOT}/home/ws-eslint && ./node_modules/.bin/eslint src --max-warnings ²",
        ACTIVE,
        HOME,
    ),
    (
        "routine_eslint_fraction_warnings",
        f"cd {ROOT}/home/ws-eslint && ./node_modules/.bin/eslint src --max-warnings ½",
        ACTIVE,
        HOME,
    ),
    (
        "routine_tsc_bun_lock",
        f"cd {ROOT}/home/ws-tsc && ./node_modules/.bin/tsc --noEmit --pretty false -p tsconfig.json",
        ACTIVE,
        HOME,
    ),
    (
        "routine_tsc_unbounded_tail",
        f"cd {ROOT}/home/ws-tsc && ./node_modules/.bin/tsc --noEmit | tail -5000",
        ACTIVE,
        HOME,
    ),
    ("routine_tsc_home_from_cwd", f"cd {ROOT}/home/ws-tsc && ./node_modules/.bin/tsc --noEmit", HOME, None),
    ("routine_yaml_config_rejected", f"cd {ROOT}/home/ws-yaml && ./node_modules/.bin/eslint src", ACTIVE, HOME),
    (
        "routine_computed_require_rejected",
        f"cd {ROOT}/home/ws-computed && ./node_modules/.bin/eslint src",
        ACTIVE,
        HOME,
    ),
    (
        "routine_untrusted_tree",
        f"cd {ROOT}/home/ws-untrusted && ./node_modules/.bin/next build --webpack",
        ACTIVE,
        HOME,
    ),
    (
        "routine_command_substitution",
        f"cd {ROOT}/home/ws-next && ./node_modules/.bin/next build $(echo --webpack)",
        ACTIVE,
        HOME,
    ),
    # Package profiles.
    ("package_impeccable_detect", "npx impeccable detect src/a.tsx", ACTIVE, HOME),
    ("package_impeccable_pinned_indefinite", "npx impeccable@1.2.3 detect --json src", ACTIVE, HOME),
    ("package_impeccable_latest_fast", "npx impeccable@latest src --fast", ACTIVE, HOME),
    ("package_impeccable_context_dir", "IMPECCABLE_CONTEXT_DIR=docs npx impeccable detect src", ACTIVE, HOME),
    ("package_impeccable_home_path", "bunx impeccable detect ~/active/src", ACTIVE, HOME),
    ("package_impeccable_skills_rejected", "npx impeccable skills add", ACTIVE, HOME),
    ("package_impeccable_secret_rejected", "npx impeccable detect .env", ACTIVE, HOME),
    ("package_impeccable_outside_rejected", f"npx impeccable detect {ROOT}/outside/report.txt", ACTIVE, HOME),
    ("package_impeccable_url_rejected", "npx impeccable detect https://example.com/a", ACTIVE, HOME),
    ("package_impeccable_option_rejected", "npx impeccable detect --write src", ACTIVE, HOME),
    ("package_impeccable_piped_falls_through", "npx impeccable detect src | jq .", ACTIVE, HOME),
    # Verified-file tools.
    (
        "verified_http_get",
        "node tool.mjs request --method=GET --path=/stats --query='entity=A&start=1'",
        ACTIVE,
        HOME,
    ),
    ("verified_http_head_short_option", "node tool.mjs fetch -X head --limit 5", ACTIVE, HOME),
    ("verified_http_post_rejected", "node tool.mjs request --method POST", ACTIVE, HOME),
    ("verified_http_missing_method", "node tool.mjs request --method", ACTIVE, HOME),
    ("verified_http_two_methods", "node tool.mjs api --method=GET --request=GET", ACTIVE, HOME),
    ("verified_method_on_read_operation", "node tool.mjs list --method=GET", ACTIVE, HOME),
    ("verified_python_status", "python3 tool.py status --verbose", ACTIVE, HOME),
    ("verified_xcli_check", "xcli check", ACTIVE, HOME),
    ("verified_xcli_describe_shape", "xcli describe item -v --path /a --query=x -- tail", ACTIVE, HOME),
    ("verified_xcli_diff", "xcli diff a b", ACTIVE, HOME),
    ("verified_xcli_find_upper", "xcli FIND name", ACTIVE, HOME),
    ("verified_xcli_get", "xcli get key --format=json", ACTIVE, HOME),
    ("verified_xcli_inspect", "xcli inspect", ACTIVE, HOME),
    ("verified_xcli_list", "xcli list --limit 10", ACTIVE, HOME),
    ("verified_xcli_query", "xcli query --path=/a", ACTIVE, HOME),
    ("verified_xcli_read", "xcli read file.txt", ACTIVE, HOME),
    ("verified_xcli_report", "xcli report -", ACTIVE, HOME),
    ("verified_xcli_search", "xcli search term", ACTIVE, HOME),
    ("verified_xcli_show", "xcli show", ACTIVE, HOME),
    ("verified_xcli_status", "xcli status", ACTIVE, HOME),
    ("verified_xcli_mutating_operation", "xcli deploy", ACTIVE, HOME),
    ("verified_xcli_option_first", "xcli --help", ACTIVE, HOME),
    ("verified_side_effect_output", "node tool.mjs get --output=out.json", ACTIVE, HOME),
    ("verified_side_effect_short_o", "xcli list -o out", ACTIVE, HOME),
    ("verified_side_effect_upper", "xcli show --FORCE", ACTIVE, HOME),
    ("verified_inline_entrypoint_rejected", "node -e 'console.log(1)' get", ACTIVE, HOME),
    ("verified_missing_entrypoint_rejected", "node missing.mjs get", ACTIVE, HOME),
    ("verified_unknown_executable", "not-installed-cli list", ACTIVE, HOME),
    # Output processors.
    ("jq_safe_filter", "node tool.mjs get --path=/a | jq -r '.data[0]'", ACTIVE, HOME),
    ("jq_safe_long_options", "xcli list | jq --sort-keys --compact-output .", ACTIVE, HOME),
    ("jq_unsafe_argument", "xcli list | jq --arg name value .", ACTIVE, HOME),
    ("jq_file_filter_rejected", "xcli list | jq -f filter.jq", ACTIVE, HOME),
    ("jq_two_filters_rejected", "xcli list | jq .a .b", ACTIVE, HOME),
    ("jq_missing_filter_rejected", "xcli list | jq -r", ACTIVE, HOME),
    ("processor_not_jq_rejected", "xcli list | head -5", ACTIVE, HOME),
    # Shell structure rejections.
    ("redirect_rejected", "xcli list > out.txt", ACTIVE, HOME),
    ("chaining_rejected", "xcli list && xcli show", ACTIVE, HOME),
    ("sequence_rejected", "xcli list; xcli show", ACTIVE, HOME),
    ("embedded_command_rejected", "xcli get $(whoami)", ACTIVE, HOME),
    ("environment_prefix_rejected", "FOO=1 xcli list", ACTIVE, HOME),
    ("nohup_prefix", "nohup xcli list", ACTIVE, HOME),
    ("env_wrapper", "env xcli list", ACTIVE, HOME),
    ("sudo_wrapper_rejected", "sudo xcli list", ACTIVE, HOME),
    ("three_segments_rejected", "xcli list | jq . | jq .", ACTIVE, HOME),
    ("non_exact_parse_rejected", "xcli list 'unterminated", ACTIVE, HOME),
]


def _normalize(value: object, root: str) -> object:
    if isinstance(value, dict):
        return {key: "<stat>" if key in STAT_KEYS else _normalize(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item, root) for item in value]
    if isinstance(value, str):
        return value.replace(root, ROOT)
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@contextmanager
def _recording_environment(root: Path, trees: list[list[str]]) -> Iterator[list[object]]:
    saved_environment = dict(os.environ)
    saved_trees = dict(routine_local_node.TRUSTED_PACKAGE_TREES)
    saved_canonical = trusted_local_tools._canonical_json
    captured: list[object] = []

    def capture(value: object) -> bytes:
        captured.append(value)
        return saved_canonical(value)

    native = {key: value for key, value in os.environ.items() if key.startswith("HOL_GUARD") or key == "TMPDIR"}
    os.environ.clear()
    os.environ.update({**native, "PATH": str(root / "bin"), "HOME": str(root / "home")})
    routine_local_node.TRUSTED_PACKAGE_TREES.clear()
    routine_local_node.TRUSTED_PACKAGE_TREES.update({(p, v, i): d for p, v, i, d in trees})
    trusted_local_tools._canonical_json = capture  # type: ignore[assignment]
    try:
        yield captured
    finally:
        trusted_local_tools._canonical_json = saved_canonical  # type: ignore[assignment]
        routine_local_node.TRUSTED_PACKAGE_TREES.clear()
        routine_local_node.TRUSTED_PACKAGE_TREES.update(saved_trees)
        os.environ.clear()
        os.environ.update(saved_environment)


def build() -> dict[str, Any]:
    entries = fixture_entries()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        build_fixture(root, entries)
        trees = trusted_trees(root)
        text_root = str(root)
        vectors: list[dict[str, Any]] = []
        with _recording_environment(root, trees) as captured:
            for name, command, cwd, home_dir in CASES:
                captured.clear()
                result = trusted_local_tools.local_tool_approval_eligibility(
                    command.replace(ROOT, text_root),
                    cwd=Path(cwd.replace(ROOT, text_root)),
                    home_dir=Path(home_dir.replace(ROOT, text_root)) if home_dir is not None else None,
                )
                expected: dict[str, Any] | None = None
                if result is not None:
                    material = captured[-1]
                    assert hashlib.sha256(_canonical(material)).hexdigest() == result.tool_identity_hash
                    normalized = _normalize(material, text_root)
                    expected = {
                        "tool_name": result.tool_name,
                        "capability": result.capability,
                        "read_only_reason": result.read_only_reason,
                        "trust_basis": result.trust_basis,
                        "indefinite_allowed": result.indefinite_allowed,
                        "material": normalized,
                        "material_sha256": hashlib.sha256(_canonical(normalized)).hexdigest(),
                    }
                vectors.append(
                    {"name": name, "command": command, "cwd": cwd, "home_dir": home_dir, "expected": expected}
                )
    return {
        "schema": "guard-local-tool-eligibility-vectors.v1",
        "launch_env": {"PATH": f"{ROOT}/bin", "HOME": HOME},
        "user_home": HOME,
        "fixture": entries,
        "trusted_trees": trees,
        "vectors": vectors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("vectors.json"))
    options = parser.parse_args()
    options.output.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
