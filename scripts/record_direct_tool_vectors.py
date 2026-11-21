"""Freeze synthetic direct-tool verdicts from explicitly pinned Git objects.

Legacy source is executed only in memory to record a migration baseline. The
fixture is portable data; neither runtime imports nor native tests load an old
Python implementation.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from record_direct_tool_public import load_services, record_public

SOURCE = "src/codex_plugin_scanner/guard/runtime/direct_vitest.py"
JSONC = "src/codex_plugin_scanner/guard/runtime/jsonc.py"


def source_at(repo: Path, commit: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo)


def load_baseline(repo: Path, commit: str) -> tuple[dict[str, Any], dict[str, str]]:
    sources = {path: source_at(repo, commit, path) for path in (SOURCE, JSONC)}
    jsonc: dict[str, Any] = {"__name__": "recorded_jsonc"}
    exec(compile(sources[JSONC], JSONC, "exec"), jsonc)
    tree = ast.parse(sources[SOURCE], filename=SOURCE)
    # The recorded leaf checks do not call imported runtime services. Keep
    # their original function bodies; do not substitute algorithmic helpers.
    tree.body = [node for node in tree.body if not isinstance(node, ast.ImportFrom) or node.level == 0]
    services, service_hashes = load_services(repo, commit, source_at)
    namespace: dict[str, Any] = {**services, "__name__": "recorded_direct_tools", "loads_jsonc": jsonc["loads_jsonc"]}
    namespace["_semver_spec_matches"] = services["node_semver_spec_matches"]
    exec(compile(tree, SOURCE, "exec"), namespace)
    return namespace, {**service_hashes, **{path: hashlib.sha256(data).hexdigest() for path, data in sources.items()}}


def file_cases(check: str, name: str, texts: list[str]) -> list[dict[str, Any]]:
    return [{"check": check, "name": name, "bytes_hex": text.encode().hex()} for text in texts]


def cases() -> list[dict[str, Any]]:
    rows = file_cases(
        "bunfig",
        "bunfig.toml",
        [
            "[install]\n",
            '[install]\nlinker="hoisted"',
            '[install]\nlinker="isolated"',
            "[install]\nsmol=true",
            "[install]\nsmol=false",
            "[install.lockfile]\nsave=true",
            "[install.lockfile]\nsave=false",
            "[install.lockfile]\n",
            "[install]\nsmol=1",
            '[install]\nlinker="other"',
            "[install]\ncache=true",
            "[install.lockfile]\nsave=1",
            "[install.lockfile]\nsave=true\nother=false",
            "[run]\nsmol=true",
            "",
            "[install",
        ],
    )
    rows += file_cases(
        "package_json",
        "package.json",
        [
            "{}",
            '{"name":"synthetic","version":"1.2.3"}',
            "[]",
            "null",
            '"package"',
            '{"name":1}',
            '{"version":"first","version":"second"}',
            '{"name":"é"}',
            '{"name":"a",}',
            "// comment\n{}",
            "{",
        ],
    )
    integrity = "sha512-" + base64.b64encode(b"\x09" * 64).decode()
    entries = [
        ["typescript@5.9.3", "", {}, integrity],
        ["typescript@", "", {}, integrity],
        ["other@5.9.3", "", {}, integrity],
        ["typescript@5.9.3"],
        [],
        None,
        [1, "", {}, integrity],
        ["typescript@5.9.3", "", {}, None],
        ["typescript@5.9.3", "", {}, "sha256-" + integrity[7:]],
        ["typescript@5.9.3", "", {}, "sha512-" + base64.b64encode(b"short").decode()],
        ["typescript@5.9.3", "", {}, integrity + "!"],
        ["typescript@5.9.3", "", {}, integrity + "\n"],
    ]
    rows += file_cases(
        "bun_identity", "bun.lock", [json.dumps({"packages": {"typescript": entry}}) for entry in entries]
    )
    rows += file_cases(
        "bun_identity",
        "bun.lock",
        [
            '{"packages":{}}',
            '{"packages":[]}',
            '{"packages":{"typescript":["typescript@5.9.3","",{},"' + integrity + '",],},}',
        ],
    )
    for name in ("bun.lock", "package-lock.json"):
        key = "vitest" if name == "bun.lock" else "node_modules/vitest"
        values: list[Any] = (
            [["vitest@2.1.0"], ["other@2.1.0"], [], [1], None]
            if name == "bun.lock"
            else [
                {"version": "2.1.0"},
                {"version": 1},
                {},
                None,
                ["vitest@2.1.0"],
            ]
        )
        rows += file_cases("locked_version", name, [json.dumps({"packages": {key: value}}) for value in values])
    for check, name in (
        ("bunfig", "bunfig.toml"),
        ("package_json", "package.json"),
        ("bun_identity", "bun.lock"),
        ("locked_version", "bun.lock"),
    ):
        for kind in ("missing", "directory", "symlink", "oversize", "invalid_utf8"):
            rows.append({"check": check, "name": name, "kind": kind})
    trees = [
        [],
        [{"path": "a", "bytes_hex": ""}],
        [{"path": "b", "bytes_hex": "62"}, {"path": "a", "bytes_hex": "61"}],
        [
            {"path": "z", "bytes_hex": "7a"},
            {"path": "dir/a", "bytes_hex": "61"},
            {"path": "dir/deep/b", "bytes_hex": "62"},
        ],
        [{"path": "é/😀", "bytes_hex": "00ff"}],
        [{"path": "a\\b", "bytes_hex": "61"}],
    ]
    rows += [{"check": "tree", "files": files} for files in trees]
    rows += [
        {"check": "tree", "files": [], "kind": kind}
        for kind in ("root_symlink", "file_symlink", "dir_symlink", "oversize")
    ]
    for value in (
        "a.test.ts",
        "nested/a.spec.ts",
        "nested/../a.test.ts",
        "a.ts",
        "missing.test.ts",
        "nested",
        "link.test.ts",
        "nested/link.test.ts",
        "../outside.test.ts",
        "/a.test.ts",
        "~/a.test.ts",
        "a.TEST.ts",
        "$a.test.ts",
        "`a`.test.ts",
        "a.test.ts>out",
    ):
        rows.append({"check": "target", "value": value})
    rows += [
        {"check": "heap", "value": value}
        for value in (
            "NODE_OPTIONS=--max-old-space-size=256",
            "NODE_OPTIONS=--max-old-space-size=32768",
            "NODE_OPTIONS=--max-old-space-size=255",
            "NODE_OPTIONS=--max-old-space-size=32769",
            "NODE_OPTIONS=--max-old-space-size=0256",
            "NODE_OPTIONS=--max-old-space-size=1024",
            "NODE_OPTIONS=--max-old-space-size=256\n",
            "NODE_OPTIONS=--max-old-space-size=256 --preload=x",
            "NODE_OPTIONS=--max-old-space-size=٢٥٦",
            "NODE_OPTIONS=--max-old-space-size=999999",
        )
    ]
    rows += [
        {"check": "dynamics", "value": value}
        for value in ("literal", "$value", "`value`", "a\x00b", "a>b", "a<b", "a\\b", "a;b")
    ]
    rows += [
        {"check": "semver", "specifier": specifier, "version": version}
        for specifier, version in [
            ("4.1.8", "4.1.8"),
            ("^4.1.8", "4.2.0"),
            ("^4.1.8", "5.0.0"),
            ("~4.1.8", "4.1.9"),
            ("~4.1.8", "4.2.0"),
            ("^0.2.3", "0.2.4"),
            ("^0.0.3", "0.0.4"),
            ("4.1.8-beta.1", "4.1.8-beta.1"),
            ("^4.1.8", "4.2.0-beta.1"),
            ("*", "4.1.8"),
            (">=4.1.0", "4.1.8"),
            ("4.x", "4.1.8"),
            ("4.1.8 || 5.0.0", "4.1.8"),
            ("v4.1.8", "4.1.8"),
            ("4.1.8 ", "4.1.8"),
            ("04.01.008", "4.1.8"),
            ("^\u0664.\u0661.\u0668", "4.2.0"),
            ("4.1.8", "4.1.8+metadata"),
            ("999999999999999999999999.1.8", "999999999999999999999999.1.8"),
        ]
    ]
    return rows


def materialize_file(root: Path, case: dict[str, Any]) -> Path:
    path = root / case["name"]
    kind = case.get("kind", "file")
    if kind == "missing":
        return path
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = root / "synthetic-target"
        target.write_text("{}")
        path.symlink_to(target)
    elif kind == "oversize":
        with path.open("wb") as handle:
            handle.truncate(16 * 1024 * 1024 + 1)
    elif kind == "invalid_utf8":
        path.write_bytes(b"\xff")
    else:
        path.write_bytes(bytes.fromhex(case["bytes_hex"]))
    return path


def evaluate(namespace: dict[str, Any], root: Path, case: dict[str, Any]) -> Any:
    check = case["check"]
    if check == "semver":
        return namespace["_semver_spec_matches"](case["specifier"], case["version"])
    if check in {"heap", "dynamics"}:
        function = "_safe_node_heap_assignment" if check == "heap" else "_has_shell_dynamics"
        return namespace[function](case["value"])
    if check in {"bunfig", "package_json", "bun_identity", "locked_version"}:
        path = materialize_file(root, case)
        function = {
            "bunfig": "_bunfig_is_install_only",
            "package_json": "_read_package_json",
            "bun_identity": "_locked_bun_package_identity",
            "locked_version": "_locked_package_version",
        }[check]
        return (
            namespace[function](path, "typescript" if check == "bun_identity" else "vitest")
            if check in {"bun_identity", "locked_version"}
            else namespace[function](path)
        )
    workspace = root / "workspace"
    workspace.mkdir()
    if check == "tree":
        for file in case["files"]:
            path = workspace / file["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes.fromhex(file["bytes_hex"]))
        kind = case.get("kind")
        if kind == "root_symlink":
            link = root / "link"
            link.symlink_to(workspace, target_is_directory=True)
            workspace = link
        elif kind in {"file_symlink", "dir_symlink"}:
            outside = root / "outside"
            outside.mkdir() if kind == "dir_symlink" else outside.write_text("synthetic")
            (workspace / "link").symlink_to(outside, target_is_directory=kind == "dir_symlink")
        elif kind == "oversize":
            with (workspace / "large").open("wb") as handle:
                handle.truncate(128 * 1024 * 1024 + 1)
        try:
            return namespace["_package_tree_digest"](workspace)
        except (OSError, RuntimeError, ValueError):
            return None
    for name in ("a.test.ts", "a.TEST.ts", "nested/a.spec.ts"):
        path = workspace / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("synthetic test")
    outside = root / "outside.test.ts"
    outside.write_text("synthetic outside")
    (workspace / "link.test.ts").symlink_to(workspace / "a.test.ts")
    (workspace / "nested/link.test.ts").symlink_to(outside)
    return namespace["_contained_test_target"](case["value"], workspace=workspace)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(
        ["git", "rev-parse", f"{args.base_commit}^{{commit}}"], cwd=repo, text=True
    ).strip()
    namespace, hashes = load_baseline(repo, commit)
    recorded = []
    for case in cases():
        with tempfile.TemporaryDirectory(prefix="guard-direct-tool-record-") as temporary:
            expected = evaluate(namespace, Path(temporary).resolve(), case)
        recorded.append({**case, "expected": expected})
    payload = {
        "schema": "hol-guard.direct-tool-python.v1",
        "base_commit": commit,
        "source_sha256": hashes,
        "cases": recorded,
    }
    public_fixture, public_recorded = record_public(namespace)
    payload["public_fixture"] = public_fixture
    payload["public_cases"] = public_recorded
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n")
    print(f"recorded {len(recorded)} leaf and {len(public_recorded)} public cases from {commit[:12]}")


if __name__ == "__main__":
    main()
