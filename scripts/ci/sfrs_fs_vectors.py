"""Record parity vectors for SFRS helpers that read the filesystem.

Usage: ``sfrs_fs_vectors.py FIXTURE_DIR``. A fixed directory tree is built under
a fresh root; each case calls a Python helper with paths below that root and
stores the result. Paths are stored with the ``{ROOT}`` token so the Rust port
can rebuild the same tree under its own root and replay every case. This script
depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import functools
import gzip
import json
import operator
import os
import sys
import tempfile
from pathlib import Path

from sfrs_graph_cases import graph_cases
from sfrs_pr_expansion_cases import pr_expansion_cases
from sfrs_quote_cases import quote_cases

from codex_plugin_scanner.guard.runtime.secret_file_request_services import source_edit_context

TOKEN = "{ROOT}"

TREE = {
    "dirs": [
        "home/proj/.git",
        "home/proj/src",
        "home/proj/src/nested",
        "home/.hidden/.git",
        "home/bare",
        "home/cargo",
        "home/gomod",
        "home/pyproj",
        "home/node/src",
        "home/node/node_modules/.bin",
        "elsewhere",
    ],
    "files": {
        "home/proj/package.json": "{}",
        "home/proj/src/a.txt": "alpha\n",
        "home/proj/src/b.txt": "beta\n",
        "home/proj/src/nested/c.txt": "gamma\n",
        "home/.hidden/x.txt": "x\n",
        "home/bare/f.txt": "f\n",
        "home/cargo/Cargo.toml": "",
        "home/gomod/go.mod": "",
        "home/pyproj/pyproject.toml": "",
        "home/node/package.json": "{}",
        "home/node/node_modules/.bin/eslint": "#!/bin/sh\n",
        "home/node/node_modules/.bin/jest": "#!/bin/sh\n",
        "elsewhere/out.txt": "out\n",
    },
    "links": {
        "home/proj/link.txt": "src/a.txt",
        "home/proj/dirlink": "src",
        "home/proj/outside.txt": "../../elsewhere/out.txt",
        "home/proj/dangling.txt": "src/missing.txt",
        "home/node/node_modules/.bin/vitest": "../../../../elsewhere/out.txt",
        "home/proj/loop1": "loop2",
        "home/proj/loop2": "loop1",
    },
}

SCRIPTS = [
    "s/a/b/",
    "s/a/b/g",
    "s/a/b/;s/c/d/",
    "s/a/b/; s/c/d/g",
    "s|a/b|c/d|",
    "s/a\\/b/c/",
    "s/a.b/c/",
    "s/a\\.b/c/",
    "s/a/&/",
    "s/a/\\&/",
    "s/a/$x/",
    "s/a/\\$x/",
    "s/a/b\\nc/",
    "s/a/b/i",
    "s/a/b/gp",
    "s//b/",
    "s/a/b",
    "s/a/b/;",
    "s/a/b/;;s/c/d/",
    "sxaxbx",
    "s a b ",
    "s\\a\\b\\",
    "d",
    "p",
    "",
    "   ",
    "s",
    "s/",
    "s//",
    "s///",
    "s/a\\",
    "s/a/b\\",
    "s/*/b/",
    "s/a/b/\n",
    "s/a/b/\ns/c/d/",
    "s/a\\|b/c/",
    "s/a\\(b\\)/c/",
    "s/\\\\/x/",
    "s/x/\\\\/",
    "s/x/\\//",
    "s/é/e/",
    "s/e/é/g",
    "sïaïbï",
    "s/a/" + "b" * 4100 + "/",
    ";".join(f"s/a{i}/b{i}/" for i in range(16)),
    ";".join(f"s/a{i}/b{i}/" for i in range(17)),
]


def _build(root: Path) -> None:
    for name in TREE["dirs"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, text in TREE["files"].items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for name, target in TREE["links"].items():
        os.symlink(target, root / name)


def _text(root: Path, value: object) -> object:
    if isinstance(value, str):
        return value.replace(str(root), TOKEN)
    if isinstance(value, list):
        return [_text(root, item) for item in value]
    if isinstance(value, dict):
        return {key: _text(root, item) for key, item in value.items()}
    return value


def _cases(root: Path) -> list[dict[str, object]]:
    home = root / "home"
    proj = home / "proj"
    cases: list[dict[str, object]] = []

    def add(function: str, args: list[object], result: object) -> None:
        cases.append({"fn": function, "args": _text(root, args), "result": _text(root, result)})

    for script in SCRIPTS:
        add("split_literal_sed_commands", [script], list(source_edit_context._split_literal_sed_commands(script)))
        add("literal_sed_script_is_safe", [script], source_edit_context._literal_sed_script_is_safe(script))
        add("literal_sed_substitution_is_safe", [script], source_edit_context._literal_sed_substitution_is_safe(script))
    for pattern in ("a", "a.b", "a\\.b", "a\\/b", "a\\\\b", "a\\", "[x]", "a|b", "a\\q", "é", ""):
        for delimiter in ("/", "|"):
            add(
                "sed_pattern_is_literal",
                [pattern, delimiter],
                source_edit_context._sed_pattern_is_literal(pattern, delimiter=delimiter),
            )
    for replacement in ("b", "&", "\\&", "$", "\\$", "\\n", "\\/", "\\\\", "a\nb", "b\\", "é", ""):
        for delimiter in ("/", "|"):
            add(
                "sed_replacement_is_literal",
                [replacement, delimiter],
                source_edit_context._sed_replacement_is_literal(replacement, delimiter=delimiter),
            )

    workspaces = [
        proj,
        home / ".hidden",
        home / "bare",
        home / "cargo",
        home / "gomod",
        home / "pyproj",
        home,
        root / "elsewhere",
        proj / "src",
        proj / "missing",
    ]
    for workspace in workspaces:
        for home_dir in (home, root / "elsewhere", home / "missing"):
            add(
                "bounded_edit_workspace_is_safe",
                [str(workspace), str(home_dir)],
                source_edit_context._bounded_edit_workspace_is_safe(workspace, home_dir=home_dir),
            )

    scripts = ["s/a/b/", "s/a.b/c/", "s/a/b/;s/c/d/"]
    targets = [
        "src/a.txt",
        "src/nested/c.txt",
        "./src/a.txt",
        "src/../src/a.txt",
        "link.txt",
        "dirlink/a.txt",
        "outside.txt",
        "dangling.txt",
        "loop1",
        "src",
        "src/missing.txt",
        "../bare/f.txt",
        "-x",
        "$HOME/x",
        "package.json",
        str(proj / "src" / "a.txt"),
        str(home / "bare" / "f.txt"),
        "",
        ".",
    ]
    for cwd in (proj, proj / "src", home):
        for target in targets:
            for script in scripts:
                args = ["-i", "", script, target]
                add(
                    "bounded_in_place_sed_target",
                    [args, str(cwd), str(proj)],
                    source_edit_context._bounded_in_place_sed_target(args, cwd=cwd, workspace_root=proj),
                )
    sample = proj
    for args in (
        ["-i", "", "-e", "s/a/b/", "-e", "s/c/d/", "src/a.txt"],
        ["-i", "", "-e", "s/a/b/", "-e"],
        ["-i", "", "-e", "s/a/b/", "src/a.txt"],
        ["-i", "", "-e", "src/a.txt"],
        ["-i", "", "s/a/b/", "src/a.txt", "src/b.txt"],
        ["-i", "", "s/a/b/"],
        ["-i", "s/a/b/", "src/a.txt"],
        ["-i", "", "d", "src/a.txt"],
        ["-n", "", "s/a/b/", "src/a.txt"],
        ["-i", "x", "s/a/b/", "src/a.txt"],
        ["-i", "", *functools.reduce(operator.iadd, [["-e", "s/a/b/"] for _ in range(16)], []), "src/a.txt"],
        ["-i", "", *functools.reduce(operator.iadd, [["-e", "s/a/b/"] for _ in range(17)], []), "src/a.txt"],
    ):
        add(
            "bounded_in_place_sed_target",
            [args, str(sample), str(proj)],
            source_edit_context._bounded_in_place_sed_target(args, cwd=sample, workspace_root=proj),
        )
    others = [
        "src/a.txt",
        "src/../src/a.txt",
        "link.txt",
        "dirlink/a.txt",
        "src/b.txt",
        "src/missing.txt",
        "outside.txt",
        "dangling.txt",
        "loop1",
        "",
    ]
    for left in others:
        for right in others:
            add(
                "same_workspace_file",
                [left, right, str(proj)],
                source_edit_context._same_workspace_file(left, right, cwd=proj),
            )
    graph_cases(root, add)
    quote_cases(root, add)
    pr_expansion_cases(root, add)
    return cases


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="sfrs-fs-") as scratch:
        root = Path(scratch).resolve()
        _build(root)
        document = {"schema": "sfrs-fs.v1", "tree": TREE, "cases": _cases(root)}
    out = fixture_dir / "fs_helpers.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(document['cases'])} cases -> {out}")


if __name__ == "__main__":
    main()
