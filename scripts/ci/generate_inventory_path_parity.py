#!/usr/bin/env python3
"""Record the CPython behaviour of the inventory contract's path redaction.

`rust/crates/guard-command/src/inventory_path_redaction.rs` ports
`redact_local_path`, `_redact_known_path` and `_redact_command_value` from
`src/codex_plugin_scanner/guard/inventory_contract_redaction.py`. Four CPython
behaviours decide what those functions let out of the machine and none is the
Rust default:

* `pathlib.Path` is `PurePosixPath` on unix and `PureWindowsPath` on Windows.
  A Windows path parsed with POSIX rules keeps `C:\\Users\\someone` as a single
  component, so `relative_to` never matches the home prefix and the
  `path.name` fallback exports the whole private path as a "name". The
  `pure_posix`/`pure_windows` sections record both flavours from one host
  because `PurePath` needs no filesystem.
* `Path.resolve()` is non-strict: it canonicalizes the longest existing prefix,
  resolves symlinks along it, invents the remainder and raises `RuntimeError`
  on a symlink loop. The `tree` section declares a directory tree the Rust test
  materializes so the symlink, `..`, loop and missing-suffix cases are pinned
  against a real filesystem.
* `relative_to` compares components, case-insensitively on Windows.
* CPython `re` treats `\\s`/`\\S` as `Py_UNICODE_ISSPACE` (U+001C..U+001F
  included) and folds `I`-like characters onto `i` under `re.IGNORECASE`, so
  `--token\\x1dabc` and `ap\\u0131_key=abc` leak through a naive port.

The `tree` section is recorded by the platform that runs this generator; the
fixture names it so a Windows parity corpus is a visible gap rather than a
silent one.

Run it from the repository root on the interpreter the project targets.
`pathlib` is not frozen across releases: 3.14 reports `PureWindowsPath("//")`
as absolute where 3.12 does not, so a newer interpreter rewrites recorded
cases the port was written against.

    uv run --python 3.12 --no-project python \
        scripts/ci/generate_inventory_path_parity.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from codex_plugin_scanner.guard.inventory_contract_redaction import (  # noqa: E402
    _redact_command_value,
    _redact_known_path,
    redact_local_path,
)

FIXTURE = Path("rust/crates/guard-command/testdata/inventory_path_parity.json")

PURE_PATHS = [
    "",
    ".",
    "..",
    "/",
    "//",
    "///",
    "a/..",
    "a/.",
    "foo/",
    "/a//b/",
    "a\\b",
    "~/x",
    "a/../..",
    "/home/me/.config/gh/hosts.yml",
    "relative/path.txt",
    "/tmp",
    "C:",
    "C:x",
    "C:\\Users\\me\\x",
    "C:/Users/me/x",
    "\\\\server\\share\\dir\\f.txt",
    # `ntpath.splitroot` upper-cases before comparing the device UNC prefix, so
    # the lower-case spelling must keep `share` inside the drive instead of
    # leaving it as the file name.
    "\\\\?\\UNC\\server\\share",
    "\\\\?\\unc\\server\\share",
    "\\\\?\\Unc\\server\\share\\dir\\f.txt",
]

RELATIVE_TO = [
    ("/home/me/x/y", "/home/me"),
    ("/home/me", "/home/me"),
    ("/home/other/x", "/home/me"),
    ("/home/me/../me/x", "/home/me"),
    ("/home/mex/y", "/home/me"),
    ("C:\\Users\\me\\x", "C:\\Users\\me"),
    ("C:\\USERS\\ME\\x", "C:\\Users\\me"),
    ("C:\\Users\\me\\x", "D:\\Users\\me"),
    ("\\\\server\\share\\dir\\f.txt", "\\\\server\\share"),
    ("\\\\?\\unc\\server\\share\\dir\\f.txt", "\\\\?\\UNC\\server\\share"),
]

TREE_DIRS = [
    "home",
    "home/project",
    "home/.config",
    "work",
    "work/pkg",
]

TREE_FILES = [
    "home/project/app.py",
    "home/.config/creds.txt",
    "work/pkg/mod.py",
]

# (link, target) — `target` is written verbatim, so a relative target stays
# relative and a dangling one stays dangling.
TREE_LINKS = [
    ("home/link-to-work", "../work"),
    ("work/loop-a", "loop-b"),
    ("work/loop-b", "loop-a"),
    ("home/project/missing-link", "gone"),
]

# Resolved against `home` as the home directory, `work` as both the workspace
# and the working directory.
LOCAL_PATH_CASES = [
    ("{root}/home/project/app.py", True),
    ("{root}/home", True),
    ("{root}/home/.", True),
    ("{root}/work/pkg/mod.py", True),
    ("pkg/mod.py", True),
    ("{root}/home/link-to-work/pkg/mod.py", True),
    ("{root}/home/project/../.config/creds.txt", True),
    ("{root}/work/loop-a/x", True),
    ("{root}/home/project/nope/deeper.txt", True),
    ("{root}/home/project/missing-link", True),
    ("{root}/home/project/app.py", False),
    ("../home/project/app.py", True),
]

KNOWN_PATH_CASES = [
    ("{root}/work/pkg/mod.py", True),
    ("{root}/home/project/app.py", True),
    ("/etc/hosts", True),
    ("pkg/mod.py", True),
    ("{root}/work", True),
    ("{root}/work/loop-a/x", True),
    ("{root}/etc/hosts", False),
    ("{root}/home/project/app.py", False),
]

COMMAND_CASES = [
    "cat {root}/home/.config/creds.txt",
    "cp {root}/home/project/app.py {root}/work/pkg/mod.py",
    "python {root}/work/pkg/mod.py --token sekrit",
    'curl https://api.example.com/v1/x?token=abc -H "Authorization: Bearer sekrit"',
    "curl -H 'authorization:   BEARER sekrit' https://user:pw@host.example.com/p",
    "xhttps://host.example.com/p",
    "gh api --api_key sekrit --api-key sekrit",
    "export API_KEY=sekrit password=sekrit",
    "export AP\u0131_KEY=sekrit",
    "AUTHOR\u0130ZAT\u0130ON: bearer sekrit",
    "cmd --token\x1dsekrit",
    "cmd secret=\x1csekrit",
    "cmd\x1d/etc/hosts",
    "no secrets here",
    "{root}/home/project/app.py leading-path-not-at-boundary",
]


@contextmanager
def working_directory(path: Path) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def pure_section(flavour: type[PurePosixPath] | type[PureWindowsPath]) -> list[dict[str, Any]]:
    cases = []
    for text in PURE_PATHS:
        path = flavour(text)
        cases.append(
            {
                "path": text,
                "name": path.name,
                "is_absolute": path.is_absolute(),
                "parts": list(path.parts),
            }
        )
    return cases


def relative_to_section(
    flavour: type[PurePosixPath] | type[PureWindowsPath],
) -> list[dict[str, Any]]:
    cases = []
    for text, base in RELATIVE_TO:
        try:
            relative = flavour(text).relative_to(flavour(base))
        except ValueError:
            parts: list[str] | None = None
        else:
            parts = list(relative.parts)
        cases.append({"path": text, "base": base, "parts": parts})
    return cases


def build_tree(root: Path) -> None:
    for name in TREE_DIRS:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in TREE_FILES:
        (root / name).write_text("x\n", encoding="utf-8")
    for link, target in TREE_LINKS:
        (root / link).symlink_to(target)


def tree_section(root: Path) -> dict[str, Any]:
    home = root / "home"
    work = root / "work"
    placeholder = str(root)

    def unplace(value: str) -> str:
        return value.replace(placeholder, "{root}")

    def place(value: str) -> str:
        return value.replace("{root}", placeholder)

    local_paths = []
    with working_directory(work):
        for template, with_home in LOCAL_PATH_CASES:
            value = place(template)
            expected = redact_local_path(value, home_dir=home if with_home else None)
            local_paths.append(
                {
                    "path": template,
                    "home_dir": "{root}/home" if with_home else None,
                    "expected": unplace(expected),
                }
            )

        known_paths = []
        for template, with_workspace in KNOWN_PATH_CASES:
            value = place(template)
            expected = _redact_known_path(value, home, work if with_workspace else None)
            known_paths.append(
                {
                    "value": template,
                    "workspace_dir": "{root}/work" if with_workspace else None,
                    "expected": unplace(expected),
                }
            )

        commands = []
        for template in COMMAND_CASES:
            value = place(template)
            expected = _redact_command_value(value, home, work)
            commands.append({"value": template, "expected": unplace(expected)})

    return {
        "platform": "windows" if os.name == "nt" else "posix",
        "dirs": TREE_DIRS,
        "files": TREE_FILES,
        "links": [{"link": link, "target": target} for link, target in TREE_LINKS],
        "home_dir": "{root}/home",
        "workspace_dir": "{root}/work",
        "cwd": "{root}/work",
        "local_paths": local_paths,
        "known_paths": known_paths,
        "commands": commands,
    }


def build_document() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="inventory-path-parity-") as raw:
        # `/var` is a symlink to `/private/var` on macOS; resolving the root
        # keeps the recorded expectations free of that indirection.
        root = Path(raw).resolve()
        build_tree(root)
        tree = tree_section(root)
    return {
        "pure_posix": pure_section(PurePosixPath),
        "pure_windows": pure_section(PureWindowsPath),
        "relative_to_posix": relative_to_section(PurePosixPath),
        "relative_to_windows": relative_to_section(PureWindowsPath),
        "tree": tree,
    }


def main() -> int:
    document = build_document()
    target = REPO_ROOT / FIXTURE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
