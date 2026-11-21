#!/usr/bin/env python3
"""Reject Guard modules that nothing in the repository still references."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path

SCHEMA_VERSION = 1

# The Rust migration folds module contents into an owning module and deletes the
# imports, but a fold that forgets the final `git rm` leaves the original file in
# the tree. `rust_migration_tree_hygiene.py` catches those only once a maintainer
# notices one and appends it to RETIRED_PATHS by hand, so residue survives until
# somebody reads the right directory. This gate finds the same residue by walking
# the tree instead of a list.
PACKAGE = "src/codex_plugin_scanner/guard"

# Referencing files live in the Python tree, the suites, and the CI tooling that
# names modules in manifests and shell steps.
SCAN_DIRS = ("src", "tests", "scripts", "ci")
SCAN_FILES = ("pyproject.toml",)
SCAN_SUFFIXES = frozenset({".cfg", ".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"})
SKIP_DIRS = frozenset({".git", ".mypy_cache", ".ruff_cache", ".venv", "__pycache__", "node_modules", "target"})

# Package markers are reached through their package name, never their own stem.
EXEMPT_STEMS = frozenset({"__init__", "__main__"})

# Tokenizing the whole file, string literals included, keeps dynamic imports such
# as `import_module(".installed_bundle", __package__)` counted as references.
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# This detector and its suite name modules that do not exist. Scanning them would
# let a fixture stem shelter a real module of the same name, so they are skipped:
# a Guard module is residue unless something other than the detector refers to it.
FIXTURE_SOURCES = (
    "scripts/ci/guard_orphan_module_gate.py",
    "tests/test_guard_orphan_module_gate.py",
)

# Modules that are deliberately unreferenced. Each entry needs a reason; an entry
# without one is residue wearing an exemption.
ALLOWLIST: tuple[str, ...] = ()


def _scan_files(root: Path) -> list[Path]:
    """Collect every file whose text can name a Guard module."""
    found: list[Path] = []
    for name in SCAN_DIRS:
        directory = root / name
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
                continue
            relative = path.relative_to(root)
            if SKIP_DIRS.intersection(relative.parts) or relative.as_posix() in FIXTURE_SOURCES:
                continue
            found.append(path)
    found.extend(root / name for name in SCAN_FILES if (root / name).is_file())
    return found


def find_orphans(root: Path) -> list[str]:
    """Return Guard modules whose stem appears in no other repository file."""
    package = root / PACKAGE
    if not package.is_dir():
        return []

    modules: dict[str, list[Path]] = {}
    for path in package.rglob("*.py"):
        if path.stem in EXEMPT_STEMS or SKIP_DIRS.intersection(path.relative_to(root).parts):
            continue
        modules.setdefault(path.stem, []).append(path)
    if not modules:
        return []

    referencing: dict[str, set[Path]] = {stem: set() for stem in modules}
    for path in _scan_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for stem in TOKEN.findall(text):
            holders = referencing.get(stem)
            if holders is not None:
                holders.add(path)

    orphans = [
        str(path.relative_to(root))
        for stem, paths in modules.items()
        for path in paths
        if not referencing[stem] - {path}
    ]
    return sorted(set(orphans) - set(ALLOWLIST))


def _self_test() -> None:
    with tempfile.TemporaryDirectory() as handle:
        root = Path(handle)
        package = root / PACKAGE
        package.mkdir(parents=True)

        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "owner.py").write_text(
            "from .folded import helper\nfrom . import dynamic_only\n",
            encoding="utf-8",
        )
        (package / "folded.py").write_text("def helper() -> int:\n    return 1\n", encoding="utf-8")
        (package / "dynamic_only.py").write_text("VALUE = 2\n", encoding="utf-8")
        (package / "left_behind.py").write_text("def helper() -> int:\n    return 3\n", encoding="utf-8")

        # A module named only from a string literal in CI tooling stays alive.
        string_named = package / "named_in_manifest.py"
        string_named.write_text("VALUE = 4\n", encoding="utf-8")
        scripts = root / "scripts" / "ci"
        scripts.mkdir(parents=True)
        (scripts / "inventory.json").write_text(
            json.dumps({"modules": ["named_in_manifest"]}),
            encoding="utf-8",
        )

        # Bytecode caches must never keep a deleted module alive.
        cache = package / "__pycache__"
        cache.mkdir()
        (cache / "left_behind.py").write_text("left_behind\n", encoding="utf-8")

        # Nor may this detector's own fixtures, which name the same module.
        for name in FIXTURE_SOURCES:
            fixture = root / name
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text("left_behind folded owner dynamic\n", encoding="utf-8")

        # A test suite reference counts, so `owner` itself is not residue.
        suite = root / "tests"
        suite.mkdir(exist_ok=True)
        (suite / "test_owner.py").write_text(
            "from codex_plugin_scanner.guard.owner import helper\n",
            encoding="utf-8",
        )

        expected = [f"{PACKAGE}/left_behind.py"]
        actual = find_orphans(root)
        if actual != expected:
            raise RuntimeError(f"orphan gate self-test failed: expected={expected!r}, actual={actual!r}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        _self_test()
        print(json.dumps({"schema_version": SCHEMA_VERSION, "self_test": "passed"}, sort_keys=True))
        return 0

    orphans = find_orphans(args.root)
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "orphan_module_count": len(orphans),
                "orphan_module_paths": orphans,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if orphans else 0


if __name__ == "__main__":
    raise SystemExit(main())
