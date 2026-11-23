"""A second checkout beside the session whose dependencies pnpm installed.

An agent that is about to run a project's toolchain asks where the launcher
the package manager linked actually lives. The answer is a path, and the shim
it reads is a link into the content store below ``node_modules/.pnpm``, so the
question only has the shape it has in a real checkout when a store is there.
Only this case's fixture writes one, so no other case's tree changes.
"""

from __future__ import annotations

import json
from pathlib import Path

PACKAGE_STORE_CASE = "omp-native-shim-realpath-resolve"
PACKAGE_STORE_PROJECT = "codegen-app"
PACKAGE_NAME = "codegen-kit"
PACKAGE_VERSION = "2.1.0"


def add_package_store_checkout(home: Path, scenario_id: str | None) -> None:
    """Install one dependency the way pnpm and Bun install it, for its case only."""
    if scenario_id != PACKAGE_STORE_CASE:
        return
    project = home / PACKAGE_STORE_PROJECT
    manifest = {"name": "@acme/codegen-app", "version": "1.4.0", "devDependencies": {PACKAGE_NAME: f"^{PACKAGE_VERSION}"}}
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_package_store(project / "node_modules", PACKAGE_NAME, PACKAGE_VERSION)


def write_package_store(modules: Path, name: str, version: str) -> None:
    """``node_modules`` with a content store, the project entry and the shim linked into it."""
    store = modules / ".pnpm" / f"{name}@{version}" / "node_modules" / name
    (store / "bin").mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": version, "bin": {name: f"bin/{name}.js"}}
    (store / "package.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8", newline="\n")
    launcher = store / "bin" / f"{name}.js"
    launcher.write_text(f"#!/usr/bin/env node\nconsole.log('{name} {version}');\n", encoding="utf-8", newline="\n")
    launcher.chmod(0o755)
    entry = modules / name
    if not entry.exists():
        entry.symlink_to(Path(".pnpm") / f"{name}@{version}" / "node_modules" / name)
    shims = modules / ".bin"
    shims.mkdir(parents=True, exist_ok=True)
    shim = shims / name
    if not shim.exists():
        shim.symlink_to(Path("..") / name / "bin" / f"{name}.js")
