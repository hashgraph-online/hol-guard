"""Project trees the benign fixture writes: the toolchains a working checkout holds.

A real checkout is rarely Node, Python, Make, Go and Cargo at once, but each of
these entry points is a command shape agents run dozens of times an hour, and
none of them is interesting enough to review. They live beside the fixture's
git shapes rather than inside :mod:`tests.benign_fp_gate_fixture` so that each
file stays about one thing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


_NODE_PACKAGES = {"vite": "7.1.5", "vitest": "3.2.4", "wrangler": "4.20.0"}
# The rest of the toolchain a working project installs: type checker, linter,
# formatter, second test runner, TypeScript runner and task runner. Each entry
# names the binaries npm links, which for TypeScript is not the package name.
_NODE_TOOLS = {
    "typescript": ("5.9.2", ("tsc",)),
    "eslint": ("9.33.0", ("eslint",)),
    "prettier": ("3.6.2", ("prettier",)),
    "jest": ("30.0.5", ("jest",)),
    "tsx": ("4.20.3", ("tsx",)),
    "turbo": ("2.5.5", ("turbo",)),
}
_TOOL_SCRIPTS = {"lint": "eslint .", "typecheck": "tsc --noEmit", "format": "prettier --check ."}
_INSTALLED_PACKAGES = _NODE_PACKAGES | {name: version for name, (version, _) in _NODE_TOOLS.items()}


def _node_toolchain(workspace: Path, *, tools: bool = False) -> None:
    packages = dict(_NODE_PACKAGES)
    if tools:
        packages |= {name: version for name, (version, _) in _NODE_TOOLS.items()}
    dependencies = {name: f"^{version}" for name, version in packages.items()}
    locked = {
        f"node_modules/{name}": {"version": version, "integrity": "sha512-fixture"}
        for name, version in packages.items()
    }
    scripts = {"build": "vite build", "test": "vitest run"} | (_TOOL_SCRIPTS if tools else {})
    manifest = {"private": True, "scripts": scripts, "devDependencies": dependencies}
    _write(workspace / "package.json", json.dumps(manifest) + "\n")
    _write(workspace / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": locked}) + "\n")
    _write(workspace / "tests" / "sample.test.ts", "export const sample = 1;\n")
    for name, version in _NODE_PACKAGES.items():
        _node_package(workspace, name, version)
    if not tools:
        return
    for name, (version, binaries) in _NODE_TOOLS.items():
        _node_package(workspace, name, version, binaries)
    _write(workspace / "tsconfig.json", json.dumps({"compilerOptions": {"strict": True, "noEmit": True}}) + "\n")
    _write(workspace / "eslint.config.js", "export default [];\n")
    _write(workspace / ".prettierrc", "{}\n")


def _node_package(workspace: Path, name: str, version: str, binaries: tuple[str, ...] = ()) -> None:
    """One installed package with its ``node_modules/.bin`` shims, as npm links them."""
    binaries = binaries or (name,)
    package = workspace / "node_modules" / name
    manifest = {"name": name, "version": version, "bin": {binary: f"./bin/{binary}.js" for binary in binaries}}
    _write(package / "package.json", json.dumps(manifest) + "\n")
    for binary in binaries:
        script = package / "bin" / f"{binary}.js"
        _write(script, f"#!/usr/bin/env node\nconsole.log('{binary} {version}');\n")
        script.chmod(0o755)
        shim = workspace / "node_modules" / ".bin" / binary
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.symlink_to(Path("..") / name / "bin" / f"{binary}.js")


def _python_toolchain(workspace: Path) -> None:
    """Project virtualenv with the console scripts ``uv sync`` installs into it."""
    project = {
        "project": {"name": "fixture-app", "version": "0.1.0", "requires-python": ">=3.12"},
        "dependency-groups": {"dev": ["pytest>=8.4", "ruff>=0.12", "mypy>=1.17"]},
    }
    _write(workspace / "pyproject.toml", _toml(project))
    _write(workspace / "src" / "fixture_app" / "__init__.py", "VERSION = '0.1.0'\n")
    _write(workspace / "tests" / "test_fixture_app.py", "def test_version():\n    assert True\n")
    venv = workspace / ".venv"
    _write(venv / "pyvenv.cfg", "home = /usr/bin\nversion = 3.12.3\ninclude-system-site-packages = false\n")
    for name in ("pytest", "ruff", "mypy"):
        script = venv / "bin" / name
        _write(script, f"#!/bin/sh\nexec echo '{name}'\n")
        script.chmod(0o755)
    packages = venv / "lib" / "python3.12" / "site-packages"
    _write(packages / "pytest" / "__init__.py", "__version__ = '8.4.1'\n")
    # `python -m pytest` is the other spelling agents reach for, and it reads
    # the package's entry module rather than the console script.
    _write(packages / "pytest" / "__main__.py", "raise SystemExit(0)\n")
    # The script `source .venv/bin/activate` reads, which agents run before the
    # tools rather than spelling out `.venv/bin/`. Without it that command
    # sources a file the fixture never wrote, and the case would prove nothing
    # about a real venv.
    _write(
        venv / "bin" / "activate",
        'VIRTUAL_ENV="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"\n'
        "export VIRTUAL_ENV\n"
        'PATH="$VIRTUAL_ENV/bin:$PATH"\n'
        "export PATH\n",
    )
    # A venv links its interpreter to the base one; the gate never runs it.
    (venv / "bin" / "python").symlink_to(sys.executable)
    (venv / "bin" / "python3").symlink_to("python")


def _toml(payload: dict[str, object]) -> str:
    """The subset of TOML this fixture writes: tables of scalars and string lists."""
    lines: list[str] = []
    for table, entries in payload.items():
        lines.append(f"[{table}]")
        for key, value in entries.items():  # pyright: ignore[reportAttributeAccessIssue]
            lines.append(f"{key} = {json.dumps(value)}")
        lines.append("")
    return "\n".join(lines)


def _build_toolchain(workspace: Path) -> None:
    """Make, Go and Cargo entry points beside the Node and Python ones."""
    _write(
        workspace / "Makefile",
        "build:\n\tnpm run build\n\ntest:\n\tnpm test\n\nlint:\n\tnpm run lint\n",
    )
    _write(workspace / "go.mod", "module example.invalid/fixture\n\ngo 1.23\n")
    _write(workspace / "main.go", 'package main\n\nfunc main() {\n\tprintln("fixture")\n}\n')
    _write(workspace / "main_test.go", 'package main\n\nimport "testing"\n\nfunc TestMain(t *testing.T) {}\n')
    _write(workspace / "Cargo.toml", '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n')
    _write(workspace / "src" / "lib.rs", "pub fn fixture() -> u8 {\n    1\n}\n")


def _bun_lockfile(project: Path, packages: dict[str, str]) -> None:
    """A text ``bun.lock`` pinning registry packages, as ``bun install`` writes it."""
    manifest = {"devDependencies": {name: f"^{version}" for name, version in packages.items()}}
    locked = {name: [f"{name}@{version}", "", {}, "sha512-fixture"] for name, version in packages.items()}
    lockfile = {"lockfileVersion": 1, "workspaces": {"": manifest}, "packages": locked}
    _write(project / "bun.lock", json.dumps(lockfile, indent=2) + "\n")
