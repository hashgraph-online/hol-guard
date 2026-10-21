from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Every intent test runs against the resident authority."""

    return package_intent_native

def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def _write_typescript_workspace(
    workspace: Path,
    *,
    dependency: str = "^5.9.0",
    locked_version: str = "5.9.0",
    installed_version: str = "5.9.0",
    wrong_executable: bool = False,
) -> None:
    _write_text(workspace / "package.json", f'{{"devDependencies":{{"typescript":"{dependency}"}}}}\n')
    _write_text(
        workspace / "package-lock.json",
        (
            '{"packages":{"node_modules/typescript":'
            f'{{"version":"{locked_version}","integrity":"sha512-reviewed"}}}}}}\n'
        ),
    )
    _write_text(workspace / "src" / "example.ts", "export const value: number = 1;\n")
    runner = workspace / "node_modules" / ".bin" / "tsc"
    if wrong_executable:
        _write_text(runner, "#!/bin/sh\nexit 0\n")
        runner.chmod(0o755)
        return
    compiler = workspace / "node_modules" / "typescript" / "bin" / "tsc"
    _write_text(compiler, "#!/usr/bin/env node\nrequire('../lib/tsc.js')\n")
    compiler.chmod(0o755)
    _write_text(
        workspace / "node_modules" / "typescript" / "package.json",
        f'{{"name":"typescript","version":"{installed_version}","bin":{{"tsc":"./bin/tsc"}}}}\n',
    )
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.symlink_to(Path("..") / "typescript" / "bin" / "tsc")
