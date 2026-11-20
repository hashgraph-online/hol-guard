"""A Node project carrying a lockfile another package manager left behind.

The project installs with npm, and `package-lock.json` pins the type checker
that `node_modules` holds. A `pnpm-lock.yaml` from before the last upgrade is
still committed and pins the previous release. `npx --no-install tsc` cannot
fetch anything, so it runs the installed checker or fails; the stale file has
no say in what runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.benign_fp_gate_projects import _node_package, _write

_CURRENT = "5.9.2"
_STALE = "5.4.5"


def stale_lockfile_app_path(home: Path) -> Path:
    return home / "Code" / "dashboard-app"


def stale_lockfile_app(root: Path) -> None:
    manifest = {
        "private": True,
        "scripts": {"typecheck": "tsc --noEmit"},
        "devDependencies": {"typescript": f"^{_CURRENT}"},
    }
    _write(root / "package.json", json.dumps(manifest) + "\n")
    locked = {"node_modules/typescript": {"version": _CURRENT, "integrity": "sha512-fixture"}}
    _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": locked}) + "\n")
    _write(
        root / "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n"
        "\n"
        "importers:\n"
        "\n"
        "  .:\n"
        "    devDependencies:\n"
        "      typescript:\n"
        f"        specifier: ^{_STALE}\n"
        f"        version: {_STALE}\n"
        "\n"
        "packages:\n"
        "\n"
        f"  typescript@{_STALE}:\n"
        "    resolution: {integrity: sha512-fixture}\n"
        "    hasBin: true\n",
    )
    _write(root / "tsconfig.json", json.dumps({"compilerOptions": {"strict": True, "noEmit": True}}) + "\n")
    _write(root / "src" / "index.ts", "export const ready = true;\n")
    _node_package(root, "typescript", _CURRENT, ("tsc",))
