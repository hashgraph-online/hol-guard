"""Seed data for the dashboard supply chain integration specs.

Gives the package firewall what a machine with Guard Cloud connected looks
like: a paid entitlement (without one every package action stops at "connect
Guard Cloud"), Guard shims installed for two managers, and a registered project
folder with a manifest and lockfile for the workspace audit. Records go through
the same calls the CLI and daemon use.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.shims import install_package_shims

from . import SeedContext

# Managers every supported OS can shim, whatever the host has installed.
SHIMMED_MANAGERS: tuple[str, ...] = ("npm", "pip")
APP_HARNESS = "grok"
PROJECT_NAME = "supply-chain-e2e-app"
# Direct npm dependencies of the seeded project, recorded in its lockfile.
DEPENDENCIES: dict[str, str] = {"left-pad": "1.3.0", "is-odd": "3.0.1", "lodash": "4.17.21"}


def _write_project(project: Path) -> None:
    project.mkdir(parents=True, exist_ok=True)
    packages = {
        f"node_modules/{name}": {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
        for name, version in DEPENDENCIES.items()
    }
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": PROJECT_NAME,
                "version": "1.0.0",
                "dependencies": DEPENDENCIES,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "name": PROJECT_NAME,
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {"name": PROJECT_NAME, "version": "1.0.0", "dependencies": DEPENDENCIES},
                    **packages,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def seed(context: SeedContext) -> dict[str, Any]:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    context.store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-06-09T12:00:00.000Z",
    )
    project = context.workspace / PROJECT_NAME
    _write_project(project)
    context.store.set_managed_install(
        APP_HARNESS,
        True,
        str(project),
        {"managed_hooks_path": f"{project}/.{APP_HARNESS}/hooks"},
        now,
    )
    shim_context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=context.guard_home)
    install_package_shims(shim_context, managers=SHIMMED_MANAGERS)
    return {
        "project": str(project),
        "projectName": PROJECT_NAME,
        "app": APP_HARNESS,
        "shimmedManagers": list(SHIMMED_MANAGERS),
        "packages": sorted(DEPENDENCIES),
    }
