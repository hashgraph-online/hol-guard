"""Seed data for the dashboard integration suite, one module per dashboard area.

Each module exposes ``seed(context) -> dict``. It writes its records through
Guard's own store and runtime APIs and returns the facts its specs assert on
(ids, counts, names). Those facts reach the browser specs through the
integration state file under ``seeded[<module name>]``, so a spec never
hard-codes a value that only the seed knows.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.store import GuardStore

# command_health stays last: any later command write would clear the failure it records.
SEED_MODULES: tuple[str, ...] = (
    "home",
    "inbox",
    "evidence",
    "extensions",
    "policy",
    "settings",
    "supply_chain",
    "command_health",
)


@dataclass(frozen=True)
class SeedContext:
    store: GuardStore
    guard_home: Path
    workspace: Path


def run_seeds(context: SeedContext) -> dict[str, Any]:
    # DASHBOARD_E2E_SEEDS=evidence,inbox limits a local run to the areas being
    # worked on. CI always seeds every area.
    selected = os.environ.get("DASHBOARD_E2E_SEEDS")
    names = SEED_MODULES if not selected else tuple(n for n in SEED_MODULES if n in selected.split(","))
    results: dict[str, Any] = {}
    for name in names:
        module = importlib.import_module(f"{__name__}.{name}")
        results[name] = module.seed(context)
    return results
