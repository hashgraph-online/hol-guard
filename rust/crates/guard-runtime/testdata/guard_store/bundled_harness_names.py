"""Offline harness names for scenario files that build command-activity values at import.

Command-activity values check their harness against the runtime's contract registry. These
files build values while a test run is still collecting, or while a recorder runs, before any
runtime is reachable. This reads the same bundled contracts file and answers the registry's
question from it, so the scenario modules can import on their own.
"""

from __future__ import annotations

import json
from pathlib import Path

CONTRACTS = (
    Path(__file__).resolve().parents[5]
    / "src"
    / "codex_plugin_scanner"
    / "guard"
    / "contracts"
    / "harness-protection-contracts.v1.json"
)


def prime() -> None:
    from codex_plugin_scanner.guard.runtime import command_activity_contract

    names = tuple(row["harness"] for row in json.loads(CONTRACTS.read_text(encoding="utf-8"))["contracts"])
    command_activity_contract.harness_names = lambda: names
    command_activity_contract.command_activity_harnesses.cache_clear()
