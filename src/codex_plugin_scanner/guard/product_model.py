"""Harness names the top-level CLI dispatches to HOL Guard."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS

SUPPORTED_HARNESS_VALUES = tuple(contract.harness for contract in HARNESS_CONTRACTS)

__all__ = ["SUPPORTED_HARNESS_VALUES"]
