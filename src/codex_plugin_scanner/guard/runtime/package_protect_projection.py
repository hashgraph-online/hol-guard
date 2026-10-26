"""Shared identity for local package protect flows."""

from __future__ import annotations

import os

from .harness_attribution import resolve_environment_harness, resolve_parent_process_harness

LOCAL_SUPPLY_CHAIN_HARNESS = "guard-cli"


def resolve_local_supply_chain_harness() -> str:
    """Attribute intercepted package commands to the harness that invoked them.

    Package shims spawn ``hol-guard protect`` inside the environment of the
    shell that ran the command, so an AI harness that executed it leaves its
    runtime env markers there. The resolved slug feeds request identity,
    receipts, and user-facing attribution only; policy scoping stays keyed on
    the synthetic guard-cli artifact harness, which the invoking process
    cannot influence.
    """

    return resolve_environment_harness(os.environ) or resolve_parent_process_harness() or LOCAL_SUPPLY_CHAIN_HARNESS


__all__ = ["LOCAL_SUPPLY_CHAIN_HARNESS", "resolve_local_supply_chain_harness"]
