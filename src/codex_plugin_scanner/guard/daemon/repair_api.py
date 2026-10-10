"""Daemon-side logic for the dashboard "Repair Guard" and "Remove from all apps" actions.

Both mirror their CLI twins (`hol-guard repair`, `hol-guard hooks remove`) and
verify step-up proof on the server; a client-side modal alone never authorizes
anything. The HTTP layer only routes: it calls these functions and maps
``ApprovalGateError`` to its normal error response.

Gating:

* repair follows ``doctor.repair``: proof when the approval gate is enabled,
  advisory otherwise, and ``dry_run`` is exempt.
* hook removal always needs proof for a real run. It is stricter than the CLI
  on purpose: the CLI can fall back to a typed phrase on an interactive
  terminal, but a daemon request has no terminal, so with no gate configured
  the request is refused rather than trusted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.base import HarnessContext
from ..approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    input_from_mapping,
    public_config,
    require_high_risk,
)
from ..hook_removal import plan_hook_removal, remove_all_guard_hooks
from ..repair_engine import run_repair

if TYPE_CHECKING:
    from ..store import GuardStore

REMOVE_CONFIRMATION = "remove-guard-hooks"
REPAIR_ACTION = "doctor.repair"
REMOVE_ACTION = "hooks.remove"


class RemovalConfirmationError(ValueError):
    """The request did not carry the explicit removal confirmation."""


def _authority_home(guard_home: Path, action: str) -> Path:
    from ..cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home

    return lifecycle_authority_home(guard_home, requirement=LifecycleGateRequirement(action, "all"))


def _gate_input(payload: Mapping[str, object]) -> ApprovalGateInput:
    gate_input = input_from_mapping(dict(payload)) or ApprovalGateInput()
    # A cooldown would let an earlier, unrelated proof authorize this action.
    return replace(gate_input, use_cooldown=False)


def _require_proof(guard_home: Path, payload: Mapping[str, object], *, action: str, required: bool) -> bool:
    """Verify step-up proof for ``action``; return whether a gate was enforced."""

    authority_home = _authority_home(guard_home, action)
    gate = public_config(authority_home)
    if not gate.enabled:
        if required:
            raise ApprovalGateError(
                "approval_gate_configuration_required",
                "Removing every Guard hook from the dashboard needs the local approval gate. Enable it in "
                "Settings > Approval gate, or run `hol-guard hooks remove --all` in a terminal.",
                status=423,
            )
        return False
    gate_input = _gate_input(payload)
    if gate.totp_enabled and not (gate_input.totp_code or "").strip():
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
    require_high_risk(
        authority_home,
        purpose="protection_lifecycle",
        approval_gate_input=gate_input,
        action=action,
        scope="local-protection",
        subject="all",
    )
    return True


def _context(guard_home: Path) -> HarnessContext:
    return HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=guard_home)


def repair_request(store: GuardStore, payload: Mapping[str, object]) -> dict[str, object]:
    """Run the full repair from the daemon. The daemon never restarts itself."""

    dry_run = payload.get("dry_run") is True
    guard_home = store.guard_home
    if not dry_run:
        _require_proof(guard_home, payload, action=REPAIR_ACTION, required=False)
    return run_repair(
        guard_home=guard_home,
        context=_context(guard_home),
        store=store,
        dry_run=dry_run,
        include_daemon=False,
    )


def _harness_rows(plans: list[object]) -> list[dict[str, object]]:
    return [plan.to_dict() for plan in plans if hasattr(plan, "to_dict")]


def removal_request(store: GuardStore, payload: Mapping[str, object]) -> dict[str, object]:
    """List (``dry_run``) or perform removal of every Guard hook from every app."""

    guard_home = store.guard_home
    context = _context(guard_home)
    if payload.get("dry_run") is True:
        return remove_all_guard_hooks(context=context, store=store, dry_run=True)
    if payload.get("confirm") != REMOVE_CONFIRMATION:
        raise RemovalConfirmationError(REMOVE_CONFIRMATION)
    _require_proof(guard_home, payload, action=REMOVE_ACTION, required=True)
    report = remove_all_guard_hooks(context=context, store=store, dry_run=False)
    remaining = plan_hook_removal(context, store)
    report["post_state"] = {
        "remaining_harnesses": _harness_rows(list(remaining)),
        "clean": not remaining,
    }
    return report


__all__ = [
    "REMOVE_CONFIRMATION",
    "RemovalConfirmationError",
    "removal_request",
    "repair_request",
]
