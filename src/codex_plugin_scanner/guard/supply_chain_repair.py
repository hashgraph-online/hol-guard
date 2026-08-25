"""Coordinate bounded supply-chain recovery steps without hiding partial failures."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

_LOGGER = logging.getLogger(__name__)

RepairStep = Callable[[], object]
ActivationStep = Callable[[], tuple[int, Mapping[str, object]]]


class SupplyChainRepairDeferredError(Exception):
    """A recovery step still needs a named user action instead of another silent retry."""

    def __init__(self, *, code: str, message: str, action: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.action = action


def coordinate_supply_chain_repair(
    *,
    repair_package_shims: RepairStep,
    activate_runtime: ActivationStep,
    sync_intelligence: RepairStep,
) -> dict[str, object]:
    """Run every independent recovery step and return an honest aggregate result."""

    completed_steps: list[str] = []
    failed_steps: list[dict[str, str]] = []
    remaining_steps: list[dict[str, str]] = []

    try:
        _ = repair_package_shims()
        completed_steps.append("package_shims")
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: package_shims")
        failed_steps.append(
            {
                "step": "package_shims",
                "message": "Guard could not repair every detected package tool.",
            }
        )

    try:
        status, response = activate_runtime()
        if status >= 400:
            message = response.get("message")
            raise RuntimeError(message if isinstance(message, str) else "activation failed")
        completed_steps.append("runtime_activation")
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: runtime_activation")
        failed_steps.append(
            {
                "step": "runtime_activation",
                "message": "Guard could not finish package protection activation.",
            }
        )

    try:
        _ = sync_intelligence()
        completed_steps.append("intelligence_sync")
    except SupplyChainRepairDeferredError as error:
        remaining_steps.append(
            {
                "step": "intelligence_sync",
                "code": error.code,
                "message": error.message,
                "action": error.action,
            }
        )
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: intelligence_sync")
        failed_steps.append(
            {
                "step": "intelligence_sync",
                "message": "Guard could not refresh supply-chain intelligence.",
            }
        )

    repaired = not failed_steps and not remaining_steps
    connect_only = (
        not failed_steps
        and remaining_steps
        and all(step.get("action") == "connect" for step in remaining_steps)
    )
    if repaired:
        message = "Supply-chain protection restored and refreshed."
    elif connect_only:
        message = (
            "Package protection is on. Connect Guard Cloud to refresh safety intelligence."
        )
    elif completed_steps:
        message = "Guard restored some supply-chain protection. Retry remaining steps to finish."
    else:
        message = "Guard could not complete supply-chain repair. Retry remaining steps to continue safely."
    return {
        "repaired": repaired,
        "completed_steps": completed_steps,
        "failed_steps": failed_steps,
        "remaining_steps": remaining_steps,
        "message": message,
    }


__all__ = ["SupplyChainRepairDeferredError", "coordinate_supply_chain_repair"]
