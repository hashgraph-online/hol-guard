"""Harness protection contracts for HOL Guard.

Each contract captures the static protection capabilities, install aliases,
config file paths, event surfaces, known blind spots, and smoke command for
one AI coding harness that HOL Guard supports.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any

from .setup_contract_models import CAPABILITY_DECLARED_ACTIONS as CAPABILITY_DECLARED_ACTIONS
from .setup_contract_models import CapabilityLocalHosted as CapabilityLocalHosted
from .setup_contract_models import HarnessCoverageSummary as HarnessCoverageSummary
from .setup_contract_models import HarnessEventCapability as HarnessEventCapability
from .setup_contract_models import HarnessProtectionContract as HarnessProtectionContract
from .setup_contract_models import HarnessSetupContract as HarnessSetupContract
from .setup_contract_models import HarnessSetupStep as HarnessSetupStep
from .setup_contract_registry import contract_for as contract_for
from .setup_contract_registry import harness_contracts as harness_contracts
from .setup_contract_registry import harness_names as harness_names

if TYPE_CHECKING:
    HARNESS_CONTRACTS: tuple[HarnessProtectionContract, ...]


def __getattr__(name: str) -> object:
    # The registry is read from the native runtime on first use, never at import.
    if name == "HARNESS_CONTRACTS":
        return harness_contracts()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@lru_cache(maxsize=256)
def display_name_for(harness: str) -> str:
    """The label for a harness name or install alias, or the name itself when it has none."""

    return _setup_contract_kind("display_name", harness)["display_name"]


def setup_contract_for(harness: str) -> HarnessSetupContract | None:
    """Return guided setup metadata for a harness name or install alias.

    The native runtime renders the steps and coverage from the bundled contract.
    """

    payload = _setup_contract_kind("contract", harness)["contract"]
    return None if payload is None else _setup_contract_from(payload)


def _setup_contract_kind(op: str, harness: str) -> dict[str, Any]:
    from .native_runner_authority import native_runner_authority

    return native_runner_authority("harness_setup_contract", {"op": op, "harness": harness})


def _steps(payload: list[dict[str, Any]]) -> tuple[HarnessSetupStep, ...]:
    return tuple(
        HarnessSetupStep(
            step_id=step["step_id"],
            title=step["title"],
            body=step["body"],
            command=tuple(step["command"]),
            writes_config=step["writes_config"],
            requires_confirmation=step["requires_confirmation"],
        )
        for step in payload
    )


def _setup_contract_from(payload: dict[str, Any]) -> HarnessSetupContract:
    coverage = payload["coverage"]
    return HarnessSetupContract(
        harness=payload["harness"],
        display_name=payload["display_name"],
        install_aliases=tuple(payload["install_aliases"]),
        setup_steps=_steps(payload["setup_steps"]),
        verify_steps=_steps(payload["verify_steps"]),
        repair_steps=_steps(payload["repair_steps"]),
        coverage=HarnessCoverageSummary(
            native_hooks=coverage["native_hooks"],
            browser_fallback=coverage["browser_fallback"],
            mcp_proxy=coverage["mcp_proxy"],
            prompt_hooks=coverage["prompt_hooks"],
            blind_spots=tuple(coverage["blind_spots"]),
        ),
        surface_capabilities=tuple(payload.get("surface_capabilities", ())),
        supported_actions=tuple(payload.get("supported_actions", ())),
        docs_path=payload.get("docs_path"),
        icon_label=payload.get("icon_label"),
    )
