"""Harness protection contracts for HOL Guard.

Each contract captures the static protection capabilities, install aliases,
config file paths, event surfaces, known blind spots, and smoke command for
one AI coding harness that HOL Guard supports.
"""

from __future__ import annotations

from .contract_models import CAPABILITY_DECLARED_ACTIONS as CAPABILITY_DECLARED_ACTIONS
from .contract_models import CapabilityLocalHosted as CapabilityLocalHosted
from .contract_models import HarnessCoverageSummary as HarnessCoverageSummary
from .contract_models import HarnessEventCapability as HarnessEventCapability
from .contract_models import HarnessProtectionContract as HarnessProtectionContract
from .contract_models import HarnessSetupContract as HarnessSetupContract
from .contract_models import HarnessSetupStep as HarnessSetupStep
from .contract_registry import HARNESS_CONTRACTS as HARNESS_CONTRACTS
from .contract_rendering import DISPLAY_NAMES as _DISPLAY_NAMES

_CONTRACT_BY_ALIAS: dict[str, HarnessProtectionContract] = {}
for _c in HARNESS_CONTRACTS:
    _CONTRACT_BY_ALIAS[_c.harness] = _c
    for _alias in _c.install_aliases:
        _CONTRACT_BY_ALIAS[_alias] = _c


def contract_for(harness: str) -> HarnessProtectionContract | None:
    """Return the contract for a harness name or install alias, or None."""
    return _CONTRACT_BY_ALIAS.get(harness)


def display_name_for(harness: str) -> str:
    contract = contract_for(harness)
    key = contract.harness if contract is not None else harness
    return _DISPLAY_NAMES.get(key, key)


def setup_contract_for(harness: str) -> HarnessSetupContract | None:
    """Return guided setup metadata for a harness name or install alias."""

    contract = contract_for(harness)
    if contract is None:
        return None
    alias = contract.install_aliases[0] if contract.install_aliases else contract.harness
    display_name = _DISPLAY_NAMES.get(contract.harness, contract.harness)
    coverage = HarnessCoverageSummary(
        native_hooks=contract.native_approval,
        browser_fallback=contract.browser_fallback,
        mcp_proxy="mcp_tool" in contract.event_surfaces,
        prompt_hooks="prompt" in contract.event_surfaces,
        blind_spots=(contract.known_blind_spots,),
    )
    setup_steps = (
        HarnessSetupStep(
            step_id="connect",
            title=f"Connect {display_name}",
            body=(
                "Install native provider hooks on the Paseo daemon host."
                if contract.harness == "paseo"
                else f"Add Guard's local protection hooks for {display_name}."
            ),
            command=("hol-guard", "apps", "connect", alias),
            writes_config=True,
        ),
        HarnessSetupStep(
            step_id="review-coverage",
            title="Review what Guard can see",
            body="Check covered events and known blind spots before relying on this app.",
        ),
    )
    verify_steps = (
        HarnessSetupStep(
            step_id="safe-test",
            title="Run a safe protection test",
            body="Confirm Guard can detect the app without reading secrets or changing app config.",
            command=("hol-guard", "apps", "test", alias),
        ),
    )
    repair_steps = (
        HarnessSetupStep(
            step_id="repair",
            title=f"Repair {display_name} protection",
            body="Re-apply Guard managed config if hooks were removed or changed.",
            command=("hol-guard", "apps", "repair", alias),
            writes_config=True,
        ),
    )
    return HarnessSetupContract(
        harness=contract.harness,
        display_name=display_name,
        install_aliases=contract.install_aliases,
        setup_steps=setup_steps,
        verify_steps=verify_steps,
        repair_steps=repair_steps,
        coverage=coverage,
        surface_capabilities=contract.surface_capabilities,
        supported_actions=contract.supported_actions,
        docs_path=contract.docs_path,
        icon_label=contract.icon_label,
    )
