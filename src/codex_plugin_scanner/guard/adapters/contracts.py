"""Harness protection contracts for HOL Guard.

Each contract captures the static protection capabilities, install aliases,
config file paths, event surfaces, known blind spots, and smoke command for
one AI coding harness that HOL Guard supports.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from .contract_models import CAPABILITY_DECLARED_ACTIONS as CAPABILITY_DECLARED_ACTIONS
from .contract_models import CapabilityLocalHosted as CapabilityLocalHosted
from .contract_models import HarnessCoverageSummary as HarnessCoverageSummary
from .contract_models import HarnessEventCapability as HarnessEventCapability
from .contract_models import HarnessProtectionContract as HarnessProtectionContract
from .contract_models import HarnessSetupContract as HarnessSetupContract
from .contract_models import HarnessSetupStep as HarnessSetupStep
from .contract_registry import HARNESS_CONTRACTS as HARNESS_CONTRACTS

_CONTRACT_BY_ALIAS: dict[str, HarnessProtectionContract] = {}
for _c in HARNESS_CONTRACTS:
    _CONTRACT_BY_ALIAS[_c.harness] = _c
    for _alias in _c.install_aliases:
        _CONTRACT_BY_ALIAS[_alias] = _c


def contract_for(harness: str) -> HarnessProtectionContract | None:
    """Return the contract for a harness name or install alias, or None."""
    return _CONTRACT_BY_ALIAS.get(harness)


@lru_cache(maxsize=256)
def display_name_for(harness: str) -> str:
    """The label for a harness name or install alias, or the name itself when it has none."""

    label = _setup_contract_kind("display_name", harness).get("display_name")
    if not isinstance(label, str):
        raise ValueError("harness display name answer is malformed")
    return label


def setup_contract_for(harness: str) -> HarnessSetupContract | None:
    """Return guided setup metadata for a harness name or install alias.

    The native runtime renders the steps and coverage from the bundled contract.
    """

    payload = _setup_contract_kind("contract", harness).get("contract")
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("harness setup contract answer is malformed")
    return _setup_contract_from(payload)


def _setup_contract_kind(op: str, harness: str) -> dict[str, Any]:
    from ..native_runner_authority import native_runner_authority

    return native_runner_authority("harness_setup_contract", {"op": op, "harness": harness})


def _texts(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("harness setup contract answer is malformed")
    return tuple(value)


def _optional_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError("harness setup contract answer is malformed")
    return value


def _step(payload: object) -> HarnessSetupStep:
    if not isinstance(payload, dict):
        raise ValueError("harness setup contract answer is malformed")
    step_id, title, body = payload.get("step_id"), payload.get("title"), payload.get("body")
    writes, confirms = payload.get("writes_config"), payload.get("requires_confirmation")
    if not (isinstance(step_id, str) and isinstance(title, str) and isinstance(body, str)):
        raise ValueError("harness setup contract answer is malformed")
    if not (isinstance(writes, bool) and isinstance(confirms, bool)):
        raise ValueError("harness setup contract answer is malformed")
    return HarnessSetupStep(
        step_id=step_id,
        title=title,
        body=body,
        command=_texts(payload, "command"),
        writes_config=writes,
        requires_confirmation=confirms,
    )


def _steps(payload: Mapping[str, Any], key: str) -> tuple[HarnessSetupStep, ...]:
    steps = payload.get(key)
    if not isinstance(steps, list):
        raise ValueError("harness setup contract answer is malformed")
    return tuple(_step(step) for step in steps)


def _setup_contract_from(payload: Mapping[str, Any]) -> HarnessSetupContract:
    coverage = payload.get("coverage")
    harness, display_name = payload.get("harness"), payload.get("display_name")
    if not (isinstance(coverage, dict) and isinstance(harness, str) and isinstance(display_name, str)):
        raise ValueError("harness setup contract answer is malformed")
    flags = [coverage.get(key) for key in ("native_hooks", "browser_fallback", "mcp_proxy", "prompt_hooks")]
    if not all(isinstance(flag, bool) for flag in flags):
        raise ValueError("harness setup contract answer is malformed")
    native_hooks, browser_fallback, mcp_proxy, prompt_hooks = flags
    return HarnessSetupContract(
        harness=harness,
        display_name=display_name,
        install_aliases=_texts(payload, "install_aliases"),
        setup_steps=_steps(payload, "setup_steps"),
        verify_steps=_steps(payload, "verify_steps"),
        repair_steps=_steps(payload, "repair_steps"),
        coverage=HarnessCoverageSummary(
            native_hooks=native_hooks,
            browser_fallback=browser_fallback,
            mcp_proxy=mcp_proxy,
            prompt_hooks=prompt_hooks,
            blind_spots=_texts(coverage, "blind_spots"),
        ),
        surface_capabilities=_texts(payload, "surface_capabilities"),
        supported_actions=_texts(payload, "supported_actions"),
        docs_path=_optional_text(payload, "docs_path"),
        icon_label=_optional_text(payload, "icon_label"),
    )
