"""Harness protection registry, loaded and validated by the native runtime.

The contracts and their per-event capability declarations live in
``guard/contracts/harness-protection-contracts.v1.json``. The runtime's
``harness_contract_registry`` kind reads that file, validates it, applies the
defaults for omitted fields and answers ready rows; the frozen dataclasses here
are built field for field from those rows. Nothing is read until a caller asks,
so importing this module never reaches the runtime.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from .setup_contract_models import HarnessEventCapability, HarnessProtectionContract


def _registry(op: str, **fields: object) -> dict[str, Any]:
    from .native_runner_authority import native_runner_authority

    return native_runner_authority("harness_contract_registry", {"op": op, **fields})


def _capability(row: dict[str, Any]) -> HarnessEventCapability:
    return HarnessEventCapability(
        harness=row["harness"],
        adapter=row["adapter"],
        host_version_scope=row["host_version_scope"],
        os_arch=row["os_arch"],
        local_hosted=row["local_hosted"],
        event=row["event"],
        tools=tuple(row["tools"]),
        surface=row["surface"],
        transport=row["transport"],
        mode=row["mode"],
        declared_actions=tuple(row["declared_actions"]),
        error_behavior=row["error_behavior"],
        mandatory_compatibility=row["mandatory_compatibility"],
        known_blind_spots=tuple(row["known_blind_spots"]),
        source_reference=row["source_reference"],
    )


def _contract(row: dict[str, Any]) -> HarnessProtectionContract:
    return HarnessProtectionContract(
        harness=row["harness"],
        install_aliases=tuple(row["install_aliases"]),
        config_paths=tuple(row["config_paths"]),
        event_surfaces=tuple(row["event_surfaces"]),
        native_approval=row["native_approval"],
        browser_fallback=row["browser_fallback"],
        resume_support=row["resume_support"],
        known_blind_spots=row["known_blind_spots"],
        smoke_command=row["smoke_command"],
        surface_capabilities=tuple(row["surface_capabilities"]),
        supported_actions=tuple(row["supported_actions"]),
        docs_path=row["docs_path"],
        icon_label=row["icon_label"],
        capability_events=tuple(_capability(event) for event in row["capability_events"]),
    )


@lru_cache(maxsize=1)
def harness_contracts() -> tuple[HarnessProtectionContract, ...]:
    """Every harness protection contract, in the bundled file's order."""

    return tuple(_contract(row) for row in _registry("contracts")["contracts"])


@lru_cache(maxsize=1)
def harness_names() -> tuple[str, ...]:
    """The canonical harness names, in the bundled file's order."""

    return tuple(_registry("harnesses")["harnesses"])


@lru_cache(maxsize=256)
def contract_for(harness: str) -> HarnessProtectionContract | None:
    """The contract a harness name or install alias identifies, or ``None``."""

    row = _registry("contract", harness=harness)["contract"]
    if row is None:
        return None
    # The same object ``harness_contracts()`` holds, so identity checks agree.
    return next(
        (contract for contract in harness_contracts() if contract.harness == row["harness"]),
        _contract(row),
    )


def __getattr__(name: str) -> object:
    # ``HARNESS_CONTRACTS`` stays importable by name, resolved on first use.
    if name == "HARNESS_CONTRACTS":
        return harness_contracts()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
