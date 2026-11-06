"""Static harness protection registry.

The contracts and their per-event capability declarations live in
``guard/contracts/harness-protection-contracts.v1.json``. Capability rows
omit the harness and adapter (the owning contract's harness), and
``host_version_scope``/``os_arch``/``local_hosted`` when they are
``unknown``/``unknown``/``local``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final, cast

from .contract_models import CapabilityLocalHosted, HarnessEventCapability, HarnessProtectionContract

_CONTRACT_PATH: Final = Path(__file__).resolve().parent.parent / "contracts" / "harness-protection-contracts.v1.json"
_CONTRACT_SCHEMA: Final = "hol-guard.harness-protection-contracts.v1"
_CONTRACT_KEYS: Final = frozenset(
    {
        "harness",
        "install_aliases",
        "config_paths",
        "event_surfaces",
        "native_approval",
        "browser_fallback",
        "resume_support",
        "known_blind_spots",
        "smoke_command",
        "surface_capabilities",
        "supported_actions",
        "docs_path",
        "icon_label",
        "capability_events",
    }
)
_EVENT_KEYS: Final = frozenset(
    {
        "harness",
        "adapter",
        "host_version_scope",
        "os_arch",
        "local_hosted",
        "event",
        "transport",
        "mode",
        "declared_actions",
        "error_behavior",
        "mandatory_compatibility",
        "known_blind_spots",
        "source_reference",
    }
)


def _object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or not set(cast("dict[str, object]", value)) <= keys:
        raise ValueError("harness protection contract has a malformed entry")
    return cast("dict[str, object]", value)


def _text(row: dict[str, object], key: str, default: str | None = None) -> str:
    value = row.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"harness protection contract field {key} must be a string")
    return value


def _optional_text(row: dict[str, object], key: str) -> str | None:
    value = row.get(key)
    return None if value is None else _text(row, key)


def _texts(row: dict[str, object], key: str, *, required: bool = True) -> tuple[str, ...]:
    value = row.get(key) if required or key in row else []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in cast("list[object]", value)):
        raise ValueError(f"harness protection contract field {key} must be a list of strings")
    return tuple(cast("list[str]", value))


def _flag(row: dict[str, object], key: str) -> bool:
    value = row.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"harness protection contract field {key} must be a boolean")
    return value


def _local_hosted(row: dict[str, object]) -> CapabilityLocalHosted:
    value = _text(row, "local_hosted", "local")
    if value not in {"local", "hosted", "unknown"}:
        raise ValueError(f"unsupported local_hosted value: {value!r}")
    return cast("CapabilityLocalHosted", value)


def _capability(harness: str, value: object) -> HarnessEventCapability:
    row = _object(value, _EVENT_KEYS)
    return HarnessEventCapability(
        harness=_text(row, "harness", harness),
        adapter=_text(row, "adapter", harness),
        host_version_scope=_text(row, "host_version_scope", "unknown"),
        os_arch=_text(row, "os_arch", "unknown"),
        local_hosted=_local_hosted(row),
        event=_text(row, "event"),
        transport=_text(row, "transport"),
        mode=_text(row, "mode"),
        declared_actions=_texts(row, "declared_actions"),
        error_behavior=_text(row, "error_behavior"),
        mandatory_compatibility=_text(row, "mandatory_compatibility"),
        known_blind_spots=_texts(row, "known_blind_spots"),
        source_reference=_text(row, "source_reference"),
    )


def _contract(value: object) -> HarnessProtectionContract:
    row = _object(value, _CONTRACT_KEYS)
    harness = _text(row, "harness")
    events = row.get("capability_events")
    if not isinstance(events, list) or not events:
        raise ValueError("harness protection contract needs capability events")
    return HarnessProtectionContract(
        harness=harness,
        install_aliases=_texts(row, "install_aliases"),
        config_paths=_texts(row, "config_paths"),
        event_surfaces=_texts(row, "event_surfaces"),
        native_approval=_flag(row, "native_approval"),
        browser_fallback=_flag(row, "browser_fallback"),
        resume_support=_flag(row, "resume_support"),
        known_blind_spots=_text(row, "known_blind_spots"),
        smoke_command=_text(row, "smoke_command"),
        surface_capabilities=_texts(row, "surface_capabilities", required=False),
        supported_actions=_texts(row, "supported_actions", required=False),
        docs_path=_optional_text(row, "docs_path"),
        icon_label=_optional_text(row, "icon_label"),
        capability_events=tuple(_capability(harness, event) for event in cast("list[object]", events)),
    )


def _load() -> tuple[HarnessProtectionContract, ...]:
    document: object = json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or cast("dict[str, object]", document).get("schema") != _CONTRACT_SCHEMA:
        raise ValueError("harness protection contract has an unsupported schema")
    contracts = cast("dict[str, object]", document).get("contracts")
    if not isinstance(contracts, list):
        raise ValueError("harness protection contract has no contracts")
    return tuple(_contract(contract) for contract in cast("list[object]", contracts))


HARNESS_CONTRACTS: Final[tuple[HarnessProtectionContract, ...]] = _load()
