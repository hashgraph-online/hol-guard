"""Trust-class lookup and inert-external observation filtering."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Final, Literal, Protocol, TypeVar, cast

from .extension_contribution import contribution_catalog_overlay
from .extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
    ExtensionControlLayer,
)


class _ExtensionLike(Protocol):
    @property
    def extension_id(self) -> str: ...

    @property
    def required(self) -> bool: ...


class _ObservationLike(Protocol):
    @property
    def extension(self) -> _ExtensionLike: ...


_ObservationT = TypeVar("_ObservationT", bound=_ObservationLike)

TrustClass = Literal["first-party", "trusted-library", "external"]
Activation = Literal["default-on", "opt-in"]

_MAP_SCHEMA: Final = "guard.extension-trust-class-map.v1"
_VALID_CLASSES: Final = frozenset({"first-party", "trusted-library", "external"})
_TEST_ID: Final = "command.test"
_HOL_PUBLISHER: Final = {"id": "hol", "displayName": "Hashgraph Online"}
_CURATED_PUBLISHER: Final = {"id": "hol-curated", "displayName": "HOL curated library"}


@lru_cache(maxsize=1)
def _trust_map() -> dict[str, TrustClass]:
    payload = _load_map()
    classes = payload.get("classes")
    if not isinstance(classes, dict):
        raise ValueError("trust-class map classes must be an object")
    index: dict[str, TrustClass] = {}
    for class_name, ids in classes.items():
        if class_name not in _VALID_CLASSES:
            raise ValueError(f"unknown trust class {class_name}")
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise ValueError(f"trust class {class_name} must be a list of ids")
        typed = cast(TrustClass, class_name)
        for extension_id in ids:
            previous = index.get(extension_id)
            if previous is not None:
                raise ValueError(f"trust-class overlap for {extension_id}")
            index[extension_id] = typed
    return index


def _load_map() -> dict[str, object]:
    packaged = _packaged_map_bytes()
    raw = packaged if packaged is not None else _repo_map_path().read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schemaVersion") != _MAP_SCHEMA:
        raise ValueError("invalid trust-class map")
    return payload


def _packaged_map_bytes() -> bytes | None:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.extensions")
        return (root / "trust-class-map.v1.json").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None


def _repo_map_path() -> Path:
    return Path(__file__).resolve().parents[4] / "contracts" / "extensions" / "trust-class-map.v1.json"


def trust_class_for(extension_id: str) -> TrustClass:
    """Return the curated class, or external for unmapped production ids."""

    mapped = _trust_map().get(extension_id)
    if mapped is not None:
        return mapped
    if extension_id == _TEST_ID or extension_id.startswith(f"{_TEST_ID}."):
        return "first-party"
    return "external"


def activation_for(extension_id: str) -> Activation:
    return "opt-in" if trust_class_for(extension_id) == "external" else "default-on"


def catalog_enabled(extension_id: str, *, required: bool) -> bool:
    if required:
        return True
    return trust_class_for(extension_id) != "external"


def publisher_for(extension_id: str) -> dict[str, str]:
    trust = trust_class_for(extension_id)
    if trust == "first-party":
        return dict(_HOL_PUBLISHER)
    if trust == "trusted-library":
        return dict(_CURATED_PUBLISHER)
    return {"id": "community", "displayName": "Community"}


def catalog_trust_fields(extension_id: str, *, required: bool) -> dict[str, object]:
    trust = trust_class_for(extension_id)
    fields: dict[str, object] = {
        "enabled": catalog_enabled(extension_id, required=required),
        "trust_class": trust,
        "activation": activation_for(extension_id),
        "publisher": publisher_for(extension_id),
        "icon": {"kind": "none"},
    }
    overlay = contribution_catalog_overlay(extension_id)
    if overlay is not None:
        fields.update(overlay)
    return fields


def mapped_ids() -> frozenset[str]:
    return frozenset(_trust_map())


def ids_for_class(trust_class: TrustClass) -> frozenset[str]:
    return frozenset(extension_id for extension_id, item in _trust_map().items() if item == trust_class)


def extension_is_active(
    extension_id: str,
    layers: Iterable[ExtensionControlLayer] | None,
    *,
    required: bool = False,
) -> bool:
    if required or trust_class_for(extension_id) != "external":
        return True
    layer_values = tuple(layers or ())
    from .extension_control_resolver import compose_control_layers

    composed = compose_control_layers(layer_values)
    if composed.state_for(ControlTargetKind.EXTENSION, extension_id) is ControlState.DISABLED:
        return False
    return any(
        layer.kind is ControlLayerKind.LOCAL_ADMIN
        and any(
            control.target.kind is ControlTargetKind.EXTENSION
            and control.target.target_id == extension_id
            and control.state is ControlState.ENABLED
            for control in layer.controls
        )
        for layer in layer_values
    )


def filter_inert_external_observations(
    observations: Sequence[_ObservationT],
    layers: Iterable[ExtensionControlLayer] | None,
) -> tuple[_ObservationT, ...]:
    """Drop external observations unless a local-admin enable is present."""

    layer_values = tuple(layers or ())
    return tuple(
        item
        for item in observations
        if extension_is_active(item.extension.extension_id, layer_values, required=item.extension.required)
    )


def reset_trust_map_cache() -> None:
    from .extension_contribution import reset_contribution_cache

    _trust_map.cache_clear()
    reset_contribution_cache()
