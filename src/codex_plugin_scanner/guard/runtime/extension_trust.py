"""Trust-class lookup and inert-external observation filtering."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Final, Literal, cast

from .extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
    ExtensionControlLayer,
)

TrustClass = Literal["first-party", "trusted-library", "external"]
Activation = Literal["default-on", "opt-in"]

_MAP_SCHEMA: Final = "guard.extension-trust-class-map.v1"
_BINDING_SCHEMA: Final = "guard.extension-trust-binding.v1"
_VALID_CLASSES: Final = frozenset({"first-party", "trusted-library", "external"})
_HOL_PUBLISHER: Final = {"id": "hol", "displayName": "Hashgraph Online"}
_CURATED_PUBLISHER: Final = {"id": "hol-curated", "displayName": "HOL curated library"}


def _bindings_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contracts" / "extensions" / "trust"


def _binding_payload(path: Path) -> tuple[str, TrustClass]:
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid trust binding {path.name}") from exc
    if not isinstance(payload, dict) or payload.get("schemaVersion") != _BINDING_SCHEMA:
        raise ValueError(f"invalid trust binding schema {path.name}")
    extension = payload.get("extension")
    trust_class = payload.get("trustClass")
    if not isinstance(extension, str) or extension != path.name[: -len(".v1.json")]:
        raise ValueError(f"trust binding {path.name} extension does not match filename")
    if trust_class not in _VALID_CLASSES:
        raise ValueError(f"trust binding {path.name} has unknown trust class")
    return extension, cast(TrustClass, trust_class)


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
    # Frozen binaries ship only packaged data; the source-tree bindings directory
    # is absent there and must never be consulted.
    if not bool(getattr(sys, "frozen", False)):
        bindings = _bindings_dir()
        if bindings.is_dir():
            return trust_map_from_bindings(bindings)
    packaged = _packaged_map_bytes()
    if packaged is None:
        if bool(getattr(sys, "frozen", False)):
            raise FileNotFoundError("frozen Guard is missing packaged extension trust-class map")
        raise FileNotFoundError("Guard requires authored trust bindings or a packaged extension trust-class map")
    raw = packaged
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schemaVersion") != _MAP_SCHEMA:
        raise ValueError("invalid trust-class map")
    return payload


def trust_binding_index(bindings: Path) -> dict[str, TrustClass]:
    """Fold authored per-extension bindings into an id -> trust-class index.

    Strictly validates each binding file: schema, filename == extension, known
    class, and no duplicate extension across files. Shared by the runtime trust
    lookup and the artifact refresh so authored and generated surfaces agree.
    """
    index: dict[str, TrustClass] = {}
    for path in sorted(bindings.glob("*.v1.json")):
        extension, trust_class = _binding_payload(path)
        if extension in index:
            raise ValueError(f"duplicate trust binding for {extension}")
        index[extension] = trust_class
    return index


def trust_map_from_bindings(bindings: Path) -> dict[str, object]:
    """Assemble the trust-class map contract from per-extension bindings."""
    classes: dict[str, list[str]] = {"first-party": [], "trusted-library": [], "external": []}
    for extension, trust_class in sorted(trust_binding_index(bindings).items()):
        classes[trust_class].append(extension)
    for values in classes.values():
        values.sort()
    return {
        "schemaVersion": _MAP_SCHEMA,
        "publishers": {"hol": dict(_HOL_PUBLISHER), "hol-curated": dict(_CURATED_PUBLISHER)},
        "classes": classes,
    }


def _packaged_map_bytes() -> bytes | None:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.extensions")
        return (root / "trust-class-map.v1.json").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        from .extension_contribution import frozen_package_data

        frozen = frozen_package_data("extensions", "trust-class-map.v1.json")
        return frozen.read_bytes() if frozen is not None and frozen.is_file() else None


def trust_class_for(extension_id: str) -> TrustClass:
    """Return the curated class.

    Unmapped ids stay first-party so custom device CLIs and test registries
    remain on. Production catalog ids must appear in the trust-class map;
    CI fails if a built-in id is missing.
    """

    mapped = _trust_map().get(extension_id)
    if mapped is not None:
        return mapped
    return "first-party"


def mapped_ids() -> frozenset[str]:
    return frozenset(_trust_map())


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
