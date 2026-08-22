"""Shared bounded limits for Extension controls and catalog exchange."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Final

LIMITS_SCHEMA_VERSION: Final = 1
MAX_CATALOG_EXTENSIONS: Final = 512
MAX_CATALOG_PAYLOAD_BYTES: Final = 1_000_000
MAX_CONTROL_LAYERS: Final = 2
MAX_CONTROL_SET_RULES: Final = 1_024
MAX_CONTROL_SET_TARGETS: Final = 1_024
MAX_CONTROLS_PER_LAYER: Final = 512
MAX_CONTROLS_TOTAL: Final = MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER
MAX_INPUT_TEXT_LENGTH: Final = 256
MAX_OBSERVATIONS: Final = 2_048
MAX_PERMISSIONS_PER_EXTENSION: Final = 512
MAX_RESOLUTION_IDS: Final = 1_024


class ExtensionControlLimitViolation(str, Enum):
    LAYERS = "layer_limit_exceeded"
    PER_LAYER = "layer_control_limit_exceeded"
    TOTAL_CONTROLS = "control_limit_exceeded"
    RESOLUTION_IDS = "resolution_id_limit_exceeded"
    OBSERVATIONS = "observation_limit_exceeded"
    INPUT_TEXT = "input_text_limit_exceeded"


def extension_control_limit_violation(
    *,
    layer_sizes: Iterable[int],
    extension_id_count: int = 0,
    permission_id_count: int = 0,
    observation_count: int = 0,
    max_input_length: int = 0,
) -> ExtensionControlLimitViolation | None:
    sizes = tuple(layer_sizes)
    if len(sizes) > MAX_CONTROL_LAYERS:
        return ExtensionControlLimitViolation.LAYERS
    if any(size > MAX_CONTROLS_PER_LAYER for size in sizes):
        return ExtensionControlLimitViolation.PER_LAYER
    if sum(sizes) > MAX_CONTROLS_TOTAL:
        return ExtensionControlLimitViolation.TOTAL_CONTROLS
    if extension_id_count > MAX_RESOLUTION_IDS or permission_id_count > MAX_RESOLUTION_IDS:
        return ExtensionControlLimitViolation.RESOLUTION_IDS
    if observation_count > MAX_OBSERVATIONS:
        return ExtensionControlLimitViolation.OBSERVATIONS
    if max_input_length > MAX_INPUT_TEXT_LENGTH:
        return ExtensionControlLimitViolation.INPUT_TEXT
    return None


def advertised_extension_control_limits() -> dict[str, int]:
    return {
        "schema_version": LIMITS_SCHEMA_VERSION,
        "max_catalog_extensions": MAX_CATALOG_EXTENSIONS,
        "max_catalog_payload_bytes": MAX_CATALOG_PAYLOAD_BYTES,
        "max_control_layers": MAX_CONTROL_LAYERS,
        "max_control_set_rules": MAX_CONTROL_SET_RULES,
        "max_control_set_targets": MAX_CONTROL_SET_TARGETS,
        "max_controls_per_layer": MAX_CONTROLS_PER_LAYER,
        "max_controls_total": MAX_CONTROLS_TOTAL,
        "max_input_text_length": MAX_INPUT_TEXT_LENGTH,
        "max_observations": MAX_OBSERVATIONS,
        "max_permissions_per_extension": MAX_PERMISSIONS_PER_EXTENSION,
        "max_resolution_ids": MAX_RESOLUTION_IDS,
    }
