"""Bounded limits for Extension controls and each catalog representation.

Catalog byte budgets are per representation, not one shared number:
``contracts/managed-controls/v1/limits.json`` is the published Cloud v1 contract, and
``contracts/catalog-delivery/limits.json`` holds the local delivery budgets. Tests
check both manifests against these constants.
"""

from __future__ import annotations

from typing import Final

LIMITS_SCHEMA_VERSION: Final = 1
MAX_CATALOG_EXTENSIONS: Final = 512
# Cloud v1 privacy-safe catalog (managed-controls v1). Its receiver requires this exact value.
CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES: Final = 1_000_000
# The Cloud v1 sync route accepts the catalog plus a small idempotency wrapper.
CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES: Final = CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES + 16_384
# Local delivery: the legacy full daemon catalog response and the packaged catalog artifact.
MAX_DAEMON_CATALOG_RESPONSE_BYTES: Final = 8_000_000
MAX_DAEMON_GET_RESPONSE_BYTES: Final = 1_048_576
MAX_GENERATED_CATALOG_ARTIFACT_BYTES: Final = 8_000_000
MAX_NATIVE_COMMAND_PROGRAM_BYTES: Final = 4 * 1024 * 1024
MAX_CONTROL_LAYERS: Final = 2
MAX_CONTROL_SET_RULES: Final = 1_024
MAX_CONTROL_SET_TARGETS: Final = 1_024
MAX_CONTROLS_PER_LAYER: Final = 512
MAX_CONTROLS_TOTAL: Final = MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER
MAX_INPUT_TEXT_LENGTH: Final = 256
MAX_OBSERVATIONS: Final = 2_048
MAX_PERMISSIONS_PER_EXTENSION: Final = 512
MAX_RESOLUTION_IDS: Final = 1_024


def advertised_extension_control_limits() -> dict[str, int]:
    """Return the managed-controls v1 limits profile shared with Cloud."""

    return {
        "schema_version": LIMITS_SCHEMA_VERSION,
        "max_catalog_extensions": MAX_CATALOG_EXTENSIONS,
        "max_catalog_payload_bytes": CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES,
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
