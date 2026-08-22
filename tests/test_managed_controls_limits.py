from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import (
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    MAX_CATALOG_EXTENSIONS,
    MAX_CONTROL_LAYERS,
    MAX_CONTROLS_PER_LAYER,
    MAX_CONTROLS_TOTAL,
    MAX_INPUT_TEXT_LENGTH,
    MAX_OBSERVATIONS,
    MAX_PERMISSIONS_PER_EXTENSION,
    MAX_RESOLUTION_IDS,
    ExtensionControlLimitViolation,
    advertised_extension_control_limits,
    extension_control_limit_violation,
)

ROOT = Path(__file__).resolve().parents[1]
LIMITS_PATH = ROOT / "contracts" / "managed-controls" / "v1" / "limits.json"
API_PATH = ROOT / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "extension_control_api.py"
NAVIGATION_PATH = ROOT / "dashboard" / "src" / "shell-navigation-model.ts"
RULES_PAGE_PATH = ROOT / "dashboard" / "src" / "policy-workspace-page.tsx"
DASHBOARD_LIMITS_PATH = ROOT / "dashboard" / "src" / "extension-controls-normalize.ts"


def test_shared_limits_fixture_matches_runtime_constants() -> None:
    fixture = json.loads(LIMITS_PATH.read_text(encoding="utf-8"))
    assert fixture == advertised_extension_control_limits()
    assert fixture["max_controls_total"] == (fixture["max_control_layers"] * fixture["max_controls_per_layer"])


@pytest.mark.parametrize("count", [MAX_CONTROLS_PER_LAYER - 1, MAX_CONTROLS_PER_LAYER])
def test_per_layer_control_boundary_accepts_limit_and_below(count: int) -> None:
    assert extension_control_limit_violation(layer_sizes=(count,)) is None


def test_per_layer_control_boundary_rejects_limit_plus_one() -> None:
    assert (
        extension_control_limit_violation(layer_sizes=(MAX_CONTROLS_PER_LAYER + 1,))
        is ExtensionControlLimitViolation.PER_LAYER
    )


@pytest.mark.parametrize("layer_count", [MAX_CONTROL_LAYERS - 1, MAX_CONTROL_LAYERS])
def test_layer_boundary_accepts_limit_and_below(layer_count: int) -> None:
    assert extension_control_limit_violation(layer_sizes=(0,) * layer_count) is None


def test_layer_boundary_rejects_limit_plus_one() -> None:
    assert (
        extension_control_limit_violation(layer_sizes=(0,) * (MAX_CONTROL_LAYERS + 1))
        is ExtensionControlLimitViolation.LAYERS
    )


def test_total_control_boundary_is_consistent() -> None:
    assert MAX_CONTROLS_TOTAL == MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER
    assert extension_control_limit_violation(layer_sizes=(MAX_CONTROLS_PER_LAYER, MAX_CONTROLS_PER_LAYER)) is None


@pytest.mark.parametrize(
    ("field", "accepted", "rejected", "violation"),
    [
        (
            "extension_id_count",
            MAX_RESOLUTION_IDS,
            MAX_RESOLUTION_IDS + 1,
            ExtensionControlLimitViolation.RESOLUTION_IDS,
        ),
        (
            "permission_id_count",
            MAX_RESOLUTION_IDS,
            MAX_RESOLUTION_IDS + 1,
            ExtensionControlLimitViolation.RESOLUTION_IDS,
        ),
        (
            "observation_count",
            MAX_OBSERVATIONS,
            MAX_OBSERVATIONS + 1,
            ExtensionControlLimitViolation.OBSERVATIONS,
        ),
        (
            "max_input_length",
            MAX_INPUT_TEXT_LENGTH,
            MAX_INPUT_TEXT_LENGTH + 1,
            ExtensionControlLimitViolation.INPUT_TEXT,
        ),
    ],
)
def test_resolution_boundaries(
    field: str,
    accepted: int,
    rejected: int,
    violation: ExtensionControlLimitViolation,
) -> None:
    accepted_values = {field: accepted}
    rejected_values = {field: rejected}
    assert extension_control_limit_violation(layer_sizes=(), **accepted_values) is None
    assert extension_control_limit_violation(layer_sizes=(), **rejected_values) is violation


def _catalog_extension(index: int) -> CommandSafetyExtension:
    extension = CommandSafetyExtension(
        extension_id=f"command.limit{index}",
        version="1.0.0",
        name=f"Limit {index}",
        description="Bounded catalog fixture.",
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=("Review the requested capability.",),
        delegated_protection="package-firewall",
        ecosystem_ids=(f"limit{index}",),
        executables=(f"limit{index}",),
        reference_urls=("https://example.com/managed-controls-limit-fixture",),
    )
    return replace(
        extension,
        permissions=(
            replace(
                extension.permissions[0],
                example_command=f"limit{index} scan",
            ),
        ),
    )


@pytest.mark.parametrize(
    "count",
    [MAX_CATALOG_EXTENSIONS - 1, MAX_CATALOG_EXTENSIONS],
)
def test_registry_extension_count_boundaries_accept_limit_and_below(count: int) -> None:
    registry = CommandSafetyExtensionRegistry(tuple(_catalog_extension(index) for index in range(count)))
    assert len(registry.extensions) == count


def test_registry_extension_count_boundary_rejects_limit_plus_one() -> None:
    with pytest.raises(ValueError, match="catalog extension limit"):
        CommandSafetyExtensionRegistry(tuple(_catalog_extension(index) for index in range(MAX_CATALOG_EXTENSIONS + 1)))


def _extension_with_permissions(count: int) -> CommandSafetyExtension:
    extension = _catalog_extension(9999)
    template = extension.permissions[0]
    permissions = tuple(
        replace(
            template,
            permission_id=f"{extension.extension_id}.permission.p{index}",
            typed_capabilities=(),
        )
        for index in range(count)
    )
    return replace(extension, permissions=permissions)


@pytest.mark.parametrize(
    "count",
    [MAX_PERMISSIONS_PER_EXTENSION - 1, MAX_PERMISSIONS_PER_EXTENSION],
)
def test_registry_permission_count_boundaries_accept_limit_and_below(count: int) -> None:
    registry = CommandSafetyExtensionRegistry((_extension_with_permissions(count),))
    assert len(registry.extensions[0].permissions) == count


def test_registry_permission_count_boundary_rejects_limit_plus_one() -> None:
    with pytest.raises(ValueError, match="permission limit"):
        CommandSafetyExtensionRegistry((_extension_with_permissions(MAX_PERMISSIONS_PER_EXTENSION + 1),))


def test_daemon_api_uses_shared_limits_and_no_longer_advertises_4096_controls() -> None:
    source = API_PATH.read_text(encoding="utf-8")
    assert "advertised_extension_control_limits" in source
    assert "MAX_CONTROLS_TOTAL" in source
    assert "MAX_CATALOG_PAYLOAD_BYTES" in source
    assert "_MAX_CONTROLS = 4096" not in source


def test_dashboard_catalog_limits_match_shared_fixture() -> None:
    fixture = json.loads(LIMITS_PATH.read_text(encoding="utf-8"))
    source = DASHBOARD_LIMITS_PATH.read_text(encoding="utf-8")
    assert f"extensions: {fixture['max_catalog_extensions']}" in source
    assert f"permissionsPerExtension: {fixture['max_permissions_per_extension']}" in source
    assert f"controls: {fixture['max_controls_total']}" in source
    assert f"layers: {fixture['max_control_layers']}" in source


def test_accessible_product_language_matches_visible_navigation() -> None:
    navigation = NAVIGATION_PATH.read_text(encoding="utf-8")
    rules_page = RULES_PAGE_PATH.read_text(encoding="utf-8")
    assert 'label: "Rules & exceptions"' in navigation
    assert 'description: "Remembered decisions, Guard Cloud rules, and exceptions"' in navigation
    assert 'label: "Extensions"' in navigation
    assert 'eyebrow="Rules & exceptions"' in rules_page
    assert 'href: "/policy"' in navigation
