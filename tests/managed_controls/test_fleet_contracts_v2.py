from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from importlib.resources import files as resource_files
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.managed_controls.bundle import ManagedControlsBundleError, parse_extension_contract
from codex_plugin_scanner.guard.managed_controls.catalog import CatalogProjection
from codex_plugin_scanner.guard.managed_controls.fleet_contracts import (
    REQUIRED_FLEET_CAPABILITIES,
    ContractKind,
    FleetContractError,
    apply_adversarial_fixture,
    canonical_fleet_contract_bytes,
    fleet_contract_digest,
    load_adversarial_fleet_fixtures,
    load_shared_fleet_fixtures,
    negotiate_fleet_capabilities,
    validate_custom_extension_binding,
    validate_fleet_contract,
    verify_packaged_contract_manifest,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    ManagedControlsPolicyError,
    parse_managed_controls_policy_fields,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts/managed-controls/v2"
PACKAGE_ROOT = resource_files("codex_plugin_scanner.guard.managed_controls.contracts.v2")
FIXTURES = load_shared_fleet_fixtures()
ADVERSARIAL = load_adversarial_fleet_fixtures()
KINDS: tuple[ContractKind, ...] = (
    "fleetExtensionConfiguration",
    "assignment",
    "customExtensionDefinition",
    "customExtensionConfiguration",
    "catalogSemantics",
)


@pytest.mark.parametrize("kind", KINDS)
def test_shared_positive_contracts_validate_and_match_frozen_digests(
    kind: ContractKind,
) -> None:
    value = FIXTURES[kind]

    normalized = validate_fleet_contract(kind, value)

    assert normalized["schemaVersion"] == cast(dict[str, object], value)["schemaVersion"]
    assert canonical_fleet_contract_bytes(kind, value) == canonical_fleet_contract_bytes(kind, normalized)
    assert fleet_contract_digest(kind, value) == cast(dict[str, str], FIXTURES["digests"])[kind]


@pytest.mark.parametrize(
    "case",
    cast(list[dict[str, object]], ADVERSARIAL["cases"]),
    ids=lambda case: cast(dict[str, object], case)["id"],
)
def test_shared_adversarial_contracts_fail_with_stable_reason(
    case: dict[str, object],
) -> None:
    kind = cast(ContractKind, case["contract"])
    candidate = apply_adversarial_fixture(FIXTURES[kind], case)

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract(kind, candidate)

    assert caught.value.code == case["expectedError"]
    assert "/Users/" not in str(caught.value)
    assert "token secret" not in str(caught.value).lower()


def test_manifest_pins_every_shared_root_and_packaged_resource_byte() -> None:
    manifest = json.loads((CONTRACT_ROOT / "manifest.json").read_text(encoding="utf-8"))
    declared = [entry["path"] for entry in manifest["files"]]
    actual = sorted(
        path.name
        for path in CONTRACT_ROOT.iterdir()
        if path.is_file() and path.suffix == ".json" and path.name != "manifest.json"
    )
    assert sorted(declared) == actual
    assert len(declared) == len(set(declared))
    assert verify_packaged_contract_manifest() == tuple(declared)

    for entry in manifest["files"]:
        root_bytes = (CONTRACT_ROOT / entry["path"]).read_bytes()
        package_bytes = PACKAGE_ROOT.joinpath(entry["path"]).read_bytes()
        assert root_bytes == package_bytes
        assert len(root_bytes) == entry["bytes"]
        assert hashlib.sha256(root_bytes).hexdigest() == entry["sha256"]


def test_canonicalization_is_independent_of_object_and_collection_order() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["customExtensionDefinition"]))
    commands = cast(list[dict[str, object]], value["commands"])
    variants = cast(list[dict[str, object]], value["variants"])
    commands.reverse()
    variants.reverse()
    cast(list[str], variants[0]["platforms"]).reverse()
    reordered = {key: value[key] for key in reversed(tuple(value))}

    assert canonical_fleet_contract_bytes("customExtensionDefinition", reordered) == canonical_fleet_contract_bytes(
        "customExtensionDefinition", FIXTURES["customExtensionDefinition"]
    )


def test_capability_negotiation_excludes_semantically_incomplete_readers() -> None:
    supported, missing = negotiate_fleet_capabilities(sorted(REQUIRED_FLEET_CAPABILITIES))
    assert supported is True
    assert missing == ()

    supported, missing = negotiate_fleet_capabilities(
        sorted(REQUIRED_FLEET_CAPABILITIES - {"guard.managed-controls-composite-apply.v2"})
    )
    assert supported is False
    assert missing == ("guard.managed-controls-composite-apply.v2",)


@pytest.mark.parametrize("advertised", [["valid.capability", ["not-a-string"]], {"bad": True}, "bad"])
def test_malformed_capabilities_are_bounded(advertised: object) -> None:
    with pytest.raises(FleetContractError) as caught:
        negotiate_fleet_capabilities(advertised)
    assert caught.value.code == "fec_invalid_identifier"


def test_managed_restrictive_authority_cannot_enable_or_permit() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    entries[0]["availability"] = "enabled"

    with pytest.raises(FleetContractError, match="cannot weaken") as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_managed_weaken_forbidden"


def test_managed_restrictive_authority_cannot_target_custom_extensions() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    entries[0] = {
        "authorityMode": "managed-restrictive",
        "availability": "disabled",
        "contextualOutcome": "block",
        "entryId": "entry.custom.block",
        "source": "explicit",
        "target": {
            "definitionId": "ced_01j5example00000001",
            "kind": "custom-extension",
        },
    }

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_managed_weaken_forbidden"


def test_utf8_limits_are_bytes_not_python_characters() -> None:
    at_limit = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    at_limit["description"] = "é" * 512
    validate_fleet_contract("fleetExtensionConfiguration", at_limit)

    over_limit = deepcopy(at_limit)
    over_limit["description"] = "é" * 513
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", over_limit)
    assert caught.value.code == "fec_limit_exceeded"


def test_nested_unknown_fields_are_classified_without_echoing_values() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    target = cast(dict[str, object], entries[0]["target"])
    target["sourcePath"] = "/Users/private/secret-tool"

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_unknown_field"
    assert "secret-tool" not in str(caught.value)


def test_noncanonical_timestamp_has_its_stable_reason() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    value["createdAt"] = "2026-08-27T12:00:00+00:00"
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)
    assert caught.value.code == "fec_invalid_timestamp"


def test_repeated_fleet_target_distinguishes_duplicate_from_conflict() -> None:
    duplicate = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    duplicate_entries = cast(list[dict[str, object]], duplicate["entries"])
    repeated = deepcopy(duplicate_entries[0])
    repeated["entryId"] = "entry.git.force-push.copy"
    duplicate_entries.append(repeated)
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", duplicate)
    assert caught.value.code == "fec_duplicate_entry"

    conflict = deepcopy(duplicate)
    cast(list[dict[str, object]], conflict["entries"])[-1]["authorityMode"] = "workspace-shared"
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", conflict)
    assert caught.value.code == "fec_conflicting_entry"


def test_custom_configuration_is_bound_to_its_exact_definition() -> None:
    definition = cast(dict[str, object], FIXTURES["customExtensionDefinition"])
    configuration = cast(dict[str, object], FIXTURES["customExtensionConfiguration"])
    validate_custom_extension_binding(definition, configuration)

    mutations = (
        ("workspaceId", "22222222-2222-4222-8222-222222222222"),
        ("definitionId", "ced_01j5example00000002"),
    )
    for field, value in mutations:
        candidate = deepcopy(configuration)
        candidate[field] = value
        with pytest.raises(FleetContractError) as caught:
            validate_custom_extension_binding(definition, candidate)
        assert caught.value.code == "fec_identity_unbound"

    untrusted_definition = deepcopy(definition)
    cast(list[dict[str, object]], untrusted_definition["variants"])[0]["reviewState"] = "pending"
    with pytest.raises(FleetContractError) as caught:
        validate_custom_extension_binding(untrusted_definition, configuration)
    assert caught.value.code == "fec_identity_unbound"

    unrelated_command = deepcopy(configuration)
    cast(list[dict[str, object]], unrelated_command["commands"])[0]["commandId"] = "cec_othercmd"
    with pytest.raises(FleetContractError) as caught:
        validate_custom_extension_binding(definition, unrelated_command)
    assert caught.value.code == "fec_identity_unbound"


def test_production_bundle_parser_validates_then_fails_closed_without_apply() -> None:
    document = {
        "fleetExtensionConfiguration": FIXTURES["fleetExtensionConfiguration"],
        "customExtensionDefinition": FIXTURES["customExtensionDefinition"],
        "customExtensionConfiguration": FIXTURES["customExtensionConfiguration"],
        "spec": {"rules": []},
    }
    with pytest.raises(ManagedControlsBundleError, match="application is not implemented"):
        parse_extension_contract(document, CatalogProjection(1, ()))

    invalid = deepcopy(document)
    cast(dict[str, object], invalid["customExtensionConfiguration"])["workspaceId"] = (
        "22222222-2222-4222-8222-222222222222"
    )
    with pytest.raises(FleetContractError) as caught:
        parse_extension_contract(invalid, CatalogProjection(1, ()))
    assert caught.value.code == "fec_identity_unbound"


def test_production_bundle_parser_keeps_legacy_documents_unchanged() -> None:
    parsed = parse_extension_contract({"spec": {"rules": []}}, CatalogProjection(1, ()))
    assert parsed.controls == ()
    assert parsed.rule_targets == {}
    assert parsed.fleet_contracts == {}


def test_signed_policy_runtime_rejects_invalid_embedded_fleet_contracts() -> None:
    document: dict[str, object] = {
        "customExtensionDefinition": FIXTURES["customExtensionDefinition"],
        "customExtensionConfiguration": deepcopy(FIXTURES["customExtensionConfiguration"]),
        "spec": {"rules": []},
    }
    cast(dict[str, object], document["customExtensionConfiguration"])["workspaceId"] = (
        "22222222-2222-4222-8222-222222222222"
    )
    with pytest.raises(ManagedControlsPolicyError) as caught:
        parse_managed_controls_policy_fields(
            document,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            negotiated_capabilities=frozenset(),
        )
    assert caught.value.code == "fec_identity_unbound"


@pytest.mark.parametrize(
    "capabilities",
    [frozenset(), REQUIRED_FLEET_CAPABILITIES],
    ids=["missing-capabilities", "complete-capabilities-without-apply"],
)
def test_signed_policy_runtime_never_acks_unapplied_fleet_payload(
    capabilities: frozenset[str],
) -> None:
    document: dict[str, object] = {
        "fleetExtensionConfiguration": FIXTURES["fleetExtensionConfiguration"],
        "spec": {"rules": []},
    }
    with pytest.raises(ManagedControlsPolicyError) as caught:
        parse_managed_controls_policy_fields(
            document,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            negotiated_capabilities=capabilities,
        )
    assert caught.value.code == "fec_unsupported_capability"
