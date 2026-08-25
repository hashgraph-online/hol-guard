from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    validated_managed_controls_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    HOL_EXTENSION_TARGETS_FIELD,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    ManagedControlsPolicyError,
    parse_managed_controls_policy_fields,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    policy_bundle_verification_key_from_public_key,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
    validate_policy_bundle_v2_transition,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    MAX_CONTROL_SET_RULES,
)

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = json.loads((_ROOT / "contracts/managed-controls/v1/policy-extension-fields.fixtures.json").read_text())
_VECTOR = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json").read_text()
)
_TRANSITIONS = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-rotation-rollback-fixtures.json").read_text()
)
_CAPABILITIES = frozenset(
    {
        EXTENSION_CONTROL_LAYER_CAPABILITY,
        POLICY_EXTENSION_TARGETS_CAPABILITY,
        MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    }
)


def _document() -> dict[str, Any]:
    return copy.deepcopy(_FIXTURE["document"])


def _parse(
    document: dict[str, Any],
    *,
    capabilities: frozenset[str] = _CAPABILITIES,
    package: bool = False,
):
    return parse_managed_controls_policy_fields(
        document,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=capabilities,
        package_firewall_supported=package,
    )


def _code(document: dict[str, Any], **kwargs: Any) -> str:
    with pytest.raises(ManagedControlsPolicyError) as captured:
        _parse(document, **kwargs)
    return captured.value.code


def test_full_capability_negotiation_parses_managed_controls_and_rule_targets() -> None:
    parsed = _parse(_document())
    assert parsed.authority_mode == "managed-restrictive"
    assert parsed.signed_cloud_layer is not None
    assert parsed.signed_cloud_layer.kind is ControlLayerKind.SIGNED_CLOUD
    assert parsed.signed_cloud_layer.controls == parsed.managed_controls
    assert parsed.managed_controls[0].target.kind is ControlTargetKind.PERMISSION
    assert parsed.managed_controls[0].state is ControlState.DISABLED
    assert parsed.rule_targets[0].extension_ids == ("command.git",)
    assert parsed.rule_targets[0].permission_ids == ("command.git.permission.force-push",)

    for capability in _CAPABILITIES:
        assert (
            _code(_document(), capabilities=frozenset(_CAPABILITIES - {capability}))
            == "unnegotiated_extension_semantics"
        )


def test_legacy_aliases_parse_but_policy_without_fields_needs_no_capabilities() -> None:
    assert _parse(_document(), capabilities=frozenset(_FIXTURE["legacyCapabilityAliases"])).has_extension_semantics
    document = _document()
    document.pop("x-hol-extension-controls")
    document["spec"]["rules"][0].pop("x-hol-extension-targets")
    assert not _parse(document, capabilities=frozenset()).has_extension_semantics


def test_shared_posture_materializes_only_into_signed_cloud_layer() -> None:
    document = _document()
    document["x-hol-extension-controls"] = copy.deepcopy(_FIXTURE["sharedEnabled"])
    parsed = _parse(document)
    assert parsed.signed_cloud_layer is not None
    assert parsed.signed_cloud_layer.kind is ControlLayerKind.SIGNED_CLOUD
    assert parsed.signed_cloud_layer.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert parsed.signed_cloud_layer.controls[0].state is ControlState.ENABLED


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (
            ("x-hol-extension-controls", "schemaVersion"),
            "guard.extension-controls.v2",
            "unsupported_control_schema",
        ),
        (("x-hol-extension-controls", "authorityMode"), "root-admin", "invalid_authority"),
        (
            ("x-hol-extension-controls", "controls", 0, "targetKind"),
            "detector",
            "invalid_target_kind",
        ),
        (
            ("x-hol-extension-controls", "controls", 0, "targetId"),
            "git.force-push",
            "invalid_permission_id",
        ),
        (
            ("x-hol-extension-controls", "controls", 0, "state"),
            "prompt",
            "invalid_control_state",
        ),
        (
            ("x-hol-extension-controls", "controls", 0, "targetId"),
            "command.git.permission.unknown",
            "unknown_permission_target",
        ),
        (
            ("spec", "rules", 0, "x-hol-extension-targets", "authorityMode"),
            "managed-restrictive",
            "unknown_field",
        ),
    ],
)
def test_malformed_namespaced_fields_fail_closed(path: tuple[str | int, ...], value: object, expected: str) -> None:
    document = _document()
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    assert _code(document) == expected


def test_duplicates_conflicts_and_limits_fail_before_projection() -> None:
    document = _document()
    controls = document["x-hol-extension-controls"]["controls"]
    controls.append(copy.deepcopy(controls[0]))
    assert _code(document) == "duplicate_target"

    document = _document()
    controls = document["x-hol-extension-controls"]["controls"]
    conflict = copy.deepcopy(controls[0])
    conflict["state"] = "enabled"
    controls.append(conflict)
    assert _code(document) == "conflicting_target"

    document = _document()
    control = document["x-hol-extension-controls"]["controls"][0]
    document["x-hol-extension-controls"]["controls"] = [
        {**control, "targetId": f"command.git.permission.force-push-{index}"} for index in range(513)
    ]
    assert _code(document) == "control_limit_exceeded"

    document = _document()
    document["spec"]["rules"][0]["x-hol-extension-targets"]["extensionIds"] = [
        f"command.tool-{index}" for index in range(1025)
    ]
    assert _code(document) == "target_limit_exceeded"


def test_explicit_null_extension_fields_fail_closed() -> None:
    document = _document()
    document[HOL_EXTENSION_CONTROLS_FIELD] = None
    assert _code(document) == "invalid_extension_controls"

    document = _document()
    document["spec"]["rules"][0][HOL_EXTENSION_TARGETS_FIELD] = None
    assert _code(document) == "invalid_extension_targets"


def test_targeted_rule_count_limit_is_enforced() -> None:
    document = _document()
    seed = document["spec"]["rules"][0]
    document["spec"]["rules"] = [
        {
            **copy.deepcopy(seed),
            "id": f"managed-rule-{index}",
            HOL_EXTENSION_TARGETS_FIELD: {
                "schemaVersion": "guard.policy-extension-targets.v1",
                "extensionIds": [],
                "permissionIds": [],
            },
        }
        for index in range(MAX_CONTROL_SET_RULES + 1)
    ]
    assert _code(document) == "rule_limit_exceeded"


def test_permission_only_target_validates_its_catalog_owner() -> None:
    document = _document()
    targets = document["spec"]["rules"][0][HOL_EXTENSION_TARGETS_FIELD]
    targets["extensionIds"] = []
    parsed = _parse(document)
    assert parsed.rule_targets[0].extension_ids == ()
    assert parsed.rule_targets[0].permission_ids == ("command.git.permission.force-push",)


def test_managed_restrictive_is_disable_or_lockdown_only() -> None:
    document = _document()
    document["x-hol-extension-controls"]["controls"][0]["state"] = "enabled"
    assert _code(document) == "managed_restrictive_broadening"

    document = _document()
    document["x-hol-extension-controls"] = copy.deepcopy(_FIXTURE["globalLockdown"])
    assert _parse(document).managed_global_lockdown


def test_delegated_targets_require_package_firewall_and_do_not_double_materialize() -> None:
    delegated = next(
        (
            extension
            for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
            if extension.delegated_protection == "package-firewall"
        ),
        None,
    )
    assert delegated is not None, "built-in registry must include Package Firewall delegation"
    permission = delegated.permissions[0]
    document = _document()
    document["spec"]["rules"][0].pop("x-hol-extension-targets")
    document["x-hol-extension-controls"] = {
        "schemaVersion": "guard.extension-controls.v1",
        "authorityMode": "workspace-shared",
        "controls": [
            {
                "targetKind": "permission",
                "targetId": permission.permission_id,
                "state": "disabled",
            }
        ],
    }
    assert _code(document) == "unsupported_delegated_protection"
    parsed = _parse(document, package=True)
    assert parsed.signed_cloud_layer is not None
    assert parsed.signed_cloud_layer.controls == ()
    assert parsed.delegated_targets[0].target.target_id == permission.permission_id


def test_shared_enable_respects_configurability_and_required_floors() -> None:
    document = _document()
    document["spec"]["rules"][0].pop("x-hol-extension-targets")
    document["x-hol-extension-controls"] = {
        "schemaVersion": "guard.extension-controls.v1",
        "authorityMode": "workspace-shared",
        "controls": [{"targetKind": "extension", "targetId": "command.git", "state": "enabled"}],
    }
    assert _code(document) == "shared_enable_requires_permission"
    immutable = next(
        permission for permission in BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions if not permission.configurable
    )
    document["x-hol-extension-controls"]["controls"] = [
        {
            "targetKind": "permission",
            "targetId": immutable.permission_id,
            "state": "enabled",
        }
    ]
    assert _code(document) == "immutable_floor"


def test_every_builtin_immutable_floor_rejects_shared_cloud_weakening() -> None:
    immutable_permissions = tuple(
        permission
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.delegated_protection is None
        for permission in extension.permissions
        if not permission.configurable
    )
    required_extensions = tuple(
        extension for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if extension.required
    )
    assert immutable_permissions
    assert required_extensions

    for permission in immutable_permissions:
        document = _document()
        document["spec"]["rules"][0].pop("x-hol-extension-targets")
        document["x-hol-extension-controls"] = {
            "schemaVersion": "guard.extension-controls.v1",
            "authorityMode": "workspace-shared",
            "controls": [
                {
                    "targetKind": "permission",
                    "targetId": permission.permission_id,
                    "state": "enabled",
                }
            ],
        }
        assert _code(document) == "immutable_floor"

    for extension in required_extensions:
        document = _document()
        document["spec"]["rules"][0].pop("x-hol-extension-targets")
        document["x-hol-extension-controls"] = {
            "schemaVersion": "guard.extension-controls.v1",
            "authorityMode": "workspace-shared",
            "controls": [
                {
                    "targetKind": "extension",
                    "targetId": extension.extension_id,
                    "state": "disabled",
                }
            ],
        }
        assert _code(document) == "immutable_floor"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "controls",
        {"schemaVersion": "guard.extension-controls.v1"},
        {"schemaVersion": 1, "authorityMode": "workspace-shared", "controls": []},
        {
            "schemaVersion": "guard.extension-controls.v1",
            "authorityMode": "workspace-shared",
            "controls": "not-an-array",
        },
    ],
)
def test_malformed_field_fuzz_matrix_is_bounded(bad: object) -> None:
    document = _document()
    document["x-hol-extension-controls"] = bad
    assert _code(document) in {
        "invalid_extension_controls",
        "invalid_shape",
        "unsupported_control_schema",
        "invalid_authority",
    }


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("x-hol-extension-controls\x00", {}, "unknown_field"),
        ("x-hol-extension-controls.regex", "(a+)+$", "unknown_field"),
        ("x-hol-extension-controls-unicode-\N{ZERO WIDTH JOINER}", [], "unknown_field"),
    ),
)
def test_namespaced_control_field_fuzz_rejects_near_matches(
    field: str,
    value: object,
    expected: str,
) -> None:
    document = _document()
    document["x-hol-extension-controls"][field] = value
    assert _code(document) == expected


def test_oversized_target_and_advanced_regex_are_not_evaluated_by_extension_parser() -> None:
    document = _document()
    document["x-hol-extension-controls"]["controls"][0]["targetId"] = "command." + ("a" * 100_000)
    assert _code(document) == "invalid_permission_id"

    matcher_accesses: list[str] = []

    class ObservableRule(dict[str, Any]):
        def __getitem__(self, key: str) -> Any:
            if key == "matcher":
                matcher_accesses.append(key)
                raise AssertionError("managed-controls parser accessed the advanced matcher")
            return super().__getitem__(key)

        def get(self, key: str, default: Any = None) -> Any:
            if key == "matcher":
                matcher_accesses.append(key)
                raise AssertionError("managed-controls parser accessed the advanced matcher")
            return super().get(key, default)

    document = _document()
    original_rule = document["spec"]["rules"][0]
    original_rule["matcher"] = {"regex": "(a+)+$"}
    document["spec"]["rules"][0] = ObservableRule(original_rule)
    parsed = _parse(document)
    assert matcher_accesses == []
    assert parsed.rule_targets[0].permission_ids == ("command.git.permission.force-push",)


def test_shared_signature_vector_validates_before_projection() -> None:
    bundle = copy.deepcopy(_VECTOR["bundle"])
    public_key = policy_bundle_verification_key_from_public_key(
        key_id=bundle["verifier"]["keyId"],
        public_key_pem=bundle["verifier"]["publicKeyPem"],
        purpose=POLICY_BUNDLE_KEY_PURPOSE,
        workspace_id=bundle["workspaceId"],
    )
    validated, parsed, reason = validated_managed_controls_policy_bundle_v2_payload(
        bundle,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
        trusted_verification_keys=(public_key,),
        anchored_verification_keys=(public_key,),
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    assert reason is None and validated is not None and parsed is not None
    assert parsed.has_extension_semantics
    assert computed_policy_bundle_v2_hash(bundle) == _VECTOR["expectedBundleHash"]
    assert payload_hash_for_policy_bundle_v2(bundle) == _VECTOR["expectedPayloadHash"]


def test_rotation_rollback_and_downgrade_fixtures_are_monotonic() -> None:
    for case in _TRANSITIONS["transitionCases"]:
        assert (
            validate_policy_bundle_v2_transition(
                {
                    "bundleVersion": case["candidateVersion"],
                    "bundleHash": case["candidateHash"],
                },
                current_bundle_version=case["currentVersion"],
                current_bundle_hash=case["currentHash"],
            )
            == case["expected"]
        )

    rollback = copy.deepcopy(_TRANSITIONS["authorizedRollback"])
    assert (
        validate_policy_bundle_v2_transition(
            rollback,
            current_bundle_version=8,
            current_bundle_hash=rollback["rollback"]["rollbackOfBundleHash"],
            expected_last_good_bundle_version=7,
            expected_last_good_bundle_hash=rollback["rollback"]["lastGoodBundleHash"],
        )
        is None
    )
