from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.policy_extension_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    PolicyExtensionFieldError,
    parse_policy_extension_fields,
    required_policy_extension_capabilities,
    validate_and_project_policy_extension_fields,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)

_GIT_EXTENSION = "command.git"
_GIT_PERMISSION = "command.git.permission.force-push"
_REQUIRED_CAPABILITIES = frozenset(
    {
        EXTENSION_CONTROL_LAYER_CAPABILITY,
        POLICY_EXTENSION_TARGETS_CAPABILITY,
        MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    }
)


def _document() -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {
            "id": "managed-controls-test",
            "name": "Managed Controls test",
            "revision": 1,
        },
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "block"},
            "rolloutState": "enforcing",
            "rules": [
                {
                    "id": "rule-git-force-push",
                    "description": "Review force pushes",
                    "enabled": True,
                    "effect": "review",
                    "match": {"tools": ["git"]},
                    "lifetime": {"mode": "workspace", "expiresAt": None},
                    "provenance": {
                        "source": "builder",
                        "createdAt": "2026-08-21T12:00:00.000Z",
                    },
                }
            ],
        },
    }


def _extension_document(*, authority_mode: str = "managed-restrictive", state: str = "disabled") -> dict[str, object]:
    document = _document()
    document["x-hol-extension-controls"] = {
        "schemaVersion": "guard.extension-controls.v1",
        "authorityMode": authority_mode,
        "controls": [
            {
                "targetKind": "permission",
                "targetId": _GIT_PERMISSION,
                "state": state,
            }
        ],
    }
    spec = document["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["x-hol-extension-targets"] = {
        "schemaVersion": "guard.policy-extension-targets.v1",
        "extensionIds": [_GIT_EXTENSION],
        "permissionIds": [_GIT_PERMISSION],
    }
    return document


def test_approved_extension_envelopes_parse_and_project_to_signed_cloud_layer() -> None:
    projection = validate_and_project_policy_extension_fields(
        _extension_document(),
        negotiated_capabilities=_REQUIRED_CAPABILITIES,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    assert required_policy_extension_capabilities(projection.parsed) == tuple(sorted(_REQUIRED_CAPABILITIES))
    assert projection.parsed.targets_for_rule("rule-git-force-push") is not None
    layer = projection.signed_cloud_layer
    assert layer is not None
    assert layer.kind is ControlLayerKind.SIGNED_CLOUD
    assert layer.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert layer.controls[0].target.kind is ControlTargetKind.PERMISSION
    assert layer.controls[0].target.target_id == _GIT_PERMISSION
    assert layer.controls[0].state is ControlState.DISABLED


def test_documents_without_extension_semantics_remain_compatible() -> None:
    parsed = parse_policy_extension_fields(_document())
    assert parsed.has_semantics is False
    assert required_policy_extension_capabilities(parsed) == ()


def test_unnegotiated_runtime_rejects_extension_semantics() -> None:
    with pytest.raises(PolicyExtensionFieldError) as caught:
        validate_and_project_policy_extension_fields(
            _extension_document(),
            negotiated_capabilities=frozenset(),
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        )
    assert caught.value.code == "unnegotiated_extension_semantics"


def test_legacy_prefixed_capability_aliases_remain_accepted_during_transition() -> None:
    projection = validate_and_project_policy_extension_fields(
        _extension_document(),
        negotiated_capabilities=frozenset(
            {
                "guard.managed-extension-controls.v1",
                "guard.policy-extension-targets.v1",
                "guard.managed-controls-atomic-apply.v1",
            }
        ),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )
    assert projection.signed_cloud_layer is not None


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda document: document.__setitem__(
                "x-hol-extension-controls",
                [
                    {
                        "authorityMode": "managed-restrictive",
                        "operation": "disable_permission",
                        "extensionId": _GIT_EXTENSION,
                        "permissionId": _GIT_PERMISSION,
                    }
                ],
            ),
            "invalid_shape",
        ),
        (
            lambda document: cast_controls(document)["controls"][0].__setitem__(
                "targetId", "git.push.force"
            ),
            "invalid_permission_id",
        ),
        (
            lambda document: cast_controls(document).__setitem__(
                "schemaVersion", "guard.extension-controls.v2"
            ),
            "unsupported_control_schema",
        ),
        (
            lambda document: cast_controls(document)["controls"][0].__setitem__(
                "state", "enabled"
            ),
            "managed_restrictive_broadening",
        ),
        (
            lambda document: cast_controls(document).__setitem__("unexpected", True),
            "unknown_field",
        ),
    ],
)
def test_malformed_or_broadening_control_envelopes_fail_closed(mutate: object, expected_code: str) -> None:
    document = _extension_document()
    callable_mutate = mutate
    assert callable(callable_mutate)
    callable_mutate(document)
    with pytest.raises(PolicyExtensionFieldError) as caught:
        parse_policy_extension_fields(document)
    assert caught.value.code == expected_code


def cast_controls(document: dict[str, object]) -> dict[str, object]:
    controls = document["x-hol-extension-controls"]
    assert isinstance(controls, dict)
    raw_controls = controls.get("controls")
    assert isinstance(raw_controls, list)
    assert isinstance(raw_controls[0], dict)
    return controls


def test_global_lockdown_requires_managed_restrictive_authority() -> None:
    document = _extension_document(authority_mode="workspace-shared")
    cast_controls(document)["globalLockdown"] = True
    with pytest.raises(PolicyExtensionFieldError) as caught:
        parse_policy_extension_fields(document)
    assert caught.value.code == "invalid_authority"


def test_unknown_and_alias_targets_are_rejected_against_local_registry() -> None:
    unknown = _extension_document()
    cast_controls(unknown)["controls"][0]["targetId"] = "command.git.permission.not-real"
    with pytest.raises(PolicyExtensionFieldError) as caught:
        validate_and_project_policy_extension_fields(
            unknown,
            negotiated_capabilities=_REQUIRED_CAPABILITIES,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        )
    assert caught.value.code == "unknown_permission_target"

    duplicate = deepcopy(_extension_document())
    controls = cast_controls(duplicate)["controls"]
    assert isinstance(controls, list)
    controls.append(deepcopy(controls[0]))
    with pytest.raises(PolicyExtensionFieldError) as caught_duplicate:
        parse_policy_extension_fields(duplicate)
    assert caught_duplicate.value.code == "duplicate_target"
