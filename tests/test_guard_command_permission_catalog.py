from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_permission_catalog import (
    COMMAND_PERMISSION_SCHEMA_VERSION,
    CommandPermissionCatalog,
    CommandPermissionSpec,
)
from codex_plugin_scanner.guard.runtime.github_capability_contract import GitHubCommandCapability

_GITHUB_PERMISSION_IDS = {
    "command.github.permission.read-local",
    "command.github.permission.read-remote",
    "command.github.permission.propose-remote",
    "command.github.permission.create-private-remote",
    "command.github.permission.routine-merge-remote",
    "command.github.permission.routine-workflow-remote",
    "command.github.permission.routine-review-thread-remote",
    "command.github.permission.write-local",
    "command.github.permission.maintain-remote",
    "command.github.permission.content-remote",
    "command.github.permission.merge-remote",
    "command.github.permission.merge-admin",
    "command.github.permission.publish-remote",
    "command.github.permission.workflow-remote",
    "command.github.permission.force-remote",
    "command.github.permission.delete-remote",
    "command.github.permission.secret-remote",
    "command.github.permission.access-remote",
    "command.github.permission.mutate-remote",
    "command.github.permission.unknown",
}
_GITHUB_CAPABILITIES: set[GitHubCommandCapability] = {
    "read_local",
    "read_remote",
    "propose_remote",
    "create_private_remote",
    "routine_merge_remote",
    "routine_workflow_remote",
    "routine_review_thread_remote",
    "write_local",
    "maintain_remote",
    "content_remote",
    "merge_remote",
    "admin_merge_remote",
    "publish_remote",
    "workflow_remote",
    "force_remote",
    "delete_remote",
    "secret_remote",
    "access_remote",
    "mutate_remote",
    "unknown",
}


def test_every_extension_has_complete_enabled_permission_metadata() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY

    assert registry.permissions
    assert all(extension.permissions for extension in registry.extensions)
    assert all(permission.schema_version == COMMAND_PERMISSION_SCHEMA_VERSION for permission in registry.permissions)
    assert all(permission.default_enabled is True for permission in registry.permissions)
    assert all(
        permission.extension_id in {extension.extension_id for extension in registry.extensions}
        for permission in registry.permissions
    )

    for extension in registry.extensions:
        extension_permission_ids = {permission.permission_id for permission in extension.permissions}
        assert len(extension_permission_ids) == len(extension.permissions)
        assert all(
            permission_id.startswith(f"{extension.extension_id}.permission.")
            for permission_id in extension_permission_ids
        )
        assert set(extension.action_classes) == {
            action_class for permission in extension.permissions for action_class in permission.action_classes
        }
        assert {rule.rule_id for rule in extension.rules} == {
            rule_id for permission in extension.permissions for rule_id in permission.rule_ids
        }


def test_permission_catalog_serialization_and_digest_are_deterministic() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    reversed_registry = CommandSafetyExtensionRegistry(tuple(reversed(registry.extensions)))

    assert reversed_registry.catalog_digest == registry.catalog_digest
    assert [permission.permission_id for permission in registry.permissions] == sorted(
        permission.permission_id for permission in registry.permissions
    )
    assert json.dumps(
        [extension.to_dict() for extension in registry.extensions],
        sort_keys=True,
        separators=(",", ":"),
    ) == json.dumps(
        [extension.to_dict() for extension in reversed_registry.extensions],
        sort_keys=True,
        separators=(",", ":"),
    )


def test_registry_digest_changes_when_generated_matcher_contract_changes() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    extension = next(item for item in registry.extensions if item.extension_id == "command.container-runtime")
    rule_index = next(index for index, item in enumerate(extension.rules) if item.matcher_kind == "native-matcher.v1")
    rule = extension.rules[rule_index]
    changed_rule = replace(
        rule,
        matcher_contract_digest=sha256(rule.matcher_contract_digest.encode("utf-8")).hexdigest(),
    )
    changed_extension = replace(
        extension,
        rules=(*extension.rules[:rule_index], changed_rule, *extension.rules[rule_index + 1 :]),
    )
    changed_registry = CommandSafetyExtensionRegistry(
        (changed_extension, *(item for item in registry.extensions if item is not extension))
    )

    assert changed_rule.to_dict()["matcher_contract_digest"] != rule.to_dict()["matcher_contract_digest"]
    assert changed_registry.catalog_digest != registry.catalog_digest

    family_extension = next(item for item in registry.extensions if any(rule.family is not None for rule in item.rules))
    family_rule_index = next(index for index, item in enumerate(family_extension.rules) if item.family is not None)
    family_rule = family_extension.rules[family_rule_index]
    assert family_rule.family is not None
    changed_family_rule = replace(family_rule, family=f"{family_rule.family}-identity")
    changed_family_extension = replace(
        family_extension,
        rules=(
            *family_extension.rules[:family_rule_index],
            changed_family_rule,
            *family_extension.rules[family_rule_index + 1 :],
        ),
    )
    changed_family_registry = CommandSafetyExtensionRegistry(
        (changed_family_extension, *(item for item in registry.extensions if item is not family_extension))
    )
    assert changed_family_registry.catalog_digest != registry.catalog_digest

    safe_variant_rules = [
        item for current_extension in registry.extensions for item in current_extension.rules if item.safe_variants
    ]
    assert safe_variant_rules
    assert all(
        isinstance(variant.to_dict()["matcher_contract_digest"], str)
        and len(variant.to_dict()["matcher_contract_digest"]) == 64
        for item in safe_variant_rules
        for variant in item.safe_variants
    )


def test_permission_catalog_rejects_duplicate_mappings_cycles_and_invalid_references() -> None:
    base = CommandPermissionSpec(
        permission_id="command.test.permission.base",
        schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
        extension_id="command.test",
        implementation_version="1.0.0",
        label="Base",
        description="Base test permission.",
        risk_tier="high",
        baseline_floor="review",
        default_enabled=True,
        configurable=True,
        fixed_reason=None,
        typed_capabilities=("test_base",),
        action_classes=("test base action",),
        rule_ids=("command.test.base",),
        dependencies=(),
        conflicts=(),
        implied_permissions=(),
        introduced_version="2.2.0",
        deprecated=False,
        replacement_permission_id=None,
        safer_guidance=("Inspect the operation.",),
        example_command="test inspect",
    )

    with pytest.raises(ValueError, match="duplicate permission ID"):
        CommandPermissionCatalog((base, base))
    with pytest.raises(ValueError, match="mapped by multiple permissions"):
        CommandPermissionCatalog((base, replace(base, permission_id="command.test.permission.other")))
    shared_action = CommandPermissionCatalog(
        (
            base,
            replace(
                base,
                permission_id="command.test.permission.normalized-collision",
                typed_capabilities=("test_normalized_collision",),
                action_classes=(" TEST BASE ACTION ",),
                rule_ids=("command.test.normalized-collision",),
            ),
        )
    )
    assert shared_action.for_action_class("test base action") is base
    assert shared_action.for_rule_id("command.test.normalized-collision") is not None
    with pytest.raises(ValueError, match=r"rule .* mapped by multiple permissions"):
        CommandPermissionCatalog(
            (
                base,
                replace(
                    base,
                    permission_id="command.test.permission.rule-collision",
                    typed_capabilities=("test_rule_collision",),
                    action_classes=("test rule collision action",),
                    rule_ids=(" COMMAND.TEST.BASE ",),
                ),
            )
        )
    with pytest.raises(ValueError, match=r"typed capability .* mapped by multiple permissions"):
        CommandPermissionCatalog(
            (
                base,
                replace(
                    base,
                    permission_id="command.test.permission.capability-collision",
                    typed_capabilities=(" TEST_BASE ",),
                    action_classes=("test capability collision action",),
                    rule_ids=("command.test.capability-collision",),
                ),
            )
        )
    with pytest.raises(ValueError, match="unknown dependency"):
        CommandPermissionCatalog((replace(base, dependencies=("command.test.permission.missing",)),))
    with pytest.raises(ValueError, match="relationship cycle"):
        other = replace(
            base,
            permission_id="command.test.permission.other",
            typed_capabilities=("test_other",),
            action_classes=("test other action",),
            rule_ids=("command.test.other",),
            dependencies=(base.permission_id,),
        )
        CommandPermissionCatalog((replace(base, dependencies=(other.permission_id,)), other))
    with pytest.raises(ValueError, match="duplicate dependency"):
        CommandPermissionCatalog((replace(base, dependencies=(base.permission_id, base.permission_id)),))
    with pytest.raises(ValueError, match="self-referential replacement"):
        CommandPermissionCatalog(
            (
                replace(
                    base,
                    deprecated=True,
                    replacement_permission_id=base.permission_id,
                ),
            )
        )
    cross_extension_target = replace(
        base,
        permission_id="command.other.permission.target",
        extension_id="command.other",
        typed_capabilities=("other_target",),
        action_classes=("other target action",),
        rule_ids=("command.other.target",),
    )
    with pytest.raises(ValueError, match="cross-extension replacement"):
        CommandPermissionCatalog(
            (
                replace(
                    base,
                    deprecated=True,
                    replacement_permission_id=cross_extension_target.permission_id,
                ),
                cross_extension_target,
            )
        )


def test_extension_serialization_contains_metadata_not_effective_control_state() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.github")
    assert extension is not None
    payload = extension.to_dict()

    assert payload["enabled"] is True
    assert payload["permissions"]
    assert all(permission["default_enabled"] is True for permission in payload["permissions"])
    assert "effective_enabled" not in payload
    assert "local_enabled" not in payload
