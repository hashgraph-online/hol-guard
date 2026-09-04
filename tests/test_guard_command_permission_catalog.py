from __future__ import annotations

import json
from dataclasses import replace

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


def test_github_permission_catalog_is_exhaustive_and_admin_merge_is_distinct() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    github = registry.get("command.github")

    assert github is not None
    assert {permission.permission_id for permission in github.permissions} == _GITHUB_PERMISSION_IDS
    assert {
        capability for permission in github.permissions for capability in permission.typed_capabilities
    } == _GITHUB_CAPABILITIES

    admin = registry.permission_for_typed_capability("admin_merge_remote")
    ordinary = registry.permission_for_typed_capability("merge_remote")
    assert admin is not None
    assert ordinary is not None
    assert admin.permission_id == "command.github.permission.merge-admin"
    assert admin.rule_ids == ("command.github.admin-merge",)
    assert admin.action_classes == ("GitHub administrator pull-request merge command",)
    assert registry.permission_for_action_class("  github ADMINISTRATOR pull-request MERGE command  ") is admin
    assert registry.permission_for_rule_id("COMMAND.GITHUB.ADMIN-MERGE") is admin
    assert registry.permission_for_typed_capability(" ADMIN_MERGE_REMOTE ") is admin
    catalog = CommandPermissionCatalog(registry.permissions)
    assert catalog.get(" COMMAND.GITHUB.PERMISSION.MERGE-ADMIN ") is admin
    assert catalog.for_rule_id(" COMMAND.GITHUB.ADMIN-MERGE ") is admin
    assert catalog.for_action_class(" github administrator pull-request merge command ") is admin
    assert catalog.for_typed_capability(" ADMIN_MERGE_REMOTE ") is admin
    assert admin.baseline_floor == "require-reapproval"
    assert ordinary.permission_id == "command.github.permission.merge-remote"
    assert ordinary.rule_ids == ("command.github.merge",)
    assert ordinary.baseline_floor == "require-reapproval"


@pytest.mark.parametrize("lookup", ["rule", "capability"])
def test_permission_indexes_map_each_enforceable_identifier_exactly_once(lookup: str) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY

    for extension in registry.extensions:
        for permission in extension.permissions:
            values = {
                "rule": permission.rule_ids,
                "capability": permission.typed_capabilities,
            }[lookup]
            for value in values:
                resolved = {
                    "rule": registry.permission_for_rule_id,
                    "capability": registry.permission_for_typed_capability,
                }[lookup](value)
                assert resolved is permission


def test_shared_action_classes_keep_unique_rule_permissions() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    git = next(extension for extension in registry.extensions if extension.extension_id == "command.git")
    git_permission_ids = {permission.permission_id for permission in git.permissions}
    assert {
        "command.git.permission.force-clean",
        "command.git.permission.force-push",
        "command.git.permission.hard-reset",
        "command.git.permission.index-inspection",
        "command.git.permission.local-branch-delete",
        "command.git.permission.remote-branch-delete",
        "command.git.permission.unverified-fetch",
        "command.git.permission.switch",
        "command.git.permission.checkout",
        "command.git.permission.status",
        "command.git.permission.unsafe-read",
    } <= git_permission_ids
    assert all(permission.configurable for permission in git.permissions)
    fetch_id = "command.git.permission.unverified-fetch"
    index_id = "command.git.permission.index-inspection"
    destructive_ids = {
        "command.git.permission.force-clean",
        "command.git.permission.force-push",
        "command.git.permission.hard-reset",
        "command.git.permission.local-branch-delete",
        "command.git.permission.remote-branch-delete",
    }
    destructive = [permission for permission in git.permissions if permission.permission_id in destructive_ids]
    fetch = next(permission for permission in git.permissions if permission.permission_id == fetch_id)
    index = next(permission for permission in git.permissions if permission.permission_id == index_id)
    assert all(permission.action_classes == ("git destructive command",) for permission in destructive)
    assert fetch.action_classes == ("git origin refresh",)
    assert index.action_classes == ("git index inspection",)
    first = min(destructive, key=lambda permission: permission.permission_id)
    assert registry.permission_for_action_class("git destructive command") is first
    assert registry.permission_for_action_class("git origin refresh") is fetch
    assert registry.permission_for_action_class("git index inspection") is index
    for permission in git.permissions:
        assert registry.permission_for_rule_id(permission.rule_ids[0]) is permission

    self_protection = next(
        extension for extension in registry.extensions if extension.extension_id == "command.guard-self-protection"
    )
    assert all(not permission.configurable for permission in self_protection.permissions)


def test_permission_catalog_serialization_and_digest_are_deterministic() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    reversed_registry = CommandSafetyExtensionRegistry(tuple(reversed(registry.extensions)))

    assert reversed_registry.catalog_digest == registry.catalog_digest
    assert registry.catalog_digest == "1f80bf6955e7f9c780e62371dd8218c6e96c25a008cf66503d74146a47ccc60e"
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
