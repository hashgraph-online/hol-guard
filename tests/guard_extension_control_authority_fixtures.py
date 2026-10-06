from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    ExtensionControlEnrollmentProof,
    ExtensionControlMutation,
    ExtensionControlProof,
    issue_extension_control_enrollment_proof,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore

_PASSWORD = "correct horse battery staple"


class MemorySecretStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.available = True
        self.anchor_set_count = 0
        self.fail_anchor_set_number: int | None = None

    def set_secret(self, secret_id: str, value: str) -> None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        if secret_id.endswith(":anchor"):
            self.anchor_set_count += 1
            if self.fail_anchor_set_number == self.anchor_set_count:
                raise RuntimeError("injected anchor failure")
        self.values[secret_id] = value

    def get_secret(self, secret_id: str) -> str | None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        return self.values.get(secret_id)

    def delete_secret(self, secret_id: str) -> None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        self.values.pop(secret_id, None)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _store(
    tmp_path: Path,
    secrets: MemorySecretStore,
    *,
    enroll: bool = True,
) -> GuardStore:
    store = GuardStore(tmp_path, prime_policy_integrity=False)
    update_settings(
        tmp_path,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    store._extension_control_authority_secret_store = secrets
    if enroll:
        _enroll(store)
    return store


def _enrollment_proof(
    store: GuardStore,
    *,
    actor_id: str = "local-admin",
    nonce: str = "enrollment-nonce",
) -> ExtensionControlEnrollmentProof:
    enrollment = ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
    )
    return issue_extension_control_enrollment_proof(
        store.guard_home,
        enrollment,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce=f"session-{nonce}",
    )


def _enroll(
    store: GuardStore,
    *,
    actor_id: str = "local-admin",
    nonce: str = "enrollment-nonce",
) -> ExtensionControlAuthorityView:
    return store.enroll_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
        proof=_enrollment_proof(store, actor_id=actor_id, nonce=nonce),
    )


def _disabled_layer() -> ExtensionControlLayer:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                ControlState.DISABLED,
            ),
        ),
    )


def _upgraded_registry(*, remove_first_extension: bool = False) -> CommandSafetyExtensionRegistry:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    if remove_first_extension:
        return CommandSafetyExtensionRegistry(extensions[1:])
    return CommandSafetyExtensionRegistry(
        (replace(extensions[0], description=f"{extensions[0].description} Updated."), *extensions[1:])
    )


def _expanded_permission_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    extension = extensions[0]
    permission = extension.permissions[0]
    expanded_permission = replace(
        permission,
        typed_capabilities=(*permission.typed_capabilities, "test.expanded-capability"),
    )
    expanded_extension = replace(
        extension,
        permissions=(expanded_permission, *extension.permissions[1:]),
    )
    return CommandSafetyExtensionRegistry((expanded_extension, *extensions[1:])), permission.permission_id


def _rule_version_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    extension = extensions[0]
    rule = extension.rules[0]
    versioned_rule = replace(rule, rule_version="99.0.0")
    versioned_extension = replace(extension, rules=(versioned_rule, *extension.rules[1:]))
    return CommandSafetyExtensionRegistry((versioned_extension, *extensions[1:])), extension.permissions[
        0
    ].permission_id


def _matcher_contract_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    extension = next(item for item in extensions if item.extension_id == "command.container-runtime")
    rule_index = next(
        index for index, rule in enumerate(extension.rules) if rule.rule_id.endswith("compose-destructive-cleanup")
    )
    rule = extension.rules[rule_index]
    changed_rule = replace(rule, matcher_contract_digest="0" * 64)
    changed_extension = replace(
        extension,
        rules=(*extension.rules[:rule_index], changed_rule, *extension.rules[rule_index + 1 :]),
    )
    permission_id = next(
        permission.permission_id for permission in extension.permissions if permission.rule_ids == (rule.rule_id,)
    )
    return (
        CommandSafetyExtensionRegistry((changed_extension, *(item for item in extensions if item is not extension))),
        permission_id,
    )


def _proof(
    store: GuardStore,
    layers: tuple[ExtensionControlLayer, ...],
    *,
    revision: int,
    key: str,
    actor_id: str,
    nonce: str,
) -> ExtensionControlProof:
    return issue_extension_control_proof(
        store.guard_home,
        ExtensionControlMutation(
            previous_revision=revision,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=layers,
            actor_id=actor_id,
            idempotency_key=key,
            nonce=nonce,
        ),
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce=f"session-{key}-{nonce}",
    )


def _commit(
    store: GuardStore,
    *,
    revision: int = 0,
    key: str = "change-1",
    actor_id: str = "local-admin",
) -> None:
    store.commit_extension_control_layers(
        (_disabled_layer(),),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        expected_revision=revision,
        idempotency_key=key,
        nonce=f"nonce-{key}",
        proof=_proof(
            store,
            (_disabled_layer(),),
            revision=revision,
            key=key,
            actor_id=actor_id,
            nonce=f"nonce-{key}",
        ),
    )


def _commit_enabled_permission(store: GuardStore, permission_id: str, *, key: str) -> None:
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, permission_id),
                ControlState.ENABLED,
            ),
        ),
    )
    nonce = f"nonce-{key}"
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key=key,
        nonce=nonce,
        proof=_proof(
            store,
            (layer,),
            revision=0,
            key=key,
            actor_id="local-admin",
            nonce=nonce,
        ),
    )
