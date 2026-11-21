"""Strict HOL Guard Managed Controls policy-field parsing entry point.

The native runtime parses the signed Extension fields and projects shared
posture; Python sends the document, the negotiated capabilities and the
catalog facts the parser needs, and rebuilds the typed result. When the
runtime cannot answer, parsing fails closed with ``native_unavailable``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeGuard, cast

from .native_context import _resolve_digest_home, native_context_digest
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

HOL_EXTENSION_CONTROLS_FIELD: Final = "x-hol-extension-controls"
HOL_EXTENSION_TARGETS_FIELD: Final = "x-hol-extension-targets"
HOL_EXTENSION_CONTROLS_SCHEMA_VERSION: Final = "guard.extension-controls.v1"
HOL_EXTENSION_TARGETS_SCHEMA_VERSION: Final = "guard.policy-extension-targets.v1"

EXTENSION_CONTROL_LAYER_CAPABILITY: Final = "extension-control-layer.v1"
POLICY_EXTENSION_TARGETS_CAPABILITY: Final = "policy-extension-targets.v1"
MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY: Final = "managed-controls-atomic-apply.v1"
PACKAGE_FIREWALL_CAPABILITY: Final = "package-firewall.v1"

_ANSWER_KEYS = frozenset(
    {
        "authority_mode",
        "signed_cloud_layer",
        "managed_controls",
        "managed_global_lockdown",
        "rule_targets",
        "delegated_targets",
    }
)


class ManagedControlsPolicyError(ValueError):
    """Bounded parser failure with a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExtensionRuleTargets:
    rule_id: str
    extension_ids: tuple[str, ...]
    permission_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DelegatedExtensionTarget:
    target: ControlTarget
    enforcement_owner: str = "package-firewall"


@dataclass(frozen=True, slots=True)
class ParsedManagedControlsPolicy:
    authority_mode: str | None
    signed_cloud_layer: ExtensionControlLayer | None
    managed_controls: tuple[ExtensionControl, ...]
    managed_global_lockdown: bool
    rule_targets: tuple[ExtensionRuleTargets, ...]
    delegated_targets: tuple[DelegatedExtensionTarget, ...]
    cloud_projection_json: str | None = None
    cloud_projection_digest: str | None = None
    cloud_enforcement_digest: str | None = None

    @property
    def has_extension_semantics(self) -> bool:
        return bool(
            self.signed_cloud_layer
            or self.managed_controls
            or self.managed_global_lockdown
            or self.rule_targets
            or self.delegated_targets
        )


_UNBOUND: Final = object()
"""Marks a parse request that no policy delivery envelope accompanied."""


def is_mapping(value: object) -> TypeGuard[dict[str, object]]:
    """Return whether a value is a string-keyed object."""

    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in cast(dict[object, object], value))


def parse_managed_controls_policy_fields(
    document: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry | Callable[[], CommandSafetyExtensionRegistry],
    negotiated_capabilities: frozenset[str],
    package_firewall_supported: bool = False,
    guard_home: Path | None = None,
    cloud_view: dict[str, object] | Callable[[CommandSafetyExtensionRegistry], dict[str, object] | None] | None = None,
    delivery_catalog_digest: object = _UNBOUND,
) -> ParsedManagedControlsPolicy:
    """Parse signed policy Extension fields after envelope authenticity is established."""

    if not isinstance(negotiated_capabilities, (set, frozenset)) or not all(
        isinstance(item, str) for item in negotiated_capabilities
    ):
        raise ManagedControlsPolicyError("invalid_capabilities", "Managed Controls capabilities are malformed.")
    capabilities = set(negotiated_capabilities)
    if package_firewall_supported:
        capabilities.add(PACKAGE_FIREWALL_CAPABILITY)
    request = {
        "document": _projected_document(document),
        "capabilities": sorted(capabilities),
    }
    result = native_context_digest(
        "managed_controls_policy_fields",
        {"request": request},
        guard_home=_resolve_digest_home(guard_home),
    )
    if (
        isinstance(result, dict)
        and result.get("status") == "ok"
        and result.get("managed_controls_policy_fields") == {"catalog_required": True}
    ):
        registry = registry() if callable(registry) else registry
        cloud_view = cloud_view(registry) if callable(cloud_view) else cloud_view
        request["catalog"] = _catalog(registry)
    else:
        return _parse_answer(result, registry=None, cloud_view=None)
    if cloud_view is not None:
        request.update(
            {
                "cloud_view": cloud_view,
                "enforcement_catalog_digest": registry.catalog_digest,
                "projection": {"version": 2, "catalog_digest": registry.catalog_digest},
            }
        )
        if delivery_catalog_digest is not _UNBOUND:
            # A caller that observed a delivery envelope reports its catalog
            # digest here; the native parse refuses an identity it did not cut.
            request["delivery_catalog_digest"] = delivery_catalog_digest
    result = native_context_digest(
        "managed_controls_policy_fields",
        {"request": request},
        guard_home=_resolve_digest_home(guard_home),
    )
    return _parse_answer(result, registry=registry, cloud_view=cloud_view)


def _parse_answer(
    result: object,
    *,
    registry: CommandSafetyExtensionRegistry | None,
    cloud_view: dict[str, object] | None,
) -> ParsedManagedControlsPolicy:
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise _unavailable()
    answer = result.get("managed_controls_policy_fields")
    if not isinstance(answer, dict) or set(answer) not in ({"ok"}, {"error"}, {"ok", "projection"}):
        raise _unavailable()
    refusal = answer.get("error")
    if refusal is not None:
        if not isinstance(refusal, dict) or not isinstance(refusal.get("code"), str):
            raise _unavailable()
        raise ManagedControlsPolicyError(refusal["code"], str(refusal.get("message", "")))
    parsed = answer.get("ok")
    if not isinstance(parsed, dict) or set(parsed) != _ANSWER_KEYS:
        raise _unavailable()
    try:
        result = _parsed(parsed, registry)
        if cloud_view is not None and registry is not None:
            from dataclasses import replace

            proof = answer.get("projection")
            if (
                not isinstance(proof, dict)
                or not isinstance(proof.get("canonical_json"), str)
                or not isinstance(proof.get("digest"), str)
            ):
                raise _unavailable()
            result = replace(
                result,
                cloud_projection_json=proof["canonical_json"],
                cloud_projection_digest=proof["digest"],
                cloud_enforcement_digest=registry.catalog_digest,
            )
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise _unavailable() from error


def _projected_document(document: object) -> object:
    """Keep only what the native parser reads; malformed shapes pass through unchanged."""

    if not is_mapping(document):
        return document
    projected = {key: document[key] for key in (HOL_EXTENSION_CONTROLS_FIELD,) if key in document}
    if "spec" not in document:
        return projected
    spec = document["spec"]
    if not is_mapping(spec) or "rules" not in spec:
        projected["spec"] = {} if is_mapping(spec) else spec
        return projected
    rules = spec["rules"]
    if isinstance(rules, list):
        rules = [
            {key: rule[key] for key in ("id", HOL_EXTENSION_TARGETS_FIELD) if key in rule} if is_mapping(rule) else rule
            for rule in cast(list[object], rules)
        ]
    projected["spec"] = {"rules": rules}
    return projected


def _catalog(registry: CommandSafetyExtensionRegistry) -> dict[str, object]:
    """Catalog facts the parser reads, keyed the way the registry resolves them."""

    extensions: dict[str, object] = {}
    for extension in registry.extensions:
        if registry.get(extension.extension_id) is extension:
            extensions[extension.extension_id] = {
                "required": extension.required,
                "delegated": extension.delegated_protection is not None,
            }
    permissions: dict[str, object] = {}
    for permission in registry.permissions:
        if registry.permission(permission.permission_id) is not permission:
            continue
        owner = registry.get(permission.extension_id)
        permissions[permission.permission_id] = {
            "extension_id": permission.extension_id,
            "owner_delegated": None if owner is None else owner.delegated_protection is not None,
            "configurable": permission.configurable,
        }
    return {"extensions": extensions, "permissions": permissions}


def _target(value: dict[str, object]) -> ControlTarget:
    return ControlTarget(ControlTargetKind(value["target_kind"]), cast(str, value["target_id"]))


def _controls(values: object) -> tuple[ExtensionControl, ...]:
    return tuple(
        ExtensionControl(_target(value), ControlState(value["state"])) for value in cast(list[dict[str, Any]], values)
    )


def _parsed(answer: dict[str, object], registry: CommandSafetyExtensionRegistry | None) -> ParsedManagedControlsPolicy:
    layer_value = answer["signed_cloud_layer"]
    layer = None
    if layer_value is not None:
        if registry is None:
            raise ValueError("native policy layer requires the requested catalog")
        layer_value = cast(dict[str, object], layer_value)
        layer = ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.SIGNED_CLOUD,
            catalog_digest=registry.catalog_digest,
            global_lockdown=cast(bool, layer_value["global_lockdown"]),
            controls=_controls(layer_value["controls"]),
        )
    authority_mode = answer["authority_mode"]
    lockdown = answer["managed_global_lockdown"]
    if not (authority_mode is None or isinstance(authority_mode, str)) or not isinstance(lockdown, bool):
        raise ValueError("malformed managed controls answer")
    return ParsedManagedControlsPolicy(
        authority_mode=authority_mode,
        signed_cloud_layer=layer,
        managed_controls=_controls(answer["managed_controls"]),
        managed_global_lockdown=lockdown,
        rule_targets=tuple(
            ExtensionRuleTargets(
                rule_id=rule["rule_id"],
                extension_ids=tuple(rule["extension_ids"]),
                permission_ids=tuple(rule["permission_ids"]),
            )
            for rule in cast(list[dict[str, Any]], answer["rule_targets"])
        ),
        delegated_targets=tuple(
            DelegatedExtensionTarget(_target(value))
            for value in cast(list[dict[str, Any]], answer["delegated_targets"])
        ),
    )


def _unavailable() -> ManagedControlsPolicyError:
    return ManagedControlsPolicyError(
        "native_unavailable",
        "Managed Controls policy fields could not be checked right now.",
    )
