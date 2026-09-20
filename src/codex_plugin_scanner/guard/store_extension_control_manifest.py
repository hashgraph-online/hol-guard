"""Frozen built-in control manifest compilation, outside authority leases."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping
from types import MappingProxyType

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.command_matcher_contracts import MatcherContractError, canonical_contract_value
from .runtime.extension_control_authority import ExtensionControlAuthorityError

_CACHE_LOCK = threading.Lock()
_manifest_cache: tuple[object, object, str, Mapping[str, str]] | None = None


def _canonical_contract_value(value: object) -> object:
    try:
        return canonical_contract_value(value)
    except MatcherContractError as error:
        raise ExtensionControlAuthorityError(str(error)) from error


def catalog_target_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
    """Cache only the exact trusted built-in registry and its retained frozen tuple.

    Custom registries are compiled each time. Callers receive a copy, so local
    mutation cannot poison later authenticated catalog comparisons. Replacing
    the built-in registry/extension tuple/catalog identity invalidates the cache.
    """

    from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    if registry is not BUILT_IN_COMMAND_EXTENSION_REGISTRY:
        return _build_catalog_target_manifest(registry)
    global _manifest_cache
    with _CACHE_LOCK:
        current = _manifest_cache
        if (
            current is not None
            and current[0] is registry
            and current[1] is registry.extensions
            and current[2] == registry.catalog_digest
        ):
            return dict(current[3])
        manifest = _build_catalog_target_manifest(registry)
        _manifest_cache = (registry, registry.extensions, registry.catalog_digest, MappingProxyType(manifest))
        return dict(manifest)


def _build_catalog_target_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for extension in registry.extensions:
        rule_contracts = {
            rule.rule_id: {
                "rule_version": rule.rule_version,
                "severity": rule.severity,
                "risk_classes": rule.risk_classes,
                "action_classes": rule.action_classes,
                "default_mode": rule.default_mode,
                "matcher": _canonical_contract_value(rule.matcher),
                "safe_variants": tuple(
                    (item.variant_id, _canonical_contract_value(item.matcher)) for item in rule.safe_variants
                ),
                "compatibility_fallback": rule.compatibility_fallback,
                "family": rule.family,
            }
            for rule in extension.rules
        }
        extension_contract = {
            "extension_id": extension.extension_id,
            "required": extension.required,
            "source": extension.source,
            "aliases": extension.aliases,
            "dependencies": extension.dependencies,
            "conflicts": extension.conflicts,
            "delegated_protection": extension.delegated_protection,
            "ecosystem_ids": extension.ecosystem_ids,
            "executables": extension.executables,
            "project_markers": extension.project_markers,
            "action_classes": extension.action_classes,
            "risk_classes": extension.risk_classes,
            "rules": rule_contracts,
        }
        extension_fingerprint = hashlib.sha256(
            json.dumps(extension_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        manifest[f"extension:{extension.extension_id}"] = extension_fingerprint
        for permission in extension.permissions:
            permission_contract = {
                "permission_id": permission.permission_id,
                "extension_id": permission.extension_id,
                "risk_tier": permission.risk_tier,
                "baseline_floor": permission.baseline_floor,
                "default_enabled": permission.default_enabled,
                "configurable": permission.configurable,
                "fixed_reason": permission.fixed_reason,
                "typed_capabilities": permission.typed_capabilities,
                "action_classes": permission.action_classes,
                "rule_ids": permission.rule_ids,
                "dependencies": permission.dependencies,
                "conflicts": permission.conflicts,
                "implied_permissions": permission.implied_permissions,
                "family": permission.family,
                "extension_required": extension.required,
                "extension_dependencies": extension.dependencies,
                "extension_conflicts": extension.conflicts,
                "extension_delegated_protection": extension.delegated_protection,
                "rules": {rule_id: rule_contracts[rule_id] for rule_id in permission.rule_ids},
            }
            manifest[f"permission:{permission.permission_id}"] = hashlib.sha256(
                json.dumps(permission_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
    return manifest
