"""Frozen control manifest compilation, outside authority leases."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping
from types import MappingProxyType

from .runtime.command_extensions import CommandSafetyExtensionRegistry

_CACHE_LOCK = threading.Lock()
# One slot for the built-in registry and one for the last authenticated pack
# registry, so a pack registry and the built-in one never evict each other.
_manifest_cache: dict[bool, tuple[object, object, str, Mapping[str, str]]] = {}


def catalog_target_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
    """Cache the built-in registry and the last other one by identity.

    Registries hold their extensions as a frozen tuple, so the same registry,
    tuple and catalog digest compile to the same manifest. The other slot keeps
    the pack registry the publisher re-reads every poll. Callers receive a
    copy, so local mutation cannot poison later authenticated catalog
    comparisons. Replacing a registry, its extension tuple or its catalog
    identity invalidates its slot.
    """

    from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    built_in = registry is BUILT_IN_COMMAND_EXTENSION_REGISTRY
    with _CACHE_LOCK:
        current = _manifest_cache.get(built_in)
        if (
            current is not None
            and current[0] is registry
            and current[1] is registry.extensions
            and current[2] == registry.catalog_digest
        ):
            return dict(current[3])
        manifest = _build_catalog_target_manifest(registry)
        _manifest_cache[built_in] = (registry, registry.extensions, registry.catalog_digest, MappingProxyType(manifest))
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
                "matcher_kind": rule.matcher_kind,
                "matcher_contract_digest": rule.matcher_contract_digest,
                "safe_variants": tuple(
                    (item.variant_id, item.matcher_kind, item.matcher_contract_digest) for item in rule.safe_variants
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
