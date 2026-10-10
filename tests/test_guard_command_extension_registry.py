"""Generated registry metadata and isolated native-evidence reducer tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog

_FLOORS = {"disabled": "allow", "monitor": "warn", "review": "review", "enforce": "block", "required": "review"}


def _extension(
    extension_id: str,
    rule_id: str,
    *,
    severity: str = "high",
    default_mode: str = "review",
    required: bool = False,
    source: str = "built-in",
    aliases: tuple[str, ...] = (),
    dependencies: tuple[str, ...] = (),
):
    template = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.api-gateway")
    assert template is not None
    rule = replace(
        template.rules[0], rule_id=rule_id, severity=severity, default_mode=default_mode, risk_classes=("test_risk",)
    )
    permission = replace(
        template.permissions[0],
        permission_id=f"{extension_id}.permission.test",
        extension_id=extension_id,
        rule_ids=(rule_id,),
        baseline_floor=_FLOORS[default_mode],
        risk_tier=severity,
    )
    return replace(
        template,
        extension_id=extension_id,
        action_classes=(extension_id,),
        rules=(rule,),
        permissions=(permission,),
        required=required,
        source=source,
        aliases=aliases,
        dependencies=dependencies,
        risk_classes=("test_risk",),
    )


def _catalog(*extensions) -> GeneratedCommandCatalog:
    return GeneratedCommandCatalog(
        extensions,
        program_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest,
        source_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.source_digest,
        implementation_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.implementation_digest,
    )


def test_generated_catalog_rejects_duplicate_normalized_action_owners() -> None:
    first = _extension("command.first", "command.first.rule")
    second = replace(
        _extension("command.second", "command.second.rule"),
        action_classes=(" COMMAND.FIRST ",),
    )

    with pytest.raises(ValueError, match=r"Duplicate command action class: command\.first"):
        _catalog(first, second)


def test_command_extension_registry_relationships_and_aliases_are_indexed() -> None:
    base = _extension("command.base", "command.base.rule", aliases=("command.legacy-base",))
    dependent = _extension("command.dependent", "command.dependent.rule", dependencies=("command.base",))
    registry = _catalog(dependent, base)
    assert registry.get("command.legacy-base") is base
    assert [item.extension_id for item in registry.extensions] == ["command.base", "command.dependent"]
    assert registry.get("command.dependent").dependencies == ("command.base",)


def test_command_extension_registry_indexes_are_immutable() -> None:
    base = _extension("command.base", "command.base.rule")
    registry = _catalog(base)
    with pytest.raises(TypeError):
        vars(registry)["_by_id"]["command.injected"] = base
    with pytest.raises(TypeError):
        vars(registry)["_by_rule_id"]["command.injected.rule"] = base.rules[0]


def test_command_extension_registry_retains_dependency_and_trust_metadata() -> None:
    first = _extension("command.first", "command.first.rule", dependencies=("command.second",))
    second = _extension("command.second", "command.second.rule", dependencies=("command.first",))
    external = _extension(
        "command.external-required", "command.external-required.rule", required=True, source="signed-cloud"
    )
    registry = _catalog(first, second, external)
    assert registry.get("command.first").dependencies == ("command.second",)
    assert registry.get("command.second").dependencies == ("command.first",)
    assert registry.get("command.external-required").source == "signed-cloud"
    assert registry.get("command.external-required").required is True


def test_command_extension_registry_rule_indexes_do_not_change_order() -> None:
    alpha = _extension("command.alpha", "command.alpha.rule")
    zeta = _extension("command.zeta", "command.zeta.rule")
    registry = _catalog(zeta, alpha)
    assert [item.extension_id for item in registry.extensions] == ["command.alpha", "command.zeta"]
    assert registry.get_rule("command.zeta.rule") is zeta.rules[0]
    assert registry.get_rule("command.alpha.rule") is alpha.rules[0]
