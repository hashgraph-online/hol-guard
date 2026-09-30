"""Generated registry metadata and isolated native-evidence reducer tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import CommandDecisionFloor, evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
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


def _evaluate(registry: GeneratedCommandCatalog, *, uncertainty: bool = False):
    command = parse_shell_command("synthetic-tool '" if uncertainty else "synthetic-tool target")
    observations = []
    for extension in registry.extensions:
        rule = extension.rules[0]
        observations.append(
            {
                "extension_id": extension.extension_id,
                "extension_version": extension.version,
                "rule_id": rule.rule_id,
                "rule_version": rule.rule_version,
                "match_class": "uncertainty" if uncertainty else "unsafe",
                "match_classes": ["unsafe", "uncertainty"] if uncertainty else ["unsafe"],
                "matcher_evidence": [
                    {
                        "segment_index": 0,
                        "executable": "synthetic-tool",
                        "detail": "Matched bounded structured command constraints.",
                    }
                ],
                "safe_variants": [],
                "uncertainty_reasons": ["matcher-failure"] if uncertainty else [],
                "effective_segment_indexes": [0],
            }
        )
    native = {
        "schema": "guard.native-command-observations.v1",
        "binding": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": registry.program_digest,
            "catalog_digest": registry.catalog_digest,
            "trust_digest": "c" * 64,
            "control_revision": 1,
            "managed_control_revision": 0,
            "control_effective_digest": "d" * 64,
            "observations_digest": "0" * 64,
            "observation_count": len(observations),
            "uncertainty_count": len(observations) if uncertainty else 0,
        },
        "observations": observations,
        "permission_observations": [],
        "evaluation_error": None,
    }
    canonical = json.dumps(
        {key: native[key] for key in ("observations", "permission_observations", "evaluation_error")},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    native["binding"]["observations_digest"] = hashlib.sha256(
        b"hol-guard.native-command-observations.v1\0" + canonical
    ).hexdigest()
    snapshot = ExtensionControlRuntimeSnapshot(AuthorityHealth.PROTECTED, 1, registry.catalog_digest, "d" * 64, (), 0)
    return evaluate_command(
        command.normalized_text,
        canonical_command=command,
        registry=registry,
        extension_control_snapshot=snapshot,
        native_extension_evidence={
            "command_model": {"normalized_text": command.normalized_text},
            "command_extensions": native,
        },
    )


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


def test_composite_evaluation_selects_strongest_rule_and_monotonic_floor() -> None:
    review = _extension("command.review", "command.review.rule", severity="low", default_mode="review")
    enforce = _extension("command.enforce", "command.enforce.rule", severity="high", default_mode="enforce")
    evaluation = _evaluate(_catalog(review, enforce))
    assert [owned.match.rule.rule_id for owned in evaluation.matches] == ["command.enforce.rule", "command.review.rule"]
    assert evaluation.controlling_rule_id == "command.enforce.rule"
    assert evaluation.minimum_action == "block"


@pytest.mark.parametrize(
    ("required", "severity", "default_mode", "expected_floor"),
    [
        (False, "low", "disabled", "review"),
        (False, "low", "monitor", "review"),
        (False, "medium", "review", "review"),
        (False, "high", "enforce", "block"),
        (False, "critical", "required", "review"),
        (True, "high", "disabled", "review"),
        (True, "critical", "disabled", "block"),
    ],
)
def test_command_decision_floor_truth_table(
    required: bool, severity: str, default_mode: str, expected_floor: CommandDecisionFloor
) -> None:
    extension = _extension(
        "command.floor", "command.floor.rule", severity=severity, default_mode=default_mode, required=required
    )
    assert _evaluate(_catalog(extension)).minimum_action == expected_floor


def test_parser_uncertainty_cannot_reduce_sensitive_evidence_below_review() -> None:
    extension = _extension("command.uncertain", "command.uncertain.rule", default_mode="disabled")
    evaluation = _evaluate(_catalog(extension), uncertainty=True)
    assert evaluation.command.confidence == "fallback"
    assert evaluation.minimum_action == "block"
