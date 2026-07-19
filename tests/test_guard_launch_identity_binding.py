from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.package_execution_context import (
    PackageExecutionContext,
    PackageExecutionContextComponent,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRequirement, UncertaintyKind
from codex_plugin_scanner.guard.runtime.launch_identity_binding import (
    LaunchBindingDimension,
    RuleVersionBinding,
    changed_launch_binding_dimensions,
    observe_launch_identity_binding,
)

_DIGEST = "a" * 64
_ECHO = shutil.which("echo") or "/bin/echo"
_RULES = (RuleVersionBinding("rule:command.test", "1.0.0"),)
_PACKAGE_COMPONENT_NAMES = (
    "repository_identity",
    "workspace_identity",
    "package_manager_executable",
    "manifests_and_lockfiles",
    "registry_and_proxy_configuration",
    "workspace_configuration",
    "lifecycle_hooks_overrides_and_patches",
    "environment_policy",
)


def _observe(
    tmp_path: Path,
    command_text: str,
    *,
    working_directory: Path | None = None,
    policy_version: str = "policy-v1",
    rules: tuple[RuleVersionBinding, ...] = _RULES,
    launch_env: dict[str, str] | None = None,
    package_contexts: tuple[PackageExecutionContext, ...] = (),
):
    cwd = working_directory or tmp_path
    command = parse_shell_command(command_text, cwd=cwd, home_dir=tmp_path)
    return observe_launch_identity_binding(
        command=command,
        workspace=tmp_path,
        repository=tmp_path,
        working_directory=cwd,
        policy_version=policy_version,
        rules=rules,
        launch_env=launch_env,
        package_contexts=package_contexts,
    )


def _package_context(*, component_digest: str = _DIGEST, portable: bool = True) -> PackageExecutionContext:
    components = tuple(PackageExecutionContextComponent(name, component_digest) for name in _PACKAGE_COMPONENT_NAMES)
    digest = hashlib.sha256(
        json.dumps(
            {
                "components": [{"name": item.name, "digest": item.digest} for item in components],
                "portable": portable,
                "version": 2,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return PackageExecutionContext(
        digest=digest,
        portable=portable,
        components=components,
        non_portable_reason=None if portable else "unproven",
    )


def test_observation_exposes_no_positive_proof_and_retains_reapproval_floor(tmp_path: Path) -> None:
    observation = _observe(tmp_path, f"{_ECHO} baseline")
    assert not observation.can_issue_positive_proof
    assert observation.required_requirements == observation.unresolved_requirements
    assert observation.action_floor == "require-reapproval"
    assert observation.uncertainties == (
        UncertaintyKind.UNKNOWN_EFFECT,
        UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY,
    )
    assert not hasattr(observation, "to_positive_proof")
    payload = observation.to_dict()
    assert payload["can_issue_positive_proof"] is False
    assert payload["action_floor"] == "require-reapproval"


def test_direct_construction_cannot_omit_mandatory_uncertainty_or_requirements(tmp_path: Path) -> None:
    observation = _observe(tmp_path, f"{_ECHO} baseline")
    with pytest.raises(ValueError, match="launch and effect uncertainty"):
        _ = replace(observation, uncertainties=(UncertaintyKind.PARTIAL_PARSE,))
    with pytest.raises(ValueError, match="core launch proof requirements"):
        _ = replace(
            observation,
            required_requirements=frozenset(),
            unresolved_requirements=frozenset(),
        )


def test_direct_construction_requires_immutable_unresolved_requirements(tmp_path: Path) -> None:
    observation = _observe(tmp_path, f"{_ECHO} baseline")
    mutable_unresolved = set(observation.unresolved_requirements)
    with pytest.raises(ValueError, match="unresolved requirements"):
        _ = replace(
            observation,
            unresolved_requirements=cast(frozenset[ProofRequirement], cast(object, mutable_unresolved)),
        )
    mutable_unresolved.clear()
    assert observation.unresolved_requirements == observation.required_requirements


def test_direct_construction_requires_every_dimension_exactly_once(tmp_path: Path) -> None:
    observation = _observe(tmp_path, f"{_ECHO} baseline")
    with pytest.raises(ValueError, match="all launch binding dimensions"):
        _ = replace(observation, dimensions=observation.dimensions[:-1])
    with pytest.raises(ValueError, match="unique and ordered"):
        _ = replace(observation, dimensions=observation.dimensions + observation.dimensions[:1])


@pytest.mark.parametrize(
    "changed_command",
    [
        f"env {_ECHO} baseline",
        f"{_ECHO} baseline > result.txt",
        f"{_ECHO} baseline | cat",
        f"{_ECHO} baseline <<'EOF'\ntext\nEOF",
        f"{_ECHO} $(echo nested)",
        f"{_ECHO} baseline && rm -rf ./build",
    ],
)
def test_wrapper_dataflow_and_sibling_changes_rekey_structure(
    tmp_path: Path,
    changed_command: str,
) -> None:
    baseline = _observe(tmp_path, f"{_ECHO} baseline")
    changed = _observe(tmp_path, changed_command)
    assert LaunchBindingDimension.COMMAND_STRUCTURE in changed_launch_binding_dimensions(baseline, changed)
    assert not changed.can_issue_positive_proof


def test_path_symlink_and_executable_drift_rekeys_observation(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    launcher = tmp_path / "tool"
    first.symlink_to(_ECHO)
    second.symlink_to(shutil.which("true") or "/bin/true")
    launcher.symlink_to(first)
    command = f"{launcher} baseline"
    baseline = _observe(tmp_path, command)
    launcher.unlink()
    launcher.symlink_to(second)
    changed = _observe(tmp_path, command)
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, changed)
    assert not changed.can_issue_positive_proof


def test_inline_path_and_working_directory_drift_are_bound_but_unproven(tmp_path: Path) -> None:
    first_bin = tmp_path / "first-bin"
    second_bin = tmp_path / "second-bin"
    first_bin.mkdir()
    second_bin.mkdir()
    (first_bin / "tool").symlink_to(_ECHO)
    (second_bin / "tool").symlink_to(shutil.which("true") or "/bin/true")
    baseline = _observe(tmp_path, "tool baseline", launch_env={"PATH": str(first_bin)})
    path_changed = _observe(tmp_path, "tool baseline", launch_env={"PATH": str(second_bin)})
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, path_changed)
    other = tmp_path / "other"
    other.mkdir()
    cwd_changed = _observe(tmp_path, "tool baseline", working_directory=other, launch_env={"PATH": str(first_bin)})
    changes = changed_launch_binding_dimensions(baseline, cwd_changed)
    assert LaunchBindingDimension.WORKING_DIRECTORY_LOCATION in changes
    assert not cwd_changed.can_issue_positive_proof


def test_partial_parse_adds_typed_uncertainty_without_issuing_proof(tmp_path: Path) -> None:
    observation = _observe(tmp_path, f"{_ECHO} 'unterminated")
    assert UncertaintyKind.PARTIAL_PARSE in observation.uncertainties
    assert not observation.can_issue_positive_proof


def test_policy_rule_and_package_context_drift_rekey_observation(tmp_path: Path) -> None:
    command = f"{_ECHO} baseline"
    baseline = _observe(tmp_path, command, package_contexts=(_package_context(),))
    policy_changed = _observe(tmp_path, command, policy_version="policy-v2", package_contexts=(_package_context(),))
    rule_changed = _observe(
        tmp_path,
        command,
        rules=(RuleVersionBinding("rule:command.test", "1.0.1"),),
        package_contexts=(_package_context(),),
    )
    package_changed = _observe(
        tmp_path,
        command,
        package_contexts=(_package_context(component_digest="b" * 64),),
    )
    assert LaunchBindingDimension.POLICY_AND_RULE_VERSIONS in changed_launch_binding_dimensions(
        baseline, policy_changed
    )
    assert LaunchBindingDimension.POLICY_AND_RULE_VERSIONS in changed_launch_binding_dimensions(baseline, rule_changed)
    assert LaunchBindingDimension.PACKAGE_CONTEXT_OBSERVATION in changed_launch_binding_dimensions(
        baseline, package_changed
    )
    assert ProofRequirement.DEPENDENCY_PROVENANCE in baseline.unresolved_requirements
    assert ProofRequirement.CONFIGURATION_IDENTITY in baseline.unresolved_requirements
    assert not baseline.can_issue_positive_proof


def test_fabricated_package_context_is_marked_invalid_and_never_proves_provenance(tmp_path: Path) -> None:
    invalid = PackageExecutionContext(
        digest="b" * 64,
        portable=True,
        components=tuple(PackageExecutionContextComponent(name, _DIGEST) for name in _PACKAGE_COMPONENT_NAMES),
    )
    observation = _observe(tmp_path, f"{_ECHO} baseline", package_contexts=(invalid,))
    assert not observation.can_issue_positive_proof
    assert ProofRequirement.DEPENDENCY_PROVENANCE in observation.unresolved_requirements
    assert "invalid" not in repr(observation)


def test_serialized_observation_contains_no_commands_paths_or_package_values(tmp_path: Path) -> None:
    command = f"{_ECHO} private-value > private-output"
    observation = _observe(tmp_path, command, package_contexts=(_package_context(),))
    payload = repr(observation.to_dict())
    assert str(tmp_path) not in payload
    assert command not in payload
    assert "private-value" not in payload
    assert "private-output" not in payload
