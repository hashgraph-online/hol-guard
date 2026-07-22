from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, cast

from ..models import GuardAction
from ..package_execution_context import PackageExecutionContext, package_execution_context_from_evidence
from .approval_context import (
    build_runtime_executable_identity,
    build_runtime_launch_identity,
    runtime_launch_identity_is_reusable,
)
from .command_model import CanonicalCommand
from .command_tokens import shell_tokens
from .effect_contract import ProofRequirement, UncertaintyKind, maximum_action_floor
from .launch_identity_environment import (
    LaunchEnvironmentPlan,
    environment_observation_material,
    inherited_launch_environment,
    launch_environment_scope_is_ambiguous,
    launch_search_path,
    plan_command_segment_environment,
    plan_launch_environment,
    unresolved_launch_observation,
)

LAUNCH_IDENTITY_BINDING_VERSION: Final = "1.0.0"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REFERENCE = re.compile(r"[a-z][a-z0-9_-]*(?:[.:/][a-z0-9][a-z0-9_-]*)+")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_MANDATORY_UNCERTAINTIES: Final = frozenset(
    {UncertaintyKind.UNKNOWN_EFFECT, UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY}
)
_PACKAGE_LAUNCHERS: Final = frozenset(
    {
        "bun",
        "bunx",
        "corepack",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "pnpm",
        "poetry",
        "uv",
        "uvx",
        "yarn",
    }
)
_PACKAGE_CONTEXT_COMPONENTS: Final = frozenset(
    {
        "repository_identity",
        "workspace_identity",
        "package_manager_executable",
        "manifests_and_lockfiles",
        "registry_and_proxy_configuration",
        "workspace_configuration",
        "lifecycle_hooks_overrides_and_patches",
        "environment_policy",
    }
)
_NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS: Final = _PACKAGE_CONTEXT_COMPONENTS | {"exact_workspace"}


class LaunchBindingDimension(str, Enum):
    COMMAND_STRUCTURE = "command-structure"
    EXECUTABLE_OBSERVATION = "executable-observation"
    LAUNCH_ENVIRONMENT_OBSERVATION = "launch-environment-observation"
    REDIRECTION_TARGET_OBSERVATION = "redirection-target-observation"
    WORKSPACE_LOCATION = "workspace-location"
    REPOSITORY_LOCATION = "repository-location"
    WORKING_DIRECTORY_LOCATION = "working-directory-location"
    POLICY_AND_RULE_VERSIONS = "policy-and-rule-versions"
    PACKAGE_CONTEXT_OBSERVATION = "package-context-observation"


_REQUIRED_DIMENSIONS: Final = frozenset(LaunchBindingDimension)


@dataclass(frozen=True, slots=True)
class RuleVersionBinding:
    rule_id: str
    version: str

    def __post_init__(self) -> None:
        if _REFERENCE.fullmatch(self.rule_id) is None or _VERSION.fullmatch(self.version) is None:
            raise ValueError("rule binding must use canonical identifiers")


@dataclass(frozen=True, slots=True)
class LaunchBindingDimensionDigest:
    dimension: LaunchBindingDimension
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.dimension), LaunchBindingDimension):
            raise ValueError("dimension must be a canonical launch binding dimension")
        if _SHA256.fullmatch(self.digest) is None:
            raise ValueError("dimension digest must be a lowercase SHA-256 value")


@dataclass(frozen=True, slots=True)
class LaunchIdentityBindingObservation:
    """Privacy-safe drift evidence that is never an authorization proof."""

    binding_digest: str
    dimensions: tuple[LaunchBindingDimensionDigest, ...]
    required_requirements: frozenset[ProofRequirement]
    unresolved_requirements: frozenset[ProofRequirement]
    uncertainties: tuple[UncertaintyKind, ...]
    schema_version: str = LAUNCH_IDENTITY_BINDING_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != LAUNCH_IDENTITY_BINDING_VERSION:
            raise ValueError("unsupported launch binding observation version")
        if _SHA256.fullmatch(self.binding_digest) is None:
            raise ValueError("binding digest must be a lowercase SHA-256 value")
        dimensions = cast(object, self.dimensions)
        requirements = cast(object, self.required_requirements)
        unresolved = cast(object, self.unresolved_requirements)
        uncertainties = cast(object, self.uncertainties)
        if not isinstance(dimensions, tuple):
            raise ValueError("dimensions must contain exact dimension digests")
        typed_dimensions = cast(tuple[object, ...], dimensions)
        if any(not isinstance(item, LaunchBindingDimensionDigest) for item in typed_dimensions):
            raise ValueError("dimensions must contain exact dimension digests")
        dimension_names = tuple(item.dimension for item in self.dimensions)
        if dimension_names != tuple(sorted(set(dimension_names), key=lambda item: item.value)):
            raise ValueError("dimensions must be unique and ordered")
        if frozenset(dimension_names) != _REQUIRED_DIMENSIONS:
            raise ValueError("all launch binding dimensions are required")
        if not isinstance(requirements, frozenset):
            raise ValueError("required requirements must contain exact proof requirements")
        if any(not isinstance(item, ProofRequirement) for item in requirements):
            raise ValueError("required requirements must contain exact proof requirements")
        if not isinstance(unresolved, frozenset):
            raise ValueError("unresolved requirements must contain exact proof requirements")
        if any(not isinstance(item, ProofRequirement) for item in unresolved):
            raise ValueError("unresolved requirements must contain exact proof requirements")
        if not self.required_requirements >= _CORE_REQUIREMENTS:
            raise ValueError("core launch proof requirements cannot be omitted")
        if self.required_requirements != self.unresolved_requirements:
            raise ValueError("observation-only bindings cannot satisfy proof requirements")
        if not isinstance(uncertainties, tuple):
            raise ValueError("uncertainties must contain exact uncertainty values")
        typed_uncertainties = cast(tuple[object, ...], uncertainties)
        if any(not isinstance(item, UncertaintyKind) for item in typed_uncertainties):
            raise ValueError("uncertainties must contain exact uncertainty values")
        if self.uncertainties != tuple(sorted(set(self.uncertainties), key=lambda item: item.value)):
            raise ValueError("uncertainties must be unique and ordered")
        if not set(self.uncertainties) >= _MANDATORY_UNCERTAINTIES:
            raise ValueError("observation-only bindings require launch and effect uncertainty")
        expected_binding_digest = _binding_digest(
            dimensions=self.dimensions,
            required_requirements=self.required_requirements,
            uncertainties=self.uncertainties,
        )
        if self.binding_digest != expected_binding_digest:
            raise ValueError("binding digest does not match launch binding material")

    @property
    def can_issue_positive_proof(self) -> bool:
        return False

    @property
    def action_floor(self) -> GuardAction:
        from .effect_contract import UNCERTAINTY_FLOOR

        return maximum_action_floor(UNCERTAINTY_FLOOR[item] for item in self.uncertainties)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "binding_digest": self.binding_digest,
            "dimensions": [{"dimension": item.dimension.value, "digest": item.digest} for item in self.dimensions],
            "required_requirements": sorted(item.value for item in self.required_requirements),
            "unresolved_requirements": sorted(item.value for item in self.unresolved_requirements),
            "uncertainties": [item.value for item in self.uncertainties],
            "can_issue_positive_proof": False,
            "action_floor": self.action_floor,
        }


_CORE_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.WORKSPACE_IDENTITY,
        ProofRequirement.REPOSITORY_IDENTITY,
        ProofRequirement.WORKING_DIRECTORY_IDENTITY,
        ProofRequirement.EXECUTABLE_IDENTITY,
        ProofRequirement.LAUNCH_CHAIN,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    }
)


def observe_launch_identity_binding(
    *,
    command: CanonicalCommand,
    workspace: Path,
    repository: Path,
    working_directory: Path,
    policy_version: str,
    rules: tuple[RuleVersionBinding, ...],
    launch_env: Mapping[str, str] | None = None,
    package_contexts: tuple[PackageExecutionContext, ...] = (),
) -> LaunchIdentityBindingObservation:
    if _VERSION.fullmatch(policy_version) is None or not rules:
        raise ValueError("policy and rule versions are required")
    if len({item.rule_id for item in rules}) != len(rules):
        raise ValueError("rule bindings must be unique")
    cwd = _resolved(working_directory)
    segment_wrapper_order = tuple(
        dict.fromkeys(
            wrapper
            for segment in command.segments
            if segment.execution_context.startswith("top:")
            for wrapper in segment.wrapper_chain
        )
    )
    normalization_wrapper_count = len(command.wrapper_chain) - len(segment_wrapper_order)
    normalization_wrappers = command.wrapper_chain[:normalization_wrapper_count]
    wrapper_chain_complete = (
        normalization_wrapper_count >= 0
        and command.wrapper_chain[normalization_wrapper_count:] == segment_wrapper_order
    )
    if not wrapper_chain_complete:
        normalization_wrappers = ()
    inherited_plan = inherited_launch_environment(launch_env)
    inherited_environment = inherited_plan.executable_environment
    raw_tokens, _raw_tokens_exact = shell_tokens(command.raw_text)
    raw_plan = (
        plan_launch_environment(raw_tokens, inherited_environment, inherited_complete=inherited_plan.complete)
        if command.raw_text != command.normalized_text
        else inherited_plan
    )
    first_top_level_index = next(
        (index for index, segment in enumerate(command.segments) if segment.execution_context.startswith("top:")),
        None,
    )
    script_scope_ambiguous = launch_environment_scope_is_ambiguous(normalization_wrappers, len(command.segments))
    planned_segments = tuple(
        plan_command_segment_environment(
            segment,
            command.embedded_commands,
            (
                raw_plan.executable_environment
                if command.raw_text != command.normalized_text and index == first_top_level_index
                else inherited_environment
            ),
        )
        for index, segment in enumerate(command.segments)
    )
    segment_plans = tuple(
        LaunchEnvironmentPlan(
            plan.executable_environment,
            plan.wrapper_environments,
            inherited_plan.complete and plan.complete and not script_scope_ambiguous,
        )
        for plan in planned_segments
    )
    runtime_identities = tuple(
        build_runtime_launch_identity(
            segment.executable,
            args=segment.arguments,
            structured_command=True,
            cwd=cwd,
            launch_env=plan.executable_environment,
        )
        for segment, plan in zip(command.segments, segment_plans, strict=True)
    )
    executable_material: list[dict[str, object]] = [
        {
            "segment_index": index,
            "identity_digest": _framed_digest("hol-guard.runtime-launch", identity),
            "reusable_observation": runtime_launch_identity_is_reusable(identity),
        }
        for index, identity in enumerate(runtime_identities)
    ]
    if not wrapper_chain_complete:
        executable_material.append(unresolved_launch_observation("unresolved-wrapper-chain"))
    if script_scope_ambiguous:
        executable_material.append(unresolved_launch_observation("unresolved-script-environment-scope"))
    raw_wrapper_environments = list(raw_plan.wrapper_environments)
    for index, wrapper in enumerate(normalization_wrappers):
        wrapper_environment = raw_plan.executable_environment
        for wrapper_environment_index, candidate in enumerate(raw_wrapper_environments):
            if candidate.name == wrapper:
                wrapper_environment = candidate.environment
                del raw_wrapper_environments[wrapper_environment_index]
                break
        wrapper_identity = build_runtime_executable_identity(
            wrapper,
            search_path=launch_search_path(wrapper_environment),
            cwd=cwd,
        )
        executable_material.append(
            {
                "segment_index": f"wrapper:{index}",
                "identity_digest": _wrapper_identity_digest(wrapper_identity),
                "reusable_observation": runtime_launch_identity_is_reusable(wrapper_identity),
            }
        )
    for segment_index, (segment, plan) in enumerate(zip(command.segments, segment_plans, strict=True)):
        for wrapper_index, wrapper in enumerate(segment.wrapper_chain):
            if wrapper_index >= len(plan.wrapper_environments):
                executable_material.append(unresolved_launch_observation(f"segment:{segment_index}:wrapper-unresolved"))
                continue
            wrapper_environment = plan.wrapper_environments[wrapper_index].environment
            wrapper_identity = build_runtime_executable_identity(
                wrapper,
                search_path=launch_search_path(wrapper_environment),
                cwd=cwd,
            )
            executable_material.append(
                {
                    "segment_index": f"segment:{segment_index}:wrapper:{wrapper_index}",
                    "identity_digest": _wrapper_identity_digest(wrapper_identity),
                    "reusable_observation": runtime_launch_identity_is_reusable(wrapper_identity),
                }
            )
    package_material = [_validated_package_observation(context) for context in package_contexts]
    environment_plans = [*segment_plans]
    for plan in (raw_plan, *segment_plans):
        environment_plans.extend(
            LaunchEnvironmentPlan(wrapper.environment, (), plan.complete) for wrapper in plan.wrapper_environments
        )
    if not environment_plans:
        environment_plans.append(raw_plan)
    dimensions = tuple(
        sorted(
            (
                _dimension(LaunchBindingDimension.COMMAND_STRUCTURE, command.security_identity),
                _dimension(LaunchBindingDimension.EXECUTABLE_OBSERVATION, executable_material),
                _dimension(
                    LaunchBindingDimension.LAUNCH_ENVIRONMENT_OBSERVATION,
                    environment_observation_material(tuple(environment_plans)),
                ),
                _dimension(
                    LaunchBindingDimension.REDIRECTION_TARGET_OBSERVATION,
                    _redirection_target_material(command, cwd=cwd),
                ),
                _dimension(LaunchBindingDimension.WORKSPACE_LOCATION, str(_resolved(workspace))),
                _dimension(LaunchBindingDimension.REPOSITORY_LOCATION, str(_resolved(repository))),
                _dimension(LaunchBindingDimension.WORKING_DIRECTORY_LOCATION, str(cwd)),
                _dimension(
                    LaunchBindingDimension.POLICY_AND_RULE_VERSIONS,
                    [policy_version, sorted((item.rule_id, item.version) for item in rules)],
                ),
                _dimension(LaunchBindingDimension.PACKAGE_CONTEXT_OBSERVATION, package_material),
            ),
            key=lambda item: item.dimension.value,
        )
    )
    required = set(_CORE_REQUIREMENTS)
    if package_contexts or _command_requires_package_context(command):
        required.update({ProofRequirement.DEPENDENCY_PROVENANCE, ProofRequirement.CONFIGURATION_IDENTITY})
    uncertainties = {UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY, UncertaintyKind.UNKNOWN_EFFECT}
    if command.confidence != "exact" or command.uncertainty_reason is not None:
        uncertainties.add(UncertaintyKind.PARTIAL_PARSE)
    typed_required = frozenset(required)
    typed_uncertainties = tuple(sorted(uncertainties, key=lambda item: item.value))
    return LaunchIdentityBindingObservation(
        binding_digest=_binding_digest(
            dimensions=dimensions,
            required_requirements=typed_required,
            uncertainties=typed_uncertainties,
        ),
        dimensions=dimensions,
        required_requirements=typed_required,
        unresolved_requirements=typed_required,
        uncertainties=typed_uncertainties,
    )


def changed_launch_binding_dimensions(
    previous: LaunchIdentityBindingObservation,
    current: LaunchIdentityBindingObservation,
) -> tuple[LaunchBindingDimension, ...]:
    previous_digests = {item.dimension: item.digest for item in previous.dimensions}
    current_digests = {item.dimension: item.digest for item in current.dimensions}
    return tuple(
        sorted(
            (
                dimension
                for dimension in previous_digests.keys() | current_digests.keys()
                if previous_digests.get(dimension) != current_digests.get(dimension)
            ),
            key=lambda item: item.value,
        )
    )


def _validated_package_observation(context: PackageExecutionContext) -> dict[str, object]:
    validated = package_execution_context_from_evidence(context.to_evidence())
    component_names = frozenset(item.name for item in context.components)
    expected_names = _PACKAGE_CONTEXT_COMPONENTS if context.portable else _NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS
    if validated != context or component_names != expected_names:
        return {"status": "invalid"}
    return {
        "status": "portable-observation" if context.portable else "non-portable-observation",
        "context_digest": context.digest,
        "component_digests": sorted((item.name, item.digest) for item in context.components),
    }


def _command_requires_package_context(command: CanonicalCommand) -> bool:
    for segment in command.segments:
        launch_tokens = (segment.executable, *segment.arguments)
        if any(
            token.replace("\\", "/").rsplit("/", 1)[-1].lower() in _PACKAGE_LAUNCHERS
            for token in launch_tokens
            if isinstance(token, str)
        ):
            return True
    return False


def _wrapper_identity_digest(identity: Mapping[str, object]) -> str:
    stable_material = {key: value for key, value in identity.items() if key != "reuse_nonce"}
    return _framed_digest("hol-guard.runtime-wrapper-executable", stable_material)


def _redirection_target_material(command: CanonicalCommand, *, cwd: Path) -> list[dict[str, object]]:
    material: list[dict[str, object]] = []
    for index, redirect in enumerate(command.redirects):
        target = redirect.target
        base = {"index": index, "operator": redirect.operator}
        operator = redirect.operator.lstrip("0123456789")
        if operator in {"<<", "<<-", "<<<"}:
            material.append({**base, "status": "inline-input-bound-by-command-structure"})
            continue
        if any(marker in target for marker in ("$", "`", "*", "?", "[", "]", "{", "}")):
            material.append({**base, "status": "dynamic", "reuse_nonce": secrets.token_hex(16)})
            continue
        lexical = Path(target).expanduser()
        if not lexical.is_absolute():
            lexical = cwd / lexical
        try:
            canonical = lexical.resolve(strict=False)
            observation: dict[str, object] = {
                **base,
                "canonical_path": str(canonical),
                "exists": lexical.exists(),
                "is_symlink": lexical.is_symlink(),
                "status": "observed",
            }
            if operator == "<":
                observation["input_identity"] = build_runtime_launch_identity(
                    str(lexical),
                    structured_command=True,
                    cwd=cwd,
                )["executable"]
            material.append(observation)
        except (OSError, RuntimeError, ValueError):
            material.append({**base, "status": "unresolved", "reuse_nonce": secrets.token_hex(16)})
    return material


def _binding_digest(
    *,
    dimensions: tuple[LaunchBindingDimensionDigest, ...],
    required_requirements: frozenset[ProofRequirement],
    uncertainties: tuple[UncertaintyKind, ...],
) -> str:
    material = {
        "schema_version": LAUNCH_IDENTITY_BINDING_VERSION,
        "dimensions": [(item.dimension.value, item.digest) for item in dimensions],
        "required_requirements": sorted(item.value for item in required_requirements),
        "uncertainties": sorted(item.value for item in uncertainties),
    }
    return _framed_digest("hol-guard.launch-binding-observation", material)


def _dimension(dimension: LaunchBindingDimension, material: object) -> LaunchBindingDimensionDigest:
    return LaunchBindingDimensionDigest(dimension, _framed_digest(f"hol-guard.{dimension.value}", material))


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _framed_digest(domain: str, value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    frame = domain.encode("ascii") + b"\x00" + len(payload).to_bytes(8, "big") + payload
    return hashlib.sha256(frame).hexdigest()
