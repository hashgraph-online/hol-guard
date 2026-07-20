"""Typed least-privilege contracts for GitHub command capabilities."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from codex_plugin_scanner.guard.action_lattice import guard_action_severity

from ..models import GuardAction
from .command_permission_catalog import COMMAND_PERMISSION_SCHEMA_VERSION, CommandPermissionSpec, PermissionRiskTier

GitHubCommandCapability = Literal[
    "read_local",
    "read_remote",
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
]

_REMOTE_MUTATION_RISKS: Final = ("destructive_shell", "network_egress")
_LOCAL_WRITE_RISKS: Final = ("destructive_shell",)


@dataclass(frozen=True, slots=True)
class GitHubCapabilityContract:
    capability: GitHubCommandCapability
    permission_id: str
    action_floor: GuardAction
    workflow_authorizable: bool
    action_class: str | None
    rule_id: str | None
    title: str
    description: str
    risk_tier: PermissionRiskTier
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]


_CAPABILITY_ORDER: Final[tuple[GitHubCommandCapability, ...]] = (
    "read_local",
    "read_remote",
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
)
_CAPABILITY_RANK: Final = MappingProxyType({capability: rank for rank, capability in enumerate(_CAPABILITY_ORDER)})
_CAPABILITY_FLOOR: Final = MappingProxyType(
    {
        "read_local": "allow",
        "read_remote": "allow",
        "write_local": "review",
        "maintain_remote": "review",
        "content_remote": "review",
        "merge_remote": "require-reapproval",
        "admin_merge_remote": "require-reapproval",
        "publish_remote": "require-reapproval",
        "workflow_remote": "require-reapproval",
        "force_remote": "block",
        "delete_remote": "require-reapproval",
        "secret_remote": "block",
        "access_remote": "require-reapproval",
        "mutate_remote": "require-reapproval",
        "unknown": "require-reapproval",
    }
)


def _contract(
    capability: GitHubCommandCapability,
    permission_suffix: str,
    action_class: str | None,
    rule_suffix: str | None,
    title: str,
    *,
    local: bool = False,
) -> GitHubCapabilityContract:
    read_only = rule_suffix is None
    description = (
        f"Reads {title.lower()} without changing state."
        if read_only
        else (
            "Identifies GitHub CLI operations that change local repository configuration."
            if local
            else f"Identifies {title.lower()} operations that change or may change GitHub-hosted state."
        )
    )
    return GitHubCapabilityContract(
        capability=capability,
        permission_id=f"command.github.permission.{permission_suffix}",
        action_floor=_CAPABILITY_FLOOR[capability],
        workflow_authorizable=capability == "maintain_remote",
        action_class=action_class,
        rule_id=None if rule_suffix is None else f"command.github.{rule_suffix}",
        title=title,
        description=description,
        risk_tier="low" if read_only else "high",
        risk_classes=() if read_only else (_LOCAL_WRITE_RISKS if local else _REMOTE_MUTATION_RISKS),
        safer_alternatives=(
            "Keep the operation read-only."
            if read_only
            else "Inspect the exact repository, resource, and operation before confirming it.",
        ),
    )


_CONTRACTS: Final = MappingProxyType(
    {
        contract.capability: contract
        for contract in (
            _contract("read_local", "read-local", None, None, "local GitHub state"),
            _contract("read_remote", "read-remote", None, None, "remote GitHub state"),
            _contract(
                "write_local",
                "write-local",
                "GitHub local configuration write",
                "local-write",
                "GitHub local configuration write",
                local=True,
            ),
            _contract(
                "maintain_remote",
                "maintain-remote",
                "GitHub bounded maintenance command",
                "maintenance",
                "Bounded GitHub maintenance",
            ),
            _contract(
                "content_remote",
                "content-remote",
                "GitHub content mutation command",
                "content",
                "GitHub content mutation",
            ),
            _contract("merge_remote", "merge-remote", "GitHub merge command", "merge", "GitHub pull-request merge"),
            _contract(
                "admin_merge_remote",
                "merge-admin",
                "GitHub administrator pull-request merge command",
                "admin-merge",
                "GitHub administrator pull-request merge",
            ),
            _contract(
                "publish_remote",
                "publish-remote",
                "GitHub release publication command",
                "publish",
                "GitHub release publication",
            ),
            _contract(
                "workflow_remote",
                "workflow-remote",
                "GitHub workflow mutation command",
                "workflow",
                "GitHub workflow mutation",
            ),
            _contract(
                "force_remote", "force-remote", "GitHub force mutation command", "force", "Forced GitHub mutation"
            ),
            _contract("delete_remote", "delete-remote", "GitHub delete command", "delete", "GitHub deletion"),
            _contract(
                "secret_remote", "secret-remote", "GitHub secret mutation command", "secret", "GitHub secret mutation"
            ),
            _contract(
                "access_remote", "access-remote", "GitHub access mutation command", "access", "GitHub access mutation"
            ),
            _contract(
                "mutate_remote", "mutate-remote", "GitHub remote mutation command", "mutation", "GitHub remote mutation"
            ),
            _contract(
                "unknown",
                "unknown",
                "Unverified GitHub command capability",
                "unknown",
                "Unverified GitHub command capability",
            ),
        )
    }
)


@dataclass(frozen=True, slots=True)
class GitHubCommandAssessment:
    """A complete capability classification for one GitHub operation."""

    capability: GitHubCommandCapability
    reason_code: str
    detail: str
    capabilities: tuple[GitHubCommandCapability, ...] = ()

    def __post_init__(self) -> None:
        if self.capability not in _CAPABILITY_RANK:
            raise ValueError("unknown GitHub capability")
        effective = self.capabilities or (self.capability,)
        if any(item not in _CAPABILITY_RANK for item in effective):
            raise ValueError("unknown GitHub capability set")
        canonical = tuple(sorted(set(effective), key=_CAPABILITY_RANK.__getitem__))
        if effective != canonical:
            raise ValueError("GitHub capabilities must be unique and canonically ordered")
        if self.capability != strongest_github_capability(canonical):
            raise ValueError("primary GitHub capability must be the strongest classified capability")
        object.__setattr__(self, "capabilities", canonical)

    @property
    def action_floor(self) -> GuardAction:
        return max(
            (github_capability_contract(item).action_floor for item in self.capabilities),
            key=guard_action_severity,
        )

    @property
    def workflow_authorizable(self) -> bool:
        return bool(self.capabilities) and all(
            github_capability_contract(item).workflow_authorizable for item in self.capabilities
        )


def github_capability_contract(capability: GitHubCommandCapability) -> GitHubCapabilityContract:
    return _CONTRACTS[capability]


def github_capability_contracts() -> tuple[GitHubCapabilityContract, ...]:
    return tuple(_CONTRACTS[capability] for capability in _CAPABILITY_ORDER)


def strongest_github_capability(capabilities: tuple[GitHubCommandCapability, ...]) -> GitHubCommandCapability:
    if not capabilities:
        raise ValueError("at least one GitHub capability is required")
    return max(capabilities, key=_CAPABILITY_RANK.__getitem__)


def github_assessment(
    capabilities: GitHubCommandCapability | tuple[GitHubCommandCapability, ...],
    reason_code: str,
    detail: str,
) -> GitHubCommandAssessment:
    effective = (capabilities,) if isinstance(capabilities, str) else capabilities
    canonical = tuple(sorted(set(effective), key=_CAPABILITY_RANK.__getitem__))
    return GitHubCommandAssessment(
        capability=strongest_github_capability(canonical),
        capabilities=canonical,
        reason_code=reason_code,
        detail=detail,
    )


def combine_github_assessments(
    assessments: Iterable[GitHubCommandAssessment],
) -> GitHubCommandAssessment | None:
    classified = tuple(assessments)
    if not classified:
        return None
    if len(classified) == 1:
        return classified[0]
    capabilities: tuple[GitHubCommandCapability, ...] = tuple(
        capability for assessment in classified for capability in assessment.capabilities
    )
    return github_assessment(
        capabilities,
        "github.shell.combined-capabilities",
        "The shell composition contains multiple GitHub capabilities.",
    )


def github_permission_specs(implementation_version: str) -> tuple[CommandPermissionSpec, ...]:
    return tuple(
        CommandPermissionSpec(
            permission_id=contract.permission_id,
            schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
            extension_id="command.github",
            implementation_version=implementation_version,
            label=contract.title,
            description=contract.description,
            risk_tier=contract.risk_tier,
            baseline_floor=contract.action_floor,
            default_enabled=True,
            configurable=True,
            fixed_reason=None,
            typed_capabilities=(contract.capability,),
            action_classes=() if contract.action_class is None else (contract.action_class,),
            rule_ids=() if contract.rule_id is None else (contract.rule_id,),
            dependencies=(),
            conflicts=(),
            implied_permissions=(),
            introduced_version="2.2.0",
            deprecated=False,
            replacement_permission_id=None,
            safer_guidance=contract.safer_alternatives,
        )
        for contract in github_capability_contracts()
    )
