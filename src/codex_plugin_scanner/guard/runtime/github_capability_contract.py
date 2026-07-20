"""Typed least-privilege contracts for GitHub command capabilities."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from codex_plugin_scanner.guard.action_lattice import guard_action_severity

from ..models import GuardAction

GitHubCommandCapability = Literal[
    "read_local",
    "read_remote",
    "write_local",
    "maintain_remote",
    "content_remote",
    "merge_remote",
    "publish_remote",
    "workflow_remote",
    "force_remote",
    "delete_remote",
    "secret_remote",
    "access_remote",
    "mutate_remote",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class GitHubCapabilityContract:
    action_floor: GuardAction
    workflow_authorizable: bool


_CAPABILITY_ORDER: Final[tuple[GitHubCommandCapability, ...]] = (
    "read_local",
    "read_remote",
    "write_local",
    "maintain_remote",
    "content_remote",
    "merge_remote",
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
_CONTRACTS: Final = MappingProxyType(
    {
        "read_local": GitHubCapabilityContract("allow", False),
        "read_remote": GitHubCapabilityContract("allow", False),
        "write_local": GitHubCapabilityContract("review", False),
        "maintain_remote": GitHubCapabilityContract("review", True),
        "content_remote": GitHubCapabilityContract("review", False),
        "merge_remote": GitHubCapabilityContract("require-reapproval", False),
        "publish_remote": GitHubCapabilityContract("require-reapproval", False),
        "workflow_remote": GitHubCapabilityContract("require-reapproval", False),
        "force_remote": GitHubCapabilityContract("block", False),
        "delete_remote": GitHubCapabilityContract("require-reapproval", False),
        "secret_remote": GitHubCapabilityContract("block", False),
        "access_remote": GitHubCapabilityContract("require-reapproval", False),
        "mutate_remote": GitHubCapabilityContract("require-reapproval", False),
        "unknown": GitHubCapabilityContract("require-reapproval", False),
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
            key=_action_rank,
        )

    @property
    def workflow_authorizable(self) -> bool:
        return bool(self.capabilities) and all(
            github_capability_contract(item).workflow_authorizable for item in self.capabilities
        )


def github_capability_contract(capability: GitHubCommandCapability) -> GitHubCapabilityContract:
    return _CONTRACTS[capability]


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
    """Combine shell-composed GitHub operations without losing weaker effects."""

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


def _action_rank(action: GuardAction) -> int:
    return guard_action_severity(action)
