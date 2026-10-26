"""Test-only entry point for the resident's GitHub CLI capability classifier.

The Rust command model owns every GitHub CLI classification
(``rust/crates/guard-command/src/github_command_capabilities.rs``) and the
capability contract behind it
(``rust/crates/guard-command/src/github_capability_contract.rs``). Production
code calls the resident through ``codex_plugin_scanner.guard.native_github_cli``
and never needs a Python copy of either.

These helpers keep a small independent oracle of the capability contract (its
order, permission and rule owners, and action floors) so the capability suites
can check the resident's answers against something the Rust code did not
produce. When the resident cannot answer, the capability is ``unknown`` (the
review floor), never a Python re-derivation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.models import GuardAction

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.native_github_cli import NativeGitHubCliClassification

GitHubCommandCapability = Literal[
    "read_local",
    "read_remote",
    "propose_remote",
    "create_private_remote",
    "routine_merge_remote",
    "routine_review_thread_remote",
    "routine_workflow_remote",
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

# capability -> (permission suffix, rule suffix, action floor), weakest first.
_ORACLE: Final[MappingProxyType[GitHubCommandCapability, tuple[str, str | None, GuardAction]]] = MappingProxyType(
    {
        "read_local": ("read-local", None, "allow"),
        "read_remote": ("read-remote", None, "allow"),
        "propose_remote": ("propose-remote", None, "allow"),
        "create_private_remote": ("create-private-remote", None, "allow"),
        "routine_merge_remote": ("routine-merge-remote", "routine-merge", "allow"),
        "routine_review_thread_remote": ("routine-review-thread-remote", None, "allow"),
        "routine_workflow_remote": ("routine-workflow-remote", "workflow-mutation", "require-reapproval"),
        "write_local": ("write-local", "local-write", "review"),
        "maintain_remote": ("maintain-remote", "maintenance", "review"),
        "content_remote": ("content-remote", "content", "review"),
        "merge_remote": ("merge-remote", "merge", "require-reapproval"),
        "admin_merge_remote": ("merge-admin", "admin-merge", "require-reapproval"),
        "publish_remote": ("publish-remote", "publish", "require-reapproval"),
        "workflow_remote": ("workflow-remote", "workflow", "require-reapproval"),
        "force_remote": ("force-remote", "force", "block"),
        "delete_remote": ("delete-remote", "delete", "require-reapproval"),
        "secret_remote": ("secret-remote", "secret", "block"),
        "access_remote": ("access-remote", "access", "require-reapproval"),
        "mutate_remote": ("mutate-remote", "mutation", "require-reapproval"),
        "unknown": ("unknown", "unknown", "require-reapproval"),
    }
)
_RANK: Final = MappingProxyType({capability: rank for rank, capability in enumerate(_ORACLE)})


@dataclass(frozen=True, slots=True)
class CapabilityOwner:
    """The oracle's permission and rule owner for one capability."""

    permission_id: str
    rule_id: str | None
    action_floor: GuardAction
    workflow_authorizable: bool


def capability_owner(capability: GitHubCommandCapability) -> CapabilityOwner:
    permission, rule, floor = _ORACLE[capability]
    return CapabilityOwner(
        permission_id=f"command.github.permission.{permission}",
        rule_id=None if rule is None else f"command.github.{rule}",
        action_floor=floor,
        workflow_authorizable=capability == "maintain_remote",
    )


@dataclass(frozen=True, slots=True)
class OracleGitHubAssessment:
    """A capability set checked against the oracle's order and owners."""

    capability: GitHubCommandCapability
    reason_code: str
    detail: str
    capabilities: tuple[GitHubCommandCapability, ...] = ()

    def __post_init__(self) -> None:
        effective = self.capabilities or (self.capability,)
        if any(item not in _RANK for item in (self.capability, *effective)):
            raise ValueError("unknown GitHub capability")
        canonical = tuple(sorted(set(effective), key=_RANK.__getitem__))
        if effective != canonical:
            raise ValueError("GitHub capabilities must be unique and canonically ordered")
        if self.capability != canonical[-1]:
            raise ValueError("primary GitHub capability must be the strongest classified capability")
        object.__setattr__(self, "capabilities", canonical)

    @property
    def action_floor(self) -> GuardAction:
        return max((capability_owner(item).action_floor for item in self.capabilities), key=guard_action_severity)

    @property
    def workflow_authorizable(self) -> bool:
        return all(capability_owner(item).workflow_authorizable for item in self.capabilities)


def oracle_assessment(
    capabilities: GitHubCommandCapability | tuple[GitHubCommandCapability, ...],
    reason_code: str,
    detail: str,
) -> OracleGitHubAssessment:
    effective = (capabilities,) if isinstance(capabilities, str) else capabilities
    canonical = tuple(sorted(set(effective), key=_RANK.__getitem__))
    return OracleGitHubAssessment(canonical[-1], reason_code, detail, canonical)


_ASSESSMENT_CACHE_LIMIT = 512
_ASSESSMENT_CACHE: dict[tuple[str, ...], OracleGitHubAssessment] = {}


def reset_github_capability_cache() -> None:
    """Drop every memoized assessment so a test can re-observe the resident."""

    _ASSESSMENT_CACHE.clear()


def _classification(args: tuple[str, ...]) -> NativeGitHubCliClassification | None:
    """Return the resident's classification for ``args``, or ``None``."""

    # Resolve the classifier per call. The capability suites monkeypatch
    # `native_github_cli.github_cli_classify_native`, and the offline stub
    # replaces the whole module in `sys.modules`; an import-time binding would
    # see neither.
    from codex_plugin_scanner.guard.native_github_cli import github_cli_classify_native

    return github_cli_classify_native(args)


def github_cli_assessment(args: Sequence[str]) -> OracleGitHubAssessment:
    """Return the native assessment for GitHub CLI arguments (without ``gh``).

    Only an assessment the oracle accepted is memoized. An unavailable
    resident and a malformed classification both fail closed to ``unknown`` on
    every call, so a later good answer for the same arguments is still seen.
    """

    key = tuple(args)
    cached = _ASSESSMENT_CACHE.get(key)
    if cached is not None:
        return cached
    native = _classification(key)
    if native is None:
        return oracle_assessment(
            "unknown",
            "github.native.unavailable",
            "The native GitHub command classifier is unavailable, so the command is unverified.",
        )
    try:
        assessment = OracleGitHubAssessment(
            # __post_init__ rejects any value outside the oracle's capability set.
            capability=cast(GitHubCommandCapability, native.capability),
            reason_code=native.reason_code,
            detail=native.detail,
            capabilities=tuple(cast(GitHubCommandCapability, item) for item in native.capabilities),
        )
    except ValueError:
        return oracle_assessment(
            "unknown",
            "github.native.malformed",
            "The native GitHub command classifier returned an unrecognized capability.",
        )
    if len(_ASSESSMENT_CACHE) >= _ASSESSMENT_CACHE_LIMIT:
        _ASSESSMENT_CACHE.clear()
    _ASSESSMENT_CACHE[key] = assessment
    return assessment


__all__ = [
    "CapabilityOwner",
    "GitHubCommandCapability",
    "OracleGitHubAssessment",
    "capability_owner",
    "github_cli_assessment",
    "oracle_assessment",
    "reset_github_capability_cache",
]
