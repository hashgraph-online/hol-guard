"""Authenticate exact command policies and retain authority across hook refresh."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..exact_command import exact_command_sha256, exact_shell_command_from_hook

if TYPE_CHECKING:
    from ..store import GuardStore

_IDENTITY_FIELDS = (
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "exact_command_sha256",
    "action",
    "reason",
    "owner",
    "source",
    "expires_at",
    "updated_at",
)


def hook_exact_command_digest(payload: Mapping[str, object]) -> str | None:
    """Use the same original shell bytes as explicit source disclosure."""
    return exact_command_sha256(exact_shell_command_from_hook(payload))


@dataclass(frozen=True, slots=True, repr=False)
class HookExactCommandSource:
    """Trusted pre-normalization capture; invalid input remains an explicit absence."""

    sha256: str | None
    command: str | None = None


def capture_hook_exact_command_source(payload: Mapping[str, object]) -> HookExactCommandSource:
    command = exact_shell_command_from_hook(payload)
    return HookExactCommandSource(exact_command_sha256(command), command)


def _identity(decision: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(decision.get(field) for field in _IDENTITY_FIELDS)


def authenticated_exact_policy_allow(
    store: GuardStore,
    decision: Mapping[str, object] | None,
    command_digest: str | None,
) -> bool:
    """A selected row's source label never proves reusable policy authority.

    The caller's lookup already applies every request selector. This additional
    check distinguishes a currently signed exact policy from saved approval
    context, whose separate content/capability/launch checks remain mandatory.
    """
    if (
        decision is None
        or command_digest is None
        or decision.get("action") != "allow"
        or decision.get("exact_command_sha256") != command_digest
        or decision.get("artifact_hash") is not None
        or decision.get("scope") not in {"artifact", "workspace"}
        or not decision.get("artifact_id")
    ):
        return False
    try:
        now = datetime.now(timezone.utc)
        if decision.get("source") == "policy-bundle-canonical":
            identities = store._cached_policy_bundle_decision_identities(now=now.timestamp())
        elif decision.get("source") == "cloud-signed-memory":
            identities = store._cached_review_memory_decision_identities(now=now.isoformat())
        else:
            return False
        return _identity(decision) in identities
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True, repr=False)
class ExactCommandPolicyClaim:
    """Internal refresh state only; never serialized into a receipt or request."""

    context_hash: str
    identity: tuple[object, ...]


HookPolicyClaim = str | ExactCommandPolicyClaim


def hook_policy_claim(
    context_hash: str,
    *,
    store: GuardStore,
    decision: Mapping[str, object] | None,
    command_digest: str | None,
) -> HookPolicyClaim:
    if decision is not None and authenticated_exact_policy_allow(store, decision, command_digest):
        return ExactCommandPolicyClaim(context_hash, _identity(decision))
    return context_hash


def hook_claim_context_hash(claim: HookPolicyClaim) -> str:
    return claim.context_hash if isinstance(claim, ExactCommandPolicyClaim) else claim


def hook_claim_policy_changed(
    claim: HookPolicyClaim,
    *,
    store: GuardStore,
    decision: Mapping[str, object] | None,
    command_digest: str | None,
) -> bool:
    if not isinstance(claim, ExactCommandPolicyClaim):
        return False
    return (
        decision is None
        or _identity(decision) != claim.identity
        or not authenticated_exact_policy_allow(store, decision, command_digest)
    )
