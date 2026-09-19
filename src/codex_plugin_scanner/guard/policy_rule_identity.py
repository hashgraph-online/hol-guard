"""Immutable canonical rule provenance for recorded decisions, never authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace

from .policy_publication_binding import PolicyPublicationBinding

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_REVISION = re.compile(r"(?:0|[1-9][0-9]*)", re.ASCII)
POLICY_RULE_IDENTITY_FIELDS = frozenset({"policyId", "ruleId", "policyVersion"})


@dataclass(frozen=True, slots=True)
class PolicyRuleIdentity:
    policy_id: str
    rule_id: str
    policy_version: str
    publication: PolicyPublicationBinding | None = None

    def __post_init__(self) -> None:
        if self.publication is not None and not isinstance(self.publication, PolicyPublicationBinding):
            raise ValueError("publication binding must be typed")
        if not all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in (self.policy_id, self.rule_id)):
            raise ValueError("policy and rule identifiers must be bounded canonical identifiers")
        if not isinstance(self.policy_version, str) or _REVISION.fullmatch(self.policy_version) is None:
            raise ValueError("policy version must be a canonical non-negative decimal revision")

    def to_dict(self) -> dict[str, str]:
        return {"policyId": self.policy_id, "ruleId": self.rule_id, "policyVersion": self.policy_version}

    def to_selected_row_dict(self) -> dict[str, object]:
        payload: dict[str, object] = dict(self.to_dict())
        if self.publication is not None:
            payload["_policyPublication"] = self.publication.to_dict()
        return payload

    @classmethod
    def from_selected_row(cls, payload: Mapping[str, object]) -> PolicyRuleIdentity | None:
        identity = cls.from_mapping(payload)
        return (
            replace(identity, publication=PolicyPublicationBinding.from_mapping(payload.get("_policyPublication")))
            if identity
            else None
        )

    @classmethod
    def from_mapping(cls, payload: object) -> PolicyRuleIdentity | None:
        """Drop incomplete legacy or malformed diagnostic identities as a unit."""
        if not isinstance(payload, Mapping):
            return None
        values = tuple(payload.get(key) for key in ("policyId", "ruleId", "policyVersion"))
        if not all(isinstance(value, str) for value in values):
            return None
        try:
            return cls(str(values[0]), str(values[1]), str(values[2]))
        except ValueError:
            return None


def canonical_rule_identity(
    bundle: Mapping[str, object], rule_id: str | None, *, installation_id: str | None = None
) -> PolicyRuleIdentity | None:
    """Project a compiler-selected rule from an already authenticated v2 source."""
    if bundle.get("contractVersion") != "guard-policy-bundle.v2":
        return None
    payload = bundle.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, Mapping) else None
    if not isinstance(metadata, Mapping):
        return None
    revision = metadata.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        return None
    identity = PolicyRuleIdentity.from_mapping(
        {"policyId": metadata.get("id"), "ruleId": rule_id, "policyVersion": str(revision)}
    )
    publication = PolicyPublicationBinding.from_mapping(
        {
            "bundleVersion": bundle.get("bundleVersion"),
            "bundleHash": bundle.get("bundleHash"),
            "installationId": installation_id,
        }
    )
    return replace(identity, publication=publication) if identity is not None else None


def package_policy_rule_identity(evaluation: object, final_action: object) -> PolicyRuleIdentity | None:
    """Retain optional typed package provenance only for its unchanged outcome."""
    identity = getattr(evaluation, "policy_rule_identity", None)
    if isinstance(identity, PolicyRuleIdentity) and getattr(evaluation, "policy_action", None) == final_action:
        return identity
    return None
