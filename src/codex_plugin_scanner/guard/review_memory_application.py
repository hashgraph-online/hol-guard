"""Bind registered delivery targets independently from local OAuth machine identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from uuid import UUID

from .review_oauth_binding import GuardReviewContractError, GuardReviewOAuthMetadata, guard_review_oauth_metadata

_APPLICATION_FIELDS = frozenset(
    {"bundleHash", "bundleVersion", "policyVersion", "workspaceId", "deviceId", "machineId", "machineInstallationId"}
)


def registered_installation_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return value if str(UUID(value)) == value else None
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class MemoryApplicationBinding:
    expected: tuple[tuple[str, str], ...]
    grant_id: str

    def target_oauth(self, oauth: GuardReviewOAuthMetadata, bundle: Mapping[str, object]) -> GuardReviewOAuthMetadata:
        expected = dict(self.expected)
        if (
            oauth.installation_id != oauth.machine_id
            or oauth.grant_id != self.grant_id
            or any(
                expected[name] != actual
                for name, actual in (
                    ("workspaceId", oauth.workspace_id),
                    ("deviceId", oauth.device_id),
                    ("machineId", oauth.machine_id),
                    ("bundleHash", bundle.get("bundleHash")),
                    ("bundleVersion", bundle.get("bundleVersion")),
                    ("policyVersion", bundle.get("policyVersion")),
                )
            )
        ):
            raise GuardReviewContractError("decision_memory_application_binding_mismatch")
        return replace(oauth, installation_id=expected["machineInstallationId"])

    def matches_ack(self, acknowledgement: Mapping[str, object]) -> bool:
        return all(acknowledgement.get(name) == value for name, value in self.expected)


def validated_memory_application(
    payload: Mapping[str, object], job: Mapping[str, object] | None, *, store
) -> MemoryApplicationBinding | None:
    expected = payload.get("expectedApplication")
    if expected is None:
        return None
    if not isinstance(expected, Mapping) or set(expected) != _APPLICATION_FIELDS or job is None:
        raise GuardReviewContractError("decision_memory_application_binding_invalid")
    if any(
        not isinstance(value, str) or not value or value.strip() != value or len(value) > 256
        for value in expected.values()
    ):
        raise GuardReviewContractError("decision_memory_application_binding_invalid")
    registered = registered_installation_id(expected.get("machineInstallationId"))
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    if (
        registered is None
        or not oauth.grant_id
        or any(
            job.get(name) != actual
            for name, actual in (
                ("targetMachineInstallationId", registered),
                ("targetDeviceId", oauth.machine_id),
                ("targetGrantId", oauth.grant_id),
                ("workspaceId", oauth.workspace_id),
            )
        )
    ):
        raise GuardReviewContractError("decision_memory_application_target_mismatch")
    binding = MemoryApplicationBinding(tuple(sorted((str(k), str(v)) for k, v in expected.items())), oauth.grant_id)
    bundle = payload.get("decisionMemoryBundle")
    if not isinstance(bundle, Mapping):
        raise GuardReviewContractError("missing_decision_memory_bundle")
    binding.target_oauth(oauth, bundle)
    return binding


def registered_oauth_for_bundle(
    oauth: GuardReviewOAuthMetadata, bound: Mapping[str, object], digest: str
) -> GuardReviewOAuthMetadata:
    applications = bound.get("registeredInstallations", {})
    if not isinstance(applications, Mapping):
        raise GuardReviewContractError("decision_memory_application_binding_invalid")
    if digest not in applications:
        return oauth
    registered = registered_installation_id(applications[digest])
    if registered is None or oauth.installation_id != oauth.machine_id:
        raise GuardReviewContractError("decision_memory_application_binding_invalid")
    return replace(oauth, installation_id=registered)
