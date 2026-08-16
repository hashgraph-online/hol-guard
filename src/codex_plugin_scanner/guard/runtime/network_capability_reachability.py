"""Machine-checkable reachability rules for advertised network capabilities."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

REACHABILITY_SCHEMA_VERSION: Final = 1
REQUIRED_CAPABILITY_IDS: Final = frozenset(
    {
        "bounded-offline-containment",
        "gvisor-isolated-runtime",
        "kubernetes-network-policy",
        "linux-selective-egress",
        "macos-selective-egress",
        "proxy-only-egress",
        "windows-selective-egress",
    }
)
_LINK_FIELDS: Final = (
    "production_entrypoint",
    "installed_artifact",
    "live_probe",
    "active_generation_source",
    "observer",
    "behavioral_test",
)
_ALLOWED_STATES: Final = frozenset({"active", "internal-reference", "unavailable"})


class ReachabilityManifestError(ValueError):
    """Raised when a capability manifest can overstate installed behavior."""


def _repository_path(root: Path, value: object, *, field: str, capability_id: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return f"{capability_id}: {field} must be a non-empty repository path"
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        return f"{capability_id}: {field} must stay within the repository"
    if not (root / relative).is_file():
        return f"{capability_id}: {field} does not exist: {value}"
    return None


def validate_reachability_manifest(payload: Mapping[str, object], *, repository_root: Path) -> tuple[str, ...]:
    """Return deterministic validation errors for one reachability manifest."""

    errors: list[str] = []
    if payload.get("schema_version") != REACHABILITY_SCHEMA_VERSION:
        errors.append("schema_version must equal 1")

    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        return (*errors, "capabilities must be a list")

    capabilities: list[Mapping[str, object]] = []
    for index, raw_capability in enumerate(raw_capabilities):
        if not isinstance(raw_capability, Mapping):
            errors.append(f"capabilities[{index}] must be an object")
            continue
        capabilities.append(cast(Mapping[str, object], raw_capability))

    identifiers = [item.get("id") for item in capabilities]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        errors.append("every capability must have a non-empty string id")
        return tuple(errors)
    string_identifiers = cast(list[str], identifiers)
    if len(string_identifiers) != len(set(string_identifiers)):
        errors.append("capability ids must be unique")
    if string_identifiers != sorted(string_identifiers):
        errors.append("capabilities must be sorted by id")
    missing_ids = sorted(REQUIRED_CAPABILITY_IDS - set(string_identifiers))
    unexpected_ids = sorted(set(string_identifiers) - REQUIRED_CAPABILITY_IDS)
    if missing_ids:
        errors.append(f"required capability ids are missing: {', '.join(missing_ids)}")
    if unexpected_ids:
        errors.append(f"unregistered capability ids are present: {', '.join(unexpected_ids)}")

    for capability in capabilities:
        capability_id = cast(str, capability["id"])
        advertised = capability.get("advertised")
        if type(advertised) is not bool:
            errors.append(f"{capability_id}: advertised must be a boolean")
            continue
        state = capability.get("state")
        if state not in _ALLOWED_STATES:
            errors.append(f"{capability_id}: state is invalid")
        platforms = capability.get("platforms")
        if (
            not isinstance(platforms, list)
            or not platforms
            or any(not isinstance(platform, str) or not platform for platform in platforms)
        ):
            errors.append(f"{capability_id}: platforms must contain non-empty strings")
        contract_error = _repository_path(
            repository_root,
            capability.get("contract"),
            field="contract",
            capability_id=capability_id,
        )
        if contract_error is not None:
            errors.append(contract_error)

        if advertised:
            if state != "active":
                errors.append(f"{capability_id}: advertised capabilities must be active")
            if capability.get("achieved_grade") in {None, "unavailable"}:
                errors.append(f"{capability_id}: advertised capabilities require an achieved grade")
            for field in _LINK_FIELDS:
                link_error = _repository_path(
                    repository_root,
                    capability.get(field),
                    field=field,
                    capability_id=capability_id,
                )
                if link_error is not None:
                    errors.append(link_error)
            if capability.get("production_ready") is not True:
                errors.append(f"{capability_id}: advertised capabilities must be production ready")
        else:
            if not isinstance(capability.get("internal_reason"), str) or not capability["internal_reason"]:
                errors.append(f"{capability_id}: non-advertised capabilities require an internal reason")
            if capability.get("achieved_grade") != "unavailable":
                errors.append(f"{capability_id}: non-advertised capabilities cannot claim an achieved grade")
            if capability.get("production_ready") is not False:
                errors.append(f"{capability_id}: non-advertised capabilities cannot be production ready")

    return tuple(errors)


def load_reachability_manifest(path: Path) -> Mapping[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ReachabilityManifestError("reachability manifest must be an object")
    return cast(Mapping[str, object], payload)


def assert_reachability_manifest(path: Path, *, repository_root: Path) -> None:
    errors = validate_reachability_manifest(load_reachability_manifest(path), repository_root=repository_root)
    if errors:
        raise ReachabilityManifestError("\n".join(errors))


def repository_manifest_path(repository_root: Path) -> Path:
    return repository_root / "ci" / "guard-network-capability-reachability.v1.json"


__all__: Sequence[str] = (
    "REACHABILITY_SCHEMA_VERSION",
    "REQUIRED_CAPABILITY_IDS",
    "ReachabilityManifestError",
    "assert_reachability_manifest",
    "load_reachability_manifest",
    "repository_manifest_path",
    "validate_reachability_manifest",
)
