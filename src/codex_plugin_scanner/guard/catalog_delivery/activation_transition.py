"""Monotonic publication checks, performed before entering a control mutation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..native_command_control_authority_store import _key
from . import lifecycle, lifecycle_store
from .activation_record import CommittedCommandPacks, seal
from .preparation import PreparedCommandPacks


def validate(previous, prepared, *, store, captured_floor=None, admission_floor=None):
    if type(prepared) is not PreparedCommandPacks:
        raise ValueError("new activation requires authenticated preparation")
    if previous is not None and not isinstance(previous, CommittedCommandPacks):
        raise ValueError("activation floor is not authenticated")
    observed, floor = lifecycle_store.inspect(store)
    if captured_floor is not None and observed != captured_floor:
        raise ValueError("pack_lifecycle_prepared_floor_conflict")
    key = _key(store)
    admission = observed if admission_floor is None else admission_floor
    floor = lifecycle.invoke("read", key=key.hex(), floor=admission)
    if prepared.authority_profile == "committed-subset":
        retained = None if previous is None else previous.record()
        candidate = {
            field: getattr(prepared, field)
            for field in (
                "source_sha",
                "engine",
                "root_digest",
                "publication_id",
                "authority_epoch",
                "revocation_epoch",
            )
        }
        from .pack_store import decode

        publication = decode(prepared._publication)
        candidate.update(issued_at=publication.get("issued_at"), expires_at=publication.get("expires_at"))
        prior = None if retained is None else {field: retained[field] for field in candidate}
        # Resolve inherited channel/version from authenticated native floor;
        # subset identity comparison is native-owned as well.
        result = lifecycle.invoke(
            "subset",
            key=key.hex(),
            floor=admission,
            previous=prior,
            predecessor=prepared.predecessor_digest,
            previous_digest=None if previous is None else previous.record_digest,
            candidate=candidate,
            selected=sorted(prepared.selected),
            active=[] if previous is None else sorted(previous.selected),
        )
    else:
        result = lifecycle.invoke(
            "transition",
            key=key.hex(),
            floor=admission,
            candidate=lifecycle.identity(prepared),
            ancestry=lifecycle.ancestry(floor, prepared.source_sha) if prepared.authority_profile == "remote" else None,
        )
    return observed, result["record"]


@dataclass(frozen=True, slots=True, init=False)
class ActivationDraft:
    _cache_lease: object
    directory: Path
    data: str
    digest: str
    mac: str
    previous_digest: str | None
    baseline_metadata: object
    lifecycle_before: str
    lifecycle_after: str
    security_digest: str | None


def stage(previous, prepared, *, verifier_key, store, captured_floor=None, admission_floor=None, now=None):
    """Prepare all pages and lineage evidence before a control mutation lease."""
    before, after = validate(
        previous, prepared, store=store, captured_floor=captured_floor, admission_floor=admission_floor
    )
    old_digest = None if previous is None else previous.record_digest
    revision = 1 if previous is None else previous.record()["revision"] + 1
    data, digest, mac = seal(prepared, key=verifier_key, revision=revision, previous_digest=old_digest, now=now)
    # Capture a completed small immutable draft; no data reconstruction is needed
    # when the eventual control transaction checks its predecessor and commits.
    from ..native_command_control_binding import load_native_command_program_metadata

    baseline = load_native_command_program_metadata() if previous is None else None
    result = object.__new__(ActivationDraft)
    object.__setattr__(result, "_cache_lease", prepared._cache_lease)
    from .active_security import scope_identity

    for field, value in {
        "directory": prepared.directory,
        "data": data,
        "digest": digest,
        "mac": mac,
        "previous_digest": old_digest,
        "baseline_metadata": baseline,
        "lifecycle_before": before,
        "lifecycle_after": after,
        "security_digest": scope_identity(store),
    }.items():
        object.__setattr__(result, field, value)
    return result
