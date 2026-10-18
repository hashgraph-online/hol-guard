"""Monotonic publication checks, performed before entering a control mutation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .activation_record import CommittedCommandPacks, seal
from .preparation import PreparedCommandPacks
from .transport import require_source_ancestor


def validate(previous, prepared, *, installed_source=None):
    if type(prepared) is not PreparedCommandPacks:
        raise ValueError("new activation requires authenticated preparation")
    if previous is None:
        if installed_source is None:
            raise ValueError("first pack activation requires the installed source floor")
        require_source_ancestor(installed_source, prepared.source_sha)
        return
    if not isinstance(previous, CommittedCommandPacks):
        raise ValueError("activation floor is not authenticated")
    retained = previous.record()
    if (
        prepared.authority_epoch < retained["authority_epoch"]
        or prepared.revocation_epoch < retained["revocation_epoch"]
    ):
        raise ValueError("publication security epoch rollback")
    old_publication = tuple(map(int, retained["publication_id"].split(".")))
    new_publication = tuple(map(int, prepared.publication_id.split(".")))
    if new_publication < old_publication:
        raise ValueError("publication version rollback")
    if new_publication == old_publication and prepared.root_digest != retained["root_digest"]:
        raise ValueError("publication version was reused")
    require_source_ancestor(retained["source_sha"], prepared.source_sha)


@dataclass(frozen=True, slots=True, init=False)
class ActivationDraft:
    directory: Path
    data: str
    digest: str
    mac: str
    previous_digest: str | None
    baseline_metadata: object


def stage(previous, prepared, *, verifier_key, installed_source=None, now=None):
    """Prepare all pages and lineage evidence before a control mutation lease."""
    validate(previous, prepared, installed_source=installed_source)
    old_digest = None if previous is None else previous.record_digest
    revision = 1 if previous is None else previous.record()["revision"] + 1
    data, digest, mac = seal(prepared, key=verifier_key, revision=revision, previous_digest=old_digest, now=now)
    # Capture a completed small immutable draft; no data reconstruction is needed
    # when the eventual control transaction checks its predecessor and commits.
    from ..native_command_control_binding import load_native_command_program_metadata

    baseline = load_native_command_program_metadata() if previous is None else None
    result = object.__new__(ActivationDraft)
    for field, value in {
        "directory": prepared.directory,
        "data": data,
        "digest": digest,
        "mac": mac,
        "previous_digest": old_digest,
        "baseline_metadata": baseline,
    }.items():
        object.__setattr__(result, field, value)
    return result
