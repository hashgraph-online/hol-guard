"""Bounded, authenticated local activation records; no remote authority by hash."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..native_command_control_binding import NativeCommandProgramMetadata
from . import lifecycle
from .activation_types import ActivationHeader
from .authority import DIGEST
from .located_store import LocatedStore
from .metadata_objects import ObjectStore, encoded
from .object_native import sessioned
from .pack_store import decode
from .preparation import PreparedCommandPacks

PURPOSE = "command-pack-activation.v1"
SCHEMA = "guard.command-pack-activation.v1"
SCHEMA_V2 = "guard.command-pack-activation.v2"
MAX_RECORD_BYTES = 64 * 1024
REGISTRY_PAGE = "guard.command-pack-registry-page.v1"
EXECUTABLE_PAGE = "guard.command-pack-executables-page.v1"
MAX_EXECUTABLES = 1048576


def _pages(store, values, schema, field="items"):
    next_page = None
    for offset in reversed(range(0, len(values), 64)):
        value = {"schema": schema, field: values[offset : offset + 64], "next": next_page}
        if len(encoded(value)) > MAX_RECORD_BYTES:
            raise ValueError("activation metadata page exceeds byte budget")
        next_page = store.put_json(value)
    return next_page


def seal(prepared, *, key: bytes, revision: int, previous_digest=None, now=None):
    """Seal only completed preparation; callers commit under the mutation lease."""
    if type(prepared) is not PreparedCommandPacks or type(revision) is not int or not 0 < revision < 2**64:
        raise ValueError("activation requires prepared packs and a valid revision")
    if previous_digest is not None and (
        not isinstance(previous_digest, str) or DIGEST.fullmatch(previous_digest) is None
    ):
        raise ValueError("activation predecessor invalid")
    publication = decode(prepared._publication)
    now = int(time.time()) if now is None else now
    profile = prepared.authority_profile
    if (
        type(now) is not int
        or not lifecycle.invoke(
            "admission",
            profile=profile,
            now=now,
            issued_at=publication.get("issued_at"),
            expires_at=publication.get("expires_at"),
        )["current"]
    ):
        raise ValueError("prepared publication expired before activation")
    if profile == "committed-subset" and prepared.predecessor_digest != previous_digest:
        raise ValueError("offline subset predecessor differs from committed authority")
    if len(prepared.candidate_executables) > MAX_EXECUTABLES:
        raise ValueError("activation executable metadata exceeds budget")
    local = ObjectStore(prepared.directory / "objects")
    registry = _pages(local, [decode(value) for value in prepared._registry_refs], REGISTRY_PAGE)
    executables = _pages(local, list(prepared.candidate_executables), EXECUTABLE_PAGE)
    payload: dict[str, object] = {
        "schema": SCHEMA_V2,
        "revision": revision,
        "previous_digest": previous_digest,
        "program_digest": prepared.metadata.program_digest,
        "catalog_digest": prepared.metadata.catalog_digest,
        "trust_digest": prepared.metadata.trust_digest,
        "engine": prepared.engine,
        "source_sha": prepared.source_sha,
        "publication_id": prepared.publication_id,
        "root_digest": prepared.root_digest,
        "authority_epoch": prepared.authority_epoch,
        "revocation_epoch": prepared.revocation_epoch,
        "issued_at": publication.get("issued_at"),
        "expires_at": publication.get("expires_at"),
        "selection": decode(prepared._selection_ref),
        "selected_count": len(prepared.selected),
        "registry": registry,
        "registry_count": len(prepared.registry_ids),
        "executables": executables,
        "executable_count": len(prepared.candidate_executables),
        "distribution": local.put(prepared._publication),
    }
    payload["authority_profile"] = profile
    # The runtime seals only a record its reader accepts, within the byte budget.
    sealed = lifecycle.record("seal", "activation", key=key, payload=payload)
    return sealed["record"], sealed["digest"], sealed["mac"]


@dataclass(frozen=True, slots=True, init=False)
class CommittedCommandPacks:
    directory: Path
    metadata: NativeCommandProgramMetadata
    engine: str
    source_sha: str
    selected: frozenset[str]
    registry_ids: frozenset[str]
    candidate_executables: tuple[str, ...]
    record_digest: str
    _record: bytes
    _registry_refs: tuple[bytes, ...]

    def registry_catalogs(self):
        store = LocatedStore(self.directory / "objects")
        for reference in self._registry_refs:
            values = store.json(decode(reference))
            if not isinstance(values, list) or len(values) != 1:
                raise ValueError("committed registry catalog invalid")
            yield values[0]

    def record(self):
        return decode(self._record)


def verify_header(data, expected_digest, expected_mac, *, key) -> ActivationHeader:
    """The authenticated activation header; the runtime checks every field."""
    verified = lifecycle.record("verify", "activation", key=key, record=data, digest=expected_digest, mac=expected_mac)
    return cast(ActivationHeader, verified["value"])


def admission_is_current(header: ActivationHeader, now: int) -> bool:
    return lifecycle.invoke(
        "admission",
        profile=header.get("authority_profile", "remote"),
        issued_at=header["issued_at"],
        expires_at=header["expires_at"],
        now=now,
    )["current"]


@sessioned
def open_record(data, expected_digest, expected_mac, *, key, directory):
    """The authenticated activation and the local inventories it binds; the runtime checks each."""
    opened = lifecycle.record(
        "open",
        "activation",
        key=key,
        record=data,
        digest=expected_digest,
        mac=expected_mac,
        directory=str(directory),
    )
    value = cast(ActivationHeader, opened["value"])
    selected, ids, executables = opened["selected"], opened["registry_ids"], tuple(opened["executables"])
    references = tuple(encoded(reference) for reference in opened["registry"])
    result = object.__new__(CommittedCommandPacks)
    captured = {
        "directory": directory,
        "metadata": NativeCommandProgramMetadata(
            value["program_digest"], value["catalog_digest"], value["trust_digest"]
        ),
        "engine": value["engine"],
        "source_sha": value["source_sha"],
        "selected": frozenset(selected),
        "registry_ids": frozenset(ids),
        "candidate_executables": executables,
        "record_digest": expected_digest,
        "_record": encoded(value),
        "_registry_refs": references,
    }
    for name, item in captured.items():
        object.__setattr__(result, name, item)
    return result
