"""Bounded, authenticated local activation records; no remote authority by hash."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..native_command_control_binding import NativeCommandProgramMetadata
from ..runtime.extension_control_authority import authenticated_record, verify_authenticated_record
from . import lifecycle
from .activation_types import ActivationHeader
from .authority import DIGEST, SHA
from .located_store import LocatedStore
from .metadata_objects import ObjectStore, encoded, validate_reference
from .pack_store import PackReader, decode
from .preparation import IDENTITY, MAX_SELECTED, PreparedCommandPacks
from .selection import PUBLICATION

PURPOSE = "command-pack-activation.v1"
SCHEMA = "guard.command-pack-activation.v1"
SCHEMA_V2 = "guard.command-pack-activation.v2"
MAX_RECORD_BYTES = 64 * 1024
REGISTRY_PAGE = "guard.command-pack-registry-page.v1"
EXECUTABLE_PAGE = "guard.command-pack-executables-page.v1"
SELECTION_PAGE = "guard.command-pack-selection-page.v1"
MAX_EXECUTABLES = 1048576


def _pages(store, values, schema, field="items"):
    next_page = None
    for offset in reversed(range(0, len(values), 64)):
        value = {"schema": schema, field: values[offset : offset + 64], "next": next_page}
        if len(encoded(value)) > MAX_RECORD_BYTES:
            raise ValueError("activation metadata page exceeds byte budget")
        next_page = store.put_json(value)
    return next_page


def _items(reader, reference, count, schema, maximum, field="items"):
    if type(count) is not int or not 0 <= count <= maximum or (reference is None) != (count == 0):
        raise ValueError("activation metadata count invalid")
    seen, read = set(), 0
    while reference is not None:
        validate_reference(reference)
        if reference["expanded_length"] > MAX_RECORD_BYTES or reference["sha256"] in seen:
            raise ValueError("activation metadata page bounds invalid")
        seen.add(reference["sha256"])
        value = reader.json(reference)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", field, "next"}
            or value["schema"] != schema
            or not isinstance(value[field], list)
            or not 0 < len(value[field]) <= 64
        ):
            raise ValueError("activation metadata page invalid")
        for item in value[field]:
            read += 1
            if read > count:
                raise ValueError("activation metadata has surplus entries")
            yield item
        reference = value["next"]
    if read != count:
        raise ValueError("activation metadata is incomplete")


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
    result = authenticated_record(payload, key=key, purpose=PURPOSE)
    if len(result[0].encode()) > MAX_RECORD_BYTES:
        raise ValueError("activation record exceeds byte budget")
    return result


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
    if not isinstance(data, str) or not 0 < len(data.encode()) <= MAX_RECORD_BYTES:
        raise ValueError("activation record byte bounds invalid")
    decode(data.encode())  # Duplicate/nonfinite fields fail before the authority decoder.
    value = verify_authenticated_record(
        data, expected_digest=expected_digest, expected_mac=expected_mac, key=key, purpose=PURPOSE
    )
    fields = {
        "authority_schema_version",
        "purpose",
        "schema",
        "revision",
        "previous_digest",
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "engine",
        "source_sha",
        "publication_id",
        "root_digest",
        "authority_epoch",
        "revocation_epoch",
        "selection",
        "selected_count",
        "registry",
        "registry_count",
        "executables",
        "executable_count",
        "distribution",
        "issued_at",
        "expires_at",
    }
    if value.get("schema") == SCHEMA_V2:
        fields.add("authority_profile")
        if value.get("authority_profile") not in {"installed", "committed-subset", "remote"}:
            raise ValueError("activation authority profile invalid")
    if set(value) != fields or value["schema"] not in {SCHEMA, SCHEMA_V2}:
        raise ValueError("activation record schema invalid")
    for field in ("program_digest", "catalog_digest", "trust_digest", "engine", "root_digest"):
        candidate = value[field]
        if not isinstance(candidate, str) or DIGEST.fullmatch(candidate) is None:
            raise ValueError("activation digest invalid")
    installed = value["issued_at"] is None and value["expires_at"] is None
    if installed and (value["schema"] != SCHEMA_V2 or value["publication_id"] != "0.0"):
        raise ValueError("activation installed authority invalid")
    if value.get("authority_profile") == "installed" and not installed:
        raise ValueError("installed activation cannot claim remote freshness")
    if value.get("authority_profile") == "committed-subset" and value["previous_digest"] is None:
        raise ValueError("offline subset requires a committed predecessor")
    if (
        not isinstance(value["source_sha"], str)
        or SHA.fullmatch(value["source_sha"]) is None
        or not isinstance(value["publication_id"], str)
        or PUBLICATION.fullmatch(value["publication_id"]) is None
    ):
        raise ValueError("activation source identity invalid")
    for field, minimum in [("revision", 1), ("authority_epoch", 1), ("revocation_epoch", 0)]:
        candidate = value[field]
        if type(candidate) is not int or not minimum <= candidate < 2**64:
            raise ValueError("activation epoch or revision invalid")
    if not installed and (
        type(value["issued_at"]) is not int
        or type(value["expires_at"]) is not int
        or not 0 <= value["issued_at"] < value["expires_at"]
    ):
        raise ValueError("activation validity interval invalid")
    if value["previous_digest"] is not None and (
        not isinstance(value["previous_digest"], str) or DIGEST.fullmatch(value["previous_digest"]) is None
    ):
        raise ValueError("activation predecessor invalid")
    for field, minimum, maximum in [
        ("selected_count", 1, MAX_SELECTED),
        ("registry_count", 1, MAX_SELECTED),
        ("executable_count", 0, MAX_EXECUTABLES),
    ]:
        candidate = value[field]
        if type(candidate) is not int or not minimum <= candidate <= maximum:
            raise ValueError("activation metadata count invalid")
    for field, count in [
        ("selection", value["selected_count"]),
        ("registry", value["registry_count"]),
        ("executables", value["executable_count"]),
    ]:
        if (value[field] is None) != (count == 0):
            raise ValueError("activation metadata reference missing")
        if value[field] is not None:
            validate_reference(value[field])
    validate_reference(value["distribution"])
    # Every scalar and reference above has been validated. Keep that typed
    # contract across the decoder boundary without treating arbitrary JSON
    # dictionaries as activation headers elsewhere.
    return cast(ActivationHeader, cast(object, value))


def admission_is_current(header: ActivationHeader, now: int) -> bool:
    return lifecycle.invoke(
        "admission",
        profile=header.get("authority_profile", "remote"),
        issued_at=header["issued_at"],
        expires_at=header["expires_at"],
        now=now,
    )["current"]


def open_record(data, expected_digest, expected_mac, *, key, directory):
    value = verify_header(data, expected_digest, expected_mac, key=key)
    reader = PackReader(directory / "objects")
    validate_reference(value["distribution"])
    if (
        value["distribution"]["expanded_length"] > MAX_RECORD_BYTES
        or value["distribution"]["sha256"] != value["root_digest"]
    ):
        raise ValueError("activation distribution binding invalid")
    distribution = reader.json(value["distribution"])
    if (
        not isinstance(distribution, dict)
        or distribution.get("schema")
        != ("guard.command-pack-bundle.v1" if value["issued_at"] is None else "guard.extension-distribution.v2")
        or any(
            distribution.get(field) != value[field]
            for field in ("source_sha", "engine", "publication_id", "authority_epoch", "issued_at", "expires_at")
        )
        or distribution["policy"]["revocations"]["epoch"] != value["revocation_epoch"]
    ):
        raise ValueError("activation publication identity invalid")
    selected = list(_items(reader, value["selection"], value["selected_count"], SELECTION_PAGE, MAX_SELECTED, "ids"))
    if (
        not selected
        or any(
            not isinstance(identity, str) or len(identity) > 256 or IDENTITY.fullmatch(identity) is None
            for identity in selected
        )
        or selected != sorted(set(selected))
    ):
        raise ValueError("activation selected inventory invalid")
    references = tuple(
        encoded(reference)
        for reference in _items(reader, value["registry"], value["registry_count"], REGISTRY_PAGE, MAX_SELECTED)
    )
    executables = tuple(
        _items(reader, value["executables"], value["executable_count"], EXECUTABLE_PAGE, MAX_EXECUTABLES)
    )
    if (
        any(not isinstance(item, str) or not 0 < len(item) <= 8192 for item in executables)
        or tuple(sorted(set(executables))) != executables
    ):
        raise ValueError("activation executable inventory invalid")
    store = LocatedStore(directory / "objects")
    ids = []
    for reference in references:
        catalog = store.json(decode(reference))
        if not isinstance(catalog, list) or len(catalog) != 1 or not isinstance(catalog[0], dict):
            raise ValueError("activation registry metadata invalid")
        ids.append(catalog[0].get("extension_id"))
    if (
        any(
            not isinstance(identity, str) or len(identity) > 256 or IDENTITY.fullmatch(identity) is None
            for identity in ids
        )
        or ids != sorted(set(ids))
        or not set(selected) <= set(ids)
    ):
        raise ValueError("activation registry inventory invalid")
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
