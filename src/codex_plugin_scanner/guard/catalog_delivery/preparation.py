"""Prepare authenticated policy data without changing controls or activation."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from ..native_command_control_binding import NativeCommandProgramMetadata
from . import lifecycle
from .cache_io import Lease, stage_archive
from .located_store import LocatedStore
from .metadata_objects import encoded
from .pack_store import PackReader
from .preparation_authority import publication
from .revocations import RevokedPackError
from .transport import cached_fetcher

IDENTITY = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")
MAX_SELECTED = 32768


class UnavailablePackError(ValueError):
    """An authenticated release does not publish the policy; `code` is Rust's typed reason."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True, init=False)
class PreparedCommandPacks:
    _cache_lease: object
    directory: Path
    metadata: NativeCommandProgramMetadata
    engine: str
    selected: frozenset[str]
    source_sha: str
    publication_id: str
    root_digest: str
    authority_epoch: int
    revocation_epoch: int
    registry_ids: frozenset[str]
    candidate_executables: tuple[str, ...]
    _catalog_refs: tuple[bytes, ...]
    _registry_refs: tuple[bytes, ...]
    _selection_ref: bytes
    _publication: bytes
    authority_profile: str
    predecessor_digest: str | None
    release_version: str | None

    def catalogs(self):
        """Read verified per-pack metadata; matching remains entirely native."""
        from .pack_store import decode

        reader = PackReader(self.directory / "objects")
        for reference in self._catalog_refs:
            values = reader.json(decode(reference))
            if not isinstance(values, list) or len(values) != 1:
                raise ValueError("prepared pack catalog shape invalid")
            yield values[0]

    def registry_catalogs(self):
        """Metadata closure for controls, including retained inactive intents."""
        from .pack_store import decode

        store = LocatedStore(self.directory / "objects")
        for reference in self._registry_refs:
            values = store.json(decode(reference))
            if not isinstance(values, list) or len(values) != 1:
                raise ValueError("prepared registry catalog shape invalid")
            yield values[0]


def prepare(
    verified, enabled_external_ids, directory: Path, *, engine: str, retained_extension_ids=(), now=None, fetch=None
):
    # `_prepare` reads the publication inside the session below. Reading it here
    # as well would start a second verified runtime for the same bytes.
    with lifecycle.verified_preparation() as invoke:
        return _prepare(
            verified,
            enabled_external_ids,
            directory,
            engine=engine,
            retained_extension_ids=retained_extension_ids,
            now=now,
            fetch=fetch,
            invoke=invoke,
        )


def _prepare(
    verified,
    enabled_external_ids,
    directory: Path,
    *,
    engine: str,
    retained_extension_ids=(),
    now=None,
    fetch=None,
    invoke,
):
    """Marshal authenticated capabilities; native preparation owns all policy."""
    root, publication_data, root_digest, profile = publication(verified)
    if profile == "committed-subset" and directory != verified.directory:
        raise ValueError("offline subset requires the committed cache")
    release_version = lifecycle.installed_identity(verified)["version"] if profile == "installed" else None
    arguments = dict(
        release_data=publication_data.decode(),
        profile=profile,
        engine=engine,
        directory=str(directory),
        selected=list(enabled_external_ids),
        retained=list(retained_extension_ids),
        now=int(time.time()) if now is None else now,
        committed_selected=sorted(verified.selected) if profile == "committed-subset" else [],
        committed_registry=sorted(verified.registry_ids) if profile == "committed-subset" else [],
    )
    # Validate before creating cache state or acquiring a lease. The same native
    # operation resumes deterministically after each requested immutable transfer.
    invoke(validate_only=True, **arguments)
    lease = Lease(directory)
    try:
        transfer = (
            verified.fetch
            if profile == "installed"
            else cached_fetcher(directory / "transfers")
            if fetch is None
            else fetch
        )
        # Rust charges every requested object against one cumulative budget and
        # bounds the rounds; the echoed `budget` is the only state carried over.
        store = LocatedStore(directory / "objects", fetch=transfer)
        result = invoke(**arguments)
        while True:
            if "revoked" in result:
                raise RevokedPackError(result["revoked"], result["epoch"])
            if "unavailable" in result:
                raise UnavailablePackError(result["unavailable"])
            if "needs" in result:
                requests = result["needs"]
            elif "need" in result or "need_archives" in result:
                requests = [result]
            else:
                break
            for request in requests:
                if "need" in request:
                    store.blob(request["need"])
                else:
                    for archive in request["need_archives"]:
                        stage_archive(directory, archive, transfer, invoke=invoke)
            result = invoke(budget=result["budget"], **arguments)
        prepared = object.__new__(PreparedCommandPacks)
        fields = dict(
            _cache_lease=lease,
            directory=directory,
            metadata=NativeCommandProgramMetadata(
                *(result[field] for field in ("program_digest", "catalog_digest", "trust_digest"))
            ),
            engine=engine,
            selected=frozenset(result["selected"]),
            source_sha=root["source_sha"],
            publication_id=root["publication_id"],
            root_digest=root_digest,
            authority_epoch=root["authority_epoch"],
            revocation_epoch=root["policy"]["revocations"]["epoch"],
            registry_ids=frozenset(result["registry_ids"]),
            candidate_executables=tuple(result["candidate_executables"]),
            _catalog_refs=tuple(encoded(reference) for reference in result["catalog_refs"]),
            _registry_refs=tuple(encoded(reference) for reference in result["registry_refs"]),
            _selection_ref=encoded(result["selection_ref"]),
            _publication=publication_data,
            authority_profile=profile,
            predecessor_digest=verified.record_digest if profile == "committed-subset" else None,
            release_version=release_version,
        )
        for field, item in fields.items():
            object.__setattr__(prepared, field, item)
        return prepared
    except BaseException:
        lease.close()
        raise
