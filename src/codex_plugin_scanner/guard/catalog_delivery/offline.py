"""Complete public release export/prefetch. All runtime planning is native."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..extension_builder.io import checked_path, read_bytes
from . import lifecycle, preparation_authority
from .authority import VerifiedDistribution
from .cache_io import Lease, write_once
from .pack_store import publish_object
from .transport import cached_fetcher

if TYPE_CHECKING:
    from .installed_bundle import VerifiedInstalledBundle


def _request(authority, directory, operation, *, destination=None):
    _root, data, _digest, profile = preparation_authority.publication(authority)
    if profile == "installed":
        evidence = lifecycle.release_evidence(authority)
    elif type(authority) is VerifiedDistribution:
        evidence = {"release_data": data.decode()}
    else:
        raise ValueError("complete offline transfer requires a verified publication")
    request = dict(
        operation=operation,
        profile=profile,
        directory=str(directory),
        now=int(time.time()),
        **({} if destination is None else {"destination": str(destination)}),
        **evidence,
    )
    return lifecycle.invoke("offline", **request) if destination is None else lifecycle.transfer(**request)


def prefetch(authority, directory: Path, *, fetch=None):
    with lifecycle.session():
        return _prefetch(authority, directory, fetch=fetch)


def _prefetch(authority, directory: Path, *, fetch=None):
    """Stage every optional public pack, without changing control state."""
    lease = Lease(directory)
    try:
        if type(authority) is preparation_authority.installed_bundle_type():
            transfer = authority.fetch
        elif type(authority) is VerifiedDistribution:
            transfer = cached_fetcher(directory / "transfers") if fetch is None else fetch
        else:
            raise ValueError("offline prefetch requires a verified publication")
        objects = checked_path(directory / "objects")
        objects.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Each wave advances a bounded immutable graph; native rejects cycles,
        # depth, size and admission budgets. Transport cannot select new roots.
        for _ in range(96):
            plan = _request(authority, directory, "plan")
            if plan.get("complete"):
                return plan
            installed = type(authority) is preparation_authority.installed_bundle_type()
            if installed:
                needs = [need for need in plan["needs"] if need["kind"] != "archive"]
                references = [(need["reference"]["location"], need["reference"]["length"]) for need in needs]
                for need, data in zip(
                    needs, cast("VerifiedInstalledBundle", authority).fetch_objects(references), strict=True
                ):
                    publish_object(objects, need["reference"]["sha256"], data)
            for need in plan["needs"]:
                ref = need["reference"]
                if need["kind"] == "archive":
                    write_once(
                        directory / "archives" / (ref["sha256"] + ".zip"), transfer(ref["location"], ref["length"])
                    )
                elif not installed:
                    publish_object(objects, ref["sha256"], transfer(ref["location"], ref["length"]))
            for archive in plan.get("ingests", ()):
                data = read_bytes(directory / "archives" / (archive["sha256"] + ".zip"), limit=32 * 1024 * 1024)
                for identity, offset, size in archive["members"]:
                    publish_object(objects, identity, data[offset : offset + size])
        raise ValueError("offline prefetch traversal did not complete")
    finally:
        lease.close()


def export_release(authority, directory: Path, destination: Path):
    """Export a portable directory containing only native-proved public assets."""
    destination = checked_path(destination)
    lease = Lease(directory)
    try:
        prefetch(authority, directory)
        _copy(authority, directory, destination, "export-fresh-copy")
        return _request(authority, destination, "import")
    finally:
        lease.close()


def _copy(authority, source, destination, operation):
    # Native-selected batches verify each read immediately before native writes.
    # No adapter re-read can leak substituted bytes into a partial export.
    _request(authority, source, operation, destination=destination)


def import_release(authority, source: Path, directory: Path):
    """Exact authenticated source/engine/Root compatibility; never activate here."""
    lease = Lease(directory)
    try:
        plan = _request(authority, checked_path(source), "import")
        if not plan.get("complete"):
            raise ValueError("offline export is incomplete")
        _copy(authority, source, directory, "import-copy")
        verified = _request(authority, directory, "plan")
        if not verified.get("complete"):
            raise ValueError("offline import did not complete")
        return verified
    finally:
        lease.close()
