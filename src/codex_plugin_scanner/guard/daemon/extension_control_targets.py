"""Targeted authenticated metadata lookup, separate from active policy identity."""

from __future__ import annotations

import time
from typing import Any

from ..catalog_delivery import activation_store, lifecycle, preparation, preparation_authority, transport
from ..catalog_delivery.located_store import LocatedStore
from ..runtime.generated_command_catalog_loader import _extension


class TargetMetadata:
    """Request-local metadata overlay; never an executable policy capability."""

    def __init__(self, active):
        self.active = active
        self.extensions = {}

    def get(self, identity):
        return self.active.get(identity) or self.extensions.get(identity)

    def permission(self, identity):
        found = self.active.permission(identity)
        if found is not None:
            return found
        return next(
            (
                permission
                for extension in self.extensions.values()
                for permission in extension.permissions
                if permission.permission_id == identity
            ),
            None,
        )


def request_metadata(store, active, layers):
    from ..catalog_delivery.cache_io import Lease

    with Lease(activation_store.prepare_directory_for_store(store)):
        return _request_metadata(store, active, layers)


def _no_fetch(target, maximum):
    raise ValueError("target metadata fetch authority is unavailable")


def _request_metadata(store, active, layers):
    result = TargetMetadata(active)
    arguments: dict[str, Any] = dict(
        operation="target-metadata",
        controls=[
            dict(
                kind=control.target.kind.value,
                id=control.target.target_id,
                extension_present=active.get(control.target.target_id) is not None,
                permission_present=active.permission(control.target.target_id) is not None,
            )
            for layer in layers
            for control in layer.controls
        ],
    )
    fetch = _no_fetch
    directory = activation_store.prepare_directory_for_store(store)
    with lifecycle.verified_preparation() as invoke:
        while True:
            response = invoke(**arguments)
            if "authority" in response:
                profile = response["authority"]
                arguments["directory"] = str(directory)
                if profile == "installed":
                    authority = (
                        preparation_authority.load_installed_bundle()
                        if preparation_authority.installed_bundle_type()
                        else None
                    )
                    arguments["committed"] = activation_store.read(store) is not None if authority is None else False
                    fetch = authority.fetch if authority is not None else _no_fetch
                else:
                    authority = transport.fetch_root(now=int(time.time()))
                    fetch = preparation.cached_fetcher(directory / "transfers")
                arguments[profile] = preparation_authority.publication(authority)[1].decode() if authority else None
            elif "need" in response:
                # Rust charges the cumulative transfer budget and bounds the rounds.
                LocatedStore(directory / "objects", fetch=fetch).blob(response["need"])
                arguments["budget"] = response["budget"]
            else:
                for reference in response["catalog_refs"]:
                    value = LocatedStore(directory / "objects").json(reference)[0]
                    result.extensions[value["extension_id"]] = _extension(value)
                break
    return result
