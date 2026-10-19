"""Check authenticated, individually proved revocation records before preparation."""

from __future__ import annotations

import hashlib

from .metadata_objects import lookup_entry
from .pack_store import digest
from .preparation_authority import publication


class RevokedPackError(ValueError):
    def __init__(self, identity, epoch):
        self.identity = identity
        self.epoch = epoch
        super().__init__(f"Policy pack {identity} is revoked at epoch {epoch}.")


def revocation_key(identity, kind, manifest=None):
    return hashlib.sha256(
        b"hol-guard.extension-revocation.v1\0"
        + kind.encode()
        + b"\0"
        + identity.encode()
        + b"\0"
        + (manifest or "").encode()
    ).hexdigest()


def check(verified, store, identity, manifest):
    if not digest(manifest):
        raise ValueError("revocation lookup requires an authenticated pack identity")
    revocations = publication(verified)[0]["policy"]["revocations"]
    if not revocations["count"]:
        return
    for kind, target in [("extension", None), ("pack", manifest)]:
        key = revocation_key(identity, kind, target)
        reference = lookup_entry(store, revocations["index"], revocations["count"], key)
        if reference is None:
            continue
        value = store.json(reference)
        fields = {"schema", "extension_id", "kind", "epoch", "state", "reason"}
        if kind == "pack":
            fields.add("manifest_sha256")
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value["schema"] != "guard.extension-revocation.v1"
            or value["extension_id"] != identity
            or value["kind"] != kind
            or (kind == "pack" and value["manifest_sha256"] != manifest)
            or type(value["epoch"]) is not int
            or not 0 < value["epoch"] <= revocations["epoch"]
            or value["state"] not in ("revoked", "restored")
            or not isinstance(value["reason"], str)
            or not 0 < len(value["reason"]) <= 1024
        ):
            raise ValueError("authenticated revocation record is invalid")
        if value["state"] == "revoked":
            raise RevokedPackError(identity, value["epoch"])
