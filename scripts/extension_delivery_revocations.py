"""Publish reviewed bounded pack/extension revocation records."""

from __future__ import annotations

import re

from command_pack_store import digest

from codex_plugin_scanner.guard.catalog_delivery.authority import decode
from codex_plugin_scanner.guard.catalog_delivery.revocations import revocation_key as revocation_key
from codex_plugin_scanner.guard.extension_builder.io import read_bytes

IDENTITY = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")


def load(root):
    security = decode(read_bytes(root / "contracts/catalog-delivery/security.v1.json", limit=65536))
    if (
        not isinstance(security, dict)
        or set(security) != {"schema", "authority_epoch", "revocation_epoch"}
        or security["schema"] != "guard.extension-delivery-security.v1"
        or type(security["authority_epoch"]) is not int
        or security["authority_epoch"] <= 0
        or type(security["revocation_epoch"]) is not int
        or security["revocation_epoch"] < 0
    ):
        raise ValueError("delivery security epoch configuration invalid")
    index = {}
    for path in sorted((root / "contracts/extensions/revocations").glob("*.v1.json")):
        value = decode(read_bytes(path, limit=65536))
        fields = {"schema", "extension_id", "kind", "epoch", "state", "reason"}
        if (
            not isinstance(value, dict)
            or value.get("schema") != "guard.extension-revocation.v1"
            or value.get("kind") not in ("pack", "extension")
        ):
            raise ValueError("delivery revocation schema invalid")
        if value["kind"] == "pack":
            fields.add("manifest_sha256")
            if not digest(value.get("manifest_sha256")):
                raise ValueError("delivery revoked manifest identity invalid")
        identity = value.get("extension_id")
        if (
            set(value) != fields
            or not isinstance(identity, str)
            or len(identity) > 256
            or IDENTITY.fullmatch(identity) is None
            or type(value["epoch"]) is not int
            or not 0 < value["epoch"] <= security["revocation_epoch"]
            or value["state"] not in ("revoked", "restored")
            or not isinstance(value["reason"], str)
            or not 0 < len(value["reason"]) <= 1024
        ):
            raise ValueError("delivery revocation record invalid")
        key = revocation_key(identity, value["kind"], value.get("manifest_sha256"))
        if path.name != key + ".v1.json" or key in index:
            raise ValueError("delivery revocation ownership invalid")
        index[key] = value
    return security, index


def build(root, store):
    security, records = load(root)
    index = {key: store.put_json(value) for key, value in records.items()}
    return security["authority_epoch"], {
        "epoch": security["revocation_epoch"],
        "count": len(index),
        "index": store.index(index) if index else None,
    }
