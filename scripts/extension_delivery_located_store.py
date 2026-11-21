"""Build-time located metadata objects.

Publishing and regeneration write and read these without the native runtime
installed. The installed runtime walks the same references natively.
"""

import hashlib

from command_pack_store import MAX_BLOB_BYTES, MAX_OBJECT_BYTES, PackReader, decode, digest, publish_object

from codex_plugin_scanner.guard.catalog_delivery.containers import location
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded


class LocatedStore(ObjectStore):
    def __init__(self, directory, publisher=None, fetch=None):
        super().__init__(directory)
        self.publisher = publisher
        self.fetch = fetch

    def put(self, data, kind="data", expanded_length=None):
        if self.publisher is None:
            raise ValueError("delivery store has no publisher")
        reference = super().put(data, kind, expanded_length)
        return {**reference, "location": self.publisher.asset(data, "object")}

    def put_json(self, value):
        data = encoded(value)
        if not 0 < len(data) <= MAX_BLOB_BYTES:
            raise ValueError("delivery metadata exceeds assembled byte limit")
        refs = [self.put(data[offset : offset + MAX_OBJECT_BYTES]) for offset in range(0, len(data), MAX_OBJECT_BYTES)]
        while len(refs) > 1:
            refs = [
                self.put(
                    encoded({"schema": "guard.delivery-concat.v2", "parts": parts}),
                    "concat",
                    sum(part["expanded_length"] for part in parts),
                )
                for offset in range(0, len(refs), 64)
                if (parts := refs[offset : offset + 64])
            ]
        return refs[0]

    def blob(self, reference, depth=0):
        if not isinstance(reference, dict) or set(reference) != {
            "sha256",
            "length",
            "expanded_length",
            "kind",
            "location",
        }:
            raise ValueError("located delivery reference invalid")
        if (
            not digest(reference["sha256"])
            or not isinstance(reference["kind"], str)
            or reference["kind"] not in {"data", "concat"}
            or type(reference["length"]) is not int
            or not 0 < reference["length"] <= MAX_OBJECT_BYTES
        ):
            raise ValueError("located delivery reference bounds invalid")
        if (
            depth > 4
            or type(reference["expanded_length"]) is not int
            or not 0 < reference["expanded_length"] <= MAX_BLOB_BYTES
        ):
            raise ValueError("located delivery expansion invalid")
        target = location(reference["location"], reference["sha256"], "object")
        raw_ref = {key: reference[key] for key in ("sha256", "length", "kind", "expanded_length")}
        raw_ref.update(kind="data", expanded_length=reference["length"])
        path = self.directory / (reference["sha256"] + ".json")
        if not path.exists() and not path.is_symlink() and self.fetch is not None:
            if type(reference["length"]) is not int or not 0 < reference["length"] <= MAX_OBJECT_BYTES:
                raise ValueError("located delivery length invalid")
            data = self.fetch(target, reference["length"])
            if len(data) != reference["length"] or hashlib.sha256(data).hexdigest() != reference["sha256"]:
                raise ValueError("fetched delivery object integrity invalid")
            publish_object(self.directory, reference["sha256"], data)
        data = PackReader.blob(self, raw_ref)
        if reference["kind"] == "data":
            if len(data) != reference["expanded_length"]:
                raise ValueError("located delivery length invalid")
            return data
        value = decode(data)
        if (
            reference["kind"] != "concat"
            or not isinstance(value, dict)
            or set(value) != {"schema", "parts"}
            or value["schema"] != "guard.delivery-concat.v2"
            or not isinstance(value["parts"], list)
            or not 0 < len(value["parts"]) <= 64
        ):
            raise ValueError("located delivery concatenation invalid")
        parts = []
        total = 0
        for part in value["parts"]:
            if not isinstance(part, dict) or type(part.get("expanded_length")) is not int:
                raise ValueError("located delivery part invalid")
            total += part["expanded_length"]
            if not 0 < total <= reference["expanded_length"]:
                raise ValueError("located delivery expansion invalid")
            parts.append(self.blob(part, depth + 1))
        if total != reference["expanded_length"]:
            raise ValueError("located delivery expansion invalid")
        return b"".join(parts)
