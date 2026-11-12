"""Build-time pack object reader.

Publishing, regeneration and pack builds run without the native runtime
installed, so they read and verify pack objects here. The installed runtime
checks the same references natively.
"""

import hashlib
import json
from typing import Any

from codex_plugin_scanner.guard.catalog_delivery.pack_store import MAX_BLOB_BYTES as MAX_BLOB_BYTES
from codex_plugin_scanner.guard.catalog_delivery.pack_store import MAX_OBJECT_BYTES as MAX_OBJECT_BYTES
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader as NativePackReader
from codex_plugin_scanner.guard.catalog_delivery.pack_store import decode as decode
from codex_plugin_scanner.guard.catalog_delivery.pack_store import digest as digest
from codex_plugin_scanner.guard.catalog_delivery.pack_store import durable_directory as durable_directory
from codex_plugin_scanner.guard.catalog_delivery.pack_store import publish_object as publish_object
from codex_plugin_scanner.guard.catalog_delivery.pack_store import read_object as read_object


class PackReader(NativePackReader):
    def blob(self, reference: dict[str, Any], depth: int = 0) -> bytes:
        if not isinstance(reference, dict) or set(reference) != {"sha256", "length", "expanded_length", "kind"}:
            raise ValueError("invalid pack object reference")
        if (
            depth > 4
            or not digest(reference["sha256"])
            or type(reference["length"]) is not int
            or not 0 < reference["length"] <= MAX_OBJECT_BYTES
            or type(reference["expanded_length"]) is not int
            or not 0 < reference["expanded_length"] <= MAX_BLOB_BYTES
        ):
            raise ValueError("pack object reference bounds invalid")
        path = self.directory / f"{reference['sha256']}.json"
        if path.is_symlink():
            raise ValueError("pack object must not be a symlink")
        data = read_object(path)
        self.reads.add(reference["sha256"])
        if len(data) != reference["length"] or hashlib.sha256(data).hexdigest() != reference["sha256"]:
            raise ValueError("pack object integrity invalid")
        if reference["kind"] == "data":
            if len(data) != reference["expanded_length"]:
                raise ValueError("pack expansion length invalid")
            return data
        if reference["kind"] != "concat":
            raise ValueError("pack object kind invalid")
        value = decode(data)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "parts"}
            or value["schema"] != "guard.pack-concat.v1"
            or not isinstance(value["parts"], list)
            or not 0 < len(value["parts"]) <= 64
        ):
            raise ValueError("pack concat invalid")
        parts = []
        length = 0
        for part in value["parts"]:
            # Check declared expansion before retaining any child data.
            if not isinstance(part, dict) or type(part.get("expanded_length")) is not int:
                raise ValueError("pack expansion length invalid")
            length += part["expanded_length"]
            if not 0 < length <= reference["expanded_length"]:
                raise ValueError("pack expansion length invalid")
            parts.append(self.blob(part, depth + 1))
        if length != reference["expanded_length"]:
            raise ValueError("pack expansion length invalid")
        return b"".join(parts)

    def verify_release(self, root: dict[str, Any], engine: str, identities: set[str]) -> None:
        if root.get("engine") != engine:
            raise ValueError("pack compiler does not match current native implementation")
        seen = set()

        def pack(identity, reference):
            manifest = self.json(reference)
            if (
                manifest.get("schema") != "guard.command-policy-pack.v1"
                or manifest.get("extension_id") != identity
                or manifest.get("engine") != engine
                or manifest.get("semantic_profile") != "cpython-3.12-ucd15"
                or not all(
                    digest(manifest.get(key))
                    for key in ("source_digest", "trust_digest", "program_digest", "cache_key")
                )
            ):
                raise ValueError("pack manifest identity invalid")
            program = self.json(manifest["program"])
            nodes = program.get("nodes")
            if not isinstance(nodes, dict) or len(nodes) > 16384:
                raise ValueError("pack program node bounds invalid")
            for key, reference in nodes.items():
                node = self.json(reference)
                encoded = json.dumps(
                    node, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
                ).encode()
                if hashlib.sha256(b"hol-guard.native-command-matcher.v1\0" + encoded).hexdigest() != key:
                    raise ValueError("pack matcher identity invalid")
                nodes[key] = node
            claimed = program.pop("program_digest", None)
            encoded = json.dumps(
                program, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode()
            if (
                claimed != manifest["program_digest"]
                or program.get("trust_digest") != manifest["trust_digest"]
                or hashlib.sha256(b"hol-guard.native-command-program.v1\0" + encoded).hexdigest() != claimed
            ):
                raise ValueError("pack program identity invalid")
            for field in ("catalog", "descriptors"):
                self.json(manifest[field])

        def page(reference, count, prefix):
            if len(prefix) > 64 or reference.get("expanded_length", MAX_OBJECT_BYTES + 1) > MAX_OBJECT_BYTES:
                raise ValueError("pack index bounds invalid")
            value = self.json(reference)
            if value.get("schema") != "guard.pack-index.v1" or value.get("prefix") != prefix:
                raise ValueError("pack index identity invalid")
            if value.get("kind") == "leaf":
                entries = value.get("entries")
                if not isinstance(entries, list) or len(entries) != count or not 0 < count <= 64:
                    raise ValueError("pack index count invalid")
                previous = ""
                for identity, target in entries:
                    if (
                        not isinstance(identity, str)
                        or not 0 < len(identity) <= 256
                        or identity <= previous
                        or identity in seen
                        or not hashlib.sha256(identity.encode()).hexdigest().startswith(prefix)
                    ):
                        raise ValueError("pack index ownership invalid")
                    previous = identity
                    seen.add(identity)
                    pack(identity, target)
                return
            children = value.get("children")
            if value.get("kind") != "branch" or not isinstance(children, list) or not 0 < len(children) <= 16:
                raise ValueError("pack index branch invalid")
            previous = ""
            total = 0
            for key, child_count, target in children:
                if (
                    not isinstance(key, str)
                    or len(key) != len(prefix) + 1
                    or not key.startswith(prefix)
                    or any(char not in "0123456789abcdef" for char in key)
                    or key <= previous
                    or type(child_count) is not int
                    or child_count <= 0
                ):
                    raise ValueError("pack index routing invalid")
                previous = key
                total += child_count
                if total > count:
                    raise ValueError("pack index count invalid")
                page(target, child_count, key)
            if total != count:
                raise ValueError("pack index count invalid")

        page(root["index"], root["extensions"], "")
        if seen != identities:
            raise ValueError("pack index does not match source inventory")
