"""Plan bounded immutable transfer containers independently of root publication."""

from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from pathlib import Path

from extension_artifact_bundle import source_sha
from extension_delivery_containers import MAX_MEMBERS, METADATA_BYTES, POLICY_BYTES

from codex_plugin_scanner.guard.catalog_delivery.containers import location

# Two slots of the 256-asset release inventory are reserved for the signed
# distribution root and its provenance bundle, which every data release
# carries so the release itself can be verified.
ASSETS_PER_RELEASE = 254
PUBLICATION = re.compile(r"[0-9]{1,20}\.[0-9]{1,10}")


class AssetPlan:
    """Existing member locations come only from a separately verified root."""

    def __init__(
        self,
        directory: Path,
        commit: str,
        existing: dict | None = None,
        *,
        publication_id="0.0",
        standalone_policy=False,
    ):
        self.commit = source_sha(commit)
        if not isinstance(publication_id, str) or PUBLICATION.fullmatch(publication_id) is None:
            raise ValueError("delivery publication identity invalid")
        self.publication_id = publication_id
        self.standalone_policy = standalone_policy
        self.directory = directory
        self.existing = existing or {}
        self.locations = {}
        self._pending = []
        self._open = {}
        self._allocated = 0
        for parent in (directory, *directory.parents):
            if parent.is_symlink():
                raise ValueError("delivery asset directory traverses a symlink")
        directory.mkdir(parents=True, exist_ok=True)

    @property
    def pending(self):
        self.finish()
        return self._pending

    def finish(self):
        for kind in tuple(self._open):
            self._finish(kind)

    def _destination(self, name):
        sequence = self._allocated
        self._allocated += 1
        batch = sequence // ASSETS_PER_RELEASE
        if batch >= 1000000:
            raise ValueError("delivery data release inventory exhausted")
        target = {
            "tag": f"extension-data-{self.commit}-{self.publication_id}-{batch:06}",
            "asset": name(sequence % ASSETS_PER_RELEASE),
        }
        directory = self.directory / target["tag"]
        if directory.is_symlink():
            raise ValueError("delivery asset directory traverses a symlink")
        directory.mkdir(exist_ok=True)
        path = directory / target["asset"]
        if path.exists() or path.is_symlink():
            raise ValueError("delivery output already exists; use a fresh staging directory")
        return target, path

    def _record(self, target, path):
        data = path.read_bytes()
        self._pending.append({"location": target, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)})

    def _finish(self, kind):
        row = self._open.pop(kind, None)
        if row is not None:
            target, path, archive, _, _ = row
            archive.close()
            self._record(target, path)

    def asset(self, data: bytes, kind: str) -> dict:
        bound = 65536 if kind == "object" else POLICY_BYTES
        if kind not in {"object", "pack"} or not 0 < len(data) <= bound:
            raise ValueError("delivery asset exceeds byte limit")
        digest = hashlib.sha256(data).hexdigest()
        key = kind + ":" + digest
        if key in self.locations:
            return self.locations[key]
        if key in self.existing:
            result = location(self.existing[key], digest, kind)
        else:
            name = kind + "-" + digest + (".json" if kind == "object" else ".zip")
            overhead = 76 + 2 * len(name)
            maximum = METADATA_BYTES if kind == "object" else POLICY_BYTES
            # A maximal valid pack remains a standalone asset. Its existing
            # 32 MiB contract is not reduced to make room for a ZIP envelope.
            if (kind == "pack" and self.standalone_policy) or len(data) + overhead + 22 > maximum:
                result, path = self._destination(lambda _: name)
                with path.open("xb") as stream:
                    stream.write(data)
                self._record(result, path)
            else:
                row = self._open.get(kind)
                if row is not None and (row[3] >= MAX_MEMBERS or row[4] + len(data) + overhead > maximum):
                    self._finish(kind)
                    row = None
                if row is None:
                    prefix = "objects" if kind == "object" else "packs"
                    target, path = self._destination(lambda index: f"{prefix}-{index:06}.zip")
                    archive = zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED)
                    row = (target, path, archive, 0, 22)
                target, path, archive, count, size = row
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, data)
                self._open[kind] = (target, path, archive, count + 1, size + len(data) + overhead)
                result = {**target, "member": name}
        self.locations[key] = result
        return result
