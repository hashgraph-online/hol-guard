"""Renew roots without rewriting an authenticated immutable v1 snapshot."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import extension_artifact_bundle as legacy

from codex_plugin_scanner.guard.catalog_delivery.authority import MAX_PROVENANCE_BYTES, _verify_attested_digest, decode
from codex_plugin_scanner.guard.catalog_delivery.transport import REPOSITORY, MissingReleaseError, download


def fetch_existing(output, source, engine):
    tag = "extension-artifacts-" + legacy.source_sha(source)
    base = f"https://github.com/{REPOSITORY}/releases/download/{tag}/"
    try:
        manifest_bytes = download(base + legacy.MANIFEST, 1024 * 1024)
        provenance = download(base + "extension-artifacts.intoto.jsonl", MAX_PROVENANCE_BYTES)
    except MissingReleaseError:
        return None
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    _verify_attested_digest(digest, provenance, legacy.MANIFEST, source)
    manifest = decode(manifest_bytes)
    if (
        not isinstance(manifest, dict)
        or manifest.get("source_sha") != source
        or manifest.get("implementation_digest") != engine
    ):
        raise ValueError("published legacy snapshot differs from reviewed source or engine")
    archive = download(base + legacy.ARCHIVE, legacy.MAX_BYTES)
    archive_digest = hashlib.sha256(archive).hexdigest()
    if archive_digest != manifest.get("archive_sha256"):
        raise ValueError("published legacy archive differs from authenticated manifest")
    _verify_attested_digest(archive_digest, provenance, legacy.ARCHIVE, source)
    destination = output / "legacy"
    if destination.exists() or destination.is_symlink():
        raise ValueError("legacy output already exists")
    with tempfile.TemporaryDirectory(dir=output, prefix=".legacy-") as temporary:
        directory = Path(temporary)
        for name, data in (
            (legacy.MANIFEST, manifest_bytes),
            (legacy.ARCHIVE, archive),
            ("extension-artifacts.intoto.jsonl", provenance),
        ):
            (directory / name).write_bytes(data)
        legacy.verify_bundle(directory, source)
        destination.mkdir()
        for name in (legacy.MANIFEST, legacy.ARCHIVE, "extension-artifacts.intoto.jsonl"):
            with (destination / name).open("xb") as stream:
                stream.write((directory / name).read_bytes())
    return {"status": "available", "manifest_sha256": digest, "archive_sha256": archive_digest, "tag": tag}
