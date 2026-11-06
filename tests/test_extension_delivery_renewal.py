"""Root renewal retains authenticated immutable compatibility bytes."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import stat
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def renewal(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("extension_delivery_legacy_reuse")


def assets(renewal, source, engine):
    identities = {"catalog_digest": "a" * 64, "program_digest": "b" * 64, "implementation_digest": engine}
    files = {name: b"{}" for name in renewal.legacy.FILES}
    files[renewal.legacy.FILES[0]] = json.dumps(identities).encode()
    files["docs/guard/extensions/catalog.v2.json"] = b'{"githubLogin":"original-public-login"}'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    raw = buffer.getvalue()
    manifest = {
        "schema": renewal.legacy.SCHEMA,
        "source_sha": source,
        **identities,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in files.items()
        },
    }
    return manifest, raw


@pytest.mark.parametrize("fault", [None, "source", "engine", "archive", "signature"])
def test_reuse_authenticates_source_engine_subjects_and_exact_bytes(renewal, monkeypatch, tmp_path, fault):
    source, engine = "1" * 40, "e" * 64
    manifest, archive = assets(renewal, source, engine)
    if fault == "source":
        manifest["source_sha"] = "2" * 40
    if fault == "engine":
        manifest["implementation_digest"] = "f" * 64
    encoded = json.dumps(manifest).encode()
    downloads, subjects = [], []

    def download(url, maximum):
        downloads.append(url)
        if url.endswith(renewal.legacy.MANIFEST):
            return encoded
        if url.endswith(".intoto.jsonl"):
            return b"unit provenance"
        assert subjects == [renewal.legacy.MANIFEST]
        return archive + (b"changed" if fault == "archive" else b"")

    def verify(digest, provenance, subject, expected_source):
        assert expected_source == source and provenance == b"unit provenance"
        if fault == "signature":
            raise ValueError("untrusted publisher")
        subjects.append(subject)

    monkeypatch.setattr(renewal, "download", download)
    monkeypatch.setattr(renewal, "_verify_attested_digest", verify)
    if fault is not None:
        with pytest.raises(ValueError):
            renewal.fetch_existing(tmp_path, source, engine)
        assert not (tmp_path / "legacy").exists()
        if fault != "archive":
            assert len(downloads) == 2
    else:
        result = renewal.fetch_existing(tmp_path, source, engine)
        assert result["manifest_sha256"] == hashlib.sha256(encoded).hexdigest()
        assert result["archive_sha256"] == hashlib.sha256(archive).hexdigest()
        assert subjects == [renewal.legacy.MANIFEST, renewal.legacy.ARCHIVE]
        assert (tmp_path / "legacy" / renewal.legacy.ARCHIVE).read_bytes() == archive


def test_missing_legacy_release_is_a_cold_build_not_a_trusted_cache(renewal, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.catalog_delivery.transport import MissingReleaseError

    def missing(*args):
        raise MissingReleaseError("missing")

    monkeypatch.setattr(renewal, "download", missing)
    assert renewal.fetch_existing(tmp_path, "1" * 40, "e" * 64) is None


def test_same_source_renewal_reuses_legacy_before_resolving_mutable_logins(renewal, monkeypatch, tmp_path):
    import build_native_command_program as compiler
    import extension_delivery_legacy as legacy

    previous = {
        "status": "available",
        "manifest_sha256": "a" * 64,
        "archive_sha256": "b" * 64,
        "tag": "extension-artifacts-" + "1" * 40,
    }
    monkeypatch.setattr(legacy, "preflight", lambda *args: None)
    monkeypatch.setattr(renewal, "fetch_existing", lambda *args: previous)
    monkeypatch.setattr(
        compiler, "main", lambda *args: pytest.fail("immutable legacy snapshot must not be regenerated")
    )
    assert (
        legacy.prepare(
            tmp_path,
            tmp_path,
            tmp_path,
            {"engine": "e" * 64},
            Path("compiler"),
            "1" * 40,
            resolve_claimants=True,
            reuse_published=True,
        )
        == previous
    )


@pytest.mark.parametrize("missing", [True, False])
def test_missing_selected_root_can_rebuild_but_invalid_provenance_cannot(renewal, monkeypatch, tmp_path, missing):
    import build_extension_delivery as builder

    from codex_plugin_scanner.guard.catalog_delivery import transport

    calls = []
    monkeypatch.setattr(transport, "selected", lambda: {"source_sha": "1" * 40})

    def fetch(**kwargs):
        if missing:
            raise transport.MissingReleaseError("missing selected root")
        raise ValueError("invalid publisher signature")

    monkeypatch.setattr(transport, "fetch_root", fetch)
    monkeypatch.setattr(
        builder,
        "create_distribution",
        lambda *args, **kwargs: (
            calls.append(kwargs)
            or {
                "source_sha": "1" * 40,
                "directory": {"count": 1},
            }
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "builder",
            "--source-sha",
            "1" * 40,
            "--compiler",
            "compiler",
            "--output",
            str(tmp_path / "output"),
            "--reuse-current",
        ],
    )
    if missing:
        builder.main()
        assert len(calls) == 1 and calls[0]["existing_locations"] is None
        assert calls[0]["reuse_published_legacy"] is True
    else:
        with pytest.raises(ValueError, match="invalid publisher signature"):
            builder.main()
        assert calls == []
