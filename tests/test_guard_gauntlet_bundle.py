"""Tests for safe Gauntlet evidence transport and inline submission."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile

import pytest

from ci.gauntlet.bundle import MAX_ENTRIES, download, pack, unpack
from ci.gauntlet.case_retry import MAX_CASE_RETRIES
from ci.gauntlet.catalog import MAX_SCENARIOS


def archive(entries):
    """Return an in-memory ZIP archive containing the supplied test entries."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as result:
        for name, body in entries:
            result.writestr(name, body)
    return buffer.getvalue()


def test_public_evidence_roundtrip(tmp_path):
    """Preserve public case JSON through evidence packaging and digest-checked extraction."""
    source = tmp_path / "source"
    (source / "cases").mkdir(parents=True)
    (source / "summary.json").write_text(json.dumps({"schema": "unit-fixture"}))
    (source / "cases/ordinary.json").write_text("{}")
    output = tmp_path / "evidence.zip"
    digest = pack(source, output)
    unpack(output.read_bytes(), tmp_path / "restored", digest)
    assert (tmp_path / "restored/cases/ordinary.json").read_text() == "{}"


@pytest.mark.parametrize(
    "name", ["../outside.json", "/absolute.json", "raw-prompts.json", "runner.py", "cases\\bad.json"]
)
def test_archive_never_extracts_code_private_logs_or_path_traversal(tmp_path, name):
    """Reject disallowed archive paths before creating an extraction directory."""
    data = archive([("summary.json", "{}"), (name, "bad")])
    with pytest.raises(ValueError, match="unsafe"):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    assert not (tmp_path / "extracted").exists()


def test_archive_digest_and_symlinks_are_verified(tmp_path):
    """Reject symlink archive entries and archives with mismatched digests."""
    info = zipfile.ZipInfo("cases/link.json")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    data = archive([("summary.json", "{}"), (info, "../../outside")])
    with pytest.raises(ValueError):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match="digest"):
        unpack(data, tmp_path / "other", "0" * 64)


def test_evidence_inventory_follows_the_catalog_bound(tmp_path):
    """A run of the whole catalog, retried attempts and all, must stay importable."""
    assert MAX_ENTRIES == MAX_SCENARIOS * (1 + MAX_CASE_RETRIES) + 2
    full = (
        [("summary.json", "{}"), ("summary.md", "")]
        + [(f"cases/case-{index}.json", "{}") for index in range(MAX_SCENARIOS)]
        + [
            (f"superseded/case-{index}.attempt-{attempt}.json", "{}")
            for index in range(MAX_SCENARIOS)
            for attempt in range(1, MAX_CASE_RETRIES + 1)
        ]
    )
    assert len(full) == MAX_ENTRIES
    data = archive(full)
    unpack(data, tmp_path / "full", hashlib.sha256(data).hexdigest())
    assert len(list((tmp_path / "full/cases").iterdir())) == MAX_SCENARIOS
    over = archive([*full, ("cases/one-too-many.json", "{}")])
    with pytest.raises(ValueError, match="oversized"):
        unpack(over, tmp_path / "over", hashlib.sha256(over).hexdigest())


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/bundle.zip",
        "https://127.0.0.1/bundle.zip",
        "https://example.com/bundle.zip",
        "https://u:p@test.s3.amazonaws.com/bundle.zip",
    ],
)
def test_evidence_downloader_rejects_internal_or_unapproved_origins(url):
    """Reject evidence URLs outside the approved credential-free HTTPS origins."""
    with pytest.raises(ValueError):
        download(url)


def test_public_bundle_can_be_submitted_inline_without_storage_credentials(tmp_path):
    """Round-trip an attested inline archive and reject submission without attestation."""
    from ci.gauntlet.submission import inline_dispatch_inputs, submitted_archive

    path = tmp_path / "evidence.zip"
    path.write_bytes(archive([("summary.json", "{}")]))
    inputs = inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=True)
    assert submitted_archive(inputs) == path.read_bytes()
    assert len(json.dumps(inputs)) < 60000
    with pytest.raises(ValueError):
        inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=False)


@pytest.mark.parametrize(
    "inputs",
    [
        {},
        {"evidence_base64": "bad!"},
        {"evidence_base64": "AAAA", "evidence_url": "https://example.com"},
        {"evidence_base64": "A" * 55001},
    ],
)
def test_inline_submission_rejects_ambiguous_malformed_or_oversized_data(inputs):
    """Reject missing, conflicting, invalid or oversized inline archive inputs."""
    from ci.gauntlet.submission import submitted_archive

    with pytest.raises(ValueError):
        submitted_archive(inputs)
