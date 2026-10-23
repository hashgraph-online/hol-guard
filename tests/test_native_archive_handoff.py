"""Native archive admission must not hand a replaced path to a decompressor."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import zipfile

import pytest

from codex_plugin_scanner.guard.catalog_delivery import cache_io


def archive_bytes(identity, data, compression):
    output = io.BytesIO()
    member = zipfile.ZipInfo(identity + ".json")
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o400) << 16
    member.compress_type = compression
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(member, data)
    return output.getvalue()


def test_replaced_archive_cannot_start_python_decompression(tmp_path, monkeypatch, native_hook_force):
    identity = hashlib.sha256(b"{}").hexdigest()
    original = archive_bytes(identity, b"{}", zipfile.ZIP_STORED)
    replacement = archive_bytes(identity, b"A" * (4 * 1024 * 1024), zipfile.ZIP_DEFLATED)
    reference = {
        "sha256": hashlib.sha256(original).hexdigest(),
        "length": len(original),
        "location": "synthetic-archive",
    }
    directory = tmp_path / "cache"
    directory.mkdir(mode=0o700)
    calls = []

    def admitted_then_replaced(kind, **fields):
        response = subprocess.run(
            [str(native_hook_force), "pack-lifecycle", "--stdin"],
            input=json.dumps({"kind": kind, **fields}).encode(),
            capture_output=True,
            timeout=30,
        )
        assert response.returncode == 0, response.stderr.decode()
        admitted = json.loads(response.stdout)
        assert admitted["members"][0][0] == identity
        from pathlib import Path

        Path(fields["path"]).write_bytes(replacement)
        return admitted

    def forbidden_decompression(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Python decompression followed native archive admission")

    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden_decompression)
    cache_io.stage_archive(directory, reference, lambda *_: original, invoke=admitted_then_replaced)
    assert not calls
    assert (directory / "objects" / (identity + ".json")).read_bytes() == b"{}"


def native_invoke(runtime):
    def invoke(kind, **fields):
        response = subprocess.run(
            [str(runtime), "pack-lifecycle", "--stdin"],
            input=json.dumps({"kind": kind, **fields}).encode(),
            capture_output=True,
            timeout=30,
        )
        if response.returncode:
            raise ValueError(response.stderr.decode().strip())
        return json.loads(response.stdout)

    return invoke


def stage(directory, data, runtime, *, digest=None, length=None):
    reference = {
        "sha256": hashlib.sha256(data).hexdigest() if digest is None else digest,
        "length": len(data) if length is None else length,
        "location": "synthetic-archive",
    }
    cache_io.stage_archive(directory, reference, lambda *_: data, invoke=native_invoke(runtime))


def published(directory):
    return sorted(path.name for path in (directory / "objects").glob("*.json"))


def test_native_admission_publishes_exact_members_and_splits_at_member_budget(tmp_path, native_hook_force):
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore
    from codex_plugin_scanner.guard.catalog_delivery.pack_archives import parts

    store = ObjectStore(tmp_path / "source")
    identities = {store.put_json({"index": index})["sha256"] for index in range(2049)}
    archives = list(parts(store.directory, identities))
    assert [len(zipfile.ZipFile(io.BytesIO(data)).infolist()) for data in archives] == [2048, 1]
    directory = tmp_path / "cache"
    for data in archives:
        stage(directory, data, native_hook_force)
    assert published(directory) == sorted(identity + ".json" for identity in identities)
    for identity in identities:
        content = (directory / "objects" / (identity + ".json")).read_bytes()
        assert hashlib.sha256(content).hexdigest() == identity


def malformed(fault):
    content = b"{}"
    identity = hashlib.sha256(content).hexdigest()
    name = {"path": "../" + identity + ".json", "object-digest": "0" * 64 + ".json"}.get(fault, identity + ".json")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        if fault == "partial":
            first = zipfile.ZipInfo(hashlib.sha256(b"[]").hexdigest() + ".json")
            first.create_system = 3
            first.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(first, b"[]")
            name = "0" * 64 + ".json"
        row = zipfile.ZipInfo(name)
        row.create_system = 3
        row.external_attr = ((stat.S_IFLNK if fault == "mode" else stat.S_IFREG) | 0o644) << 16
        row.compress_type = zipfile.ZIP_DEFLATED if fault == "compressed" else zipfile.ZIP_STORED
        archive.writestr(row, content)
        if fault == "duplicate":
            with pytest.warns(UserWarning, match="Duplicate"):
                archive.writestr(row, content)
    data = output.getvalue()
    if fault == "footer":
        data = data[:-1]
    if fault == "tampered":
        data = data.replace(content, b"[]", 1)
    return data


@pytest.mark.parametrize(
    "fault",
    ["digest", "length", "compressed", "path", "mode", "duplicate", "object-digest", "footer", "tampered", "partial"],
)
def test_malicious_transfer_is_rejected_before_any_member_is_published(tmp_path, native_hook_force, fault):
    data = malformed(fault)
    directory = tmp_path / "cache"
    # A wrong transfer digest or length never reaches the cache; every member
    # fault is refused by native admission before any object is published.
    expected = "pack transfer integrity" if fault in {"digest", "length"} else "offline_pack_invalid"
    with pytest.raises(ValueError, match=expected):
        stage(
            directory,
            data,
            native_hook_force,
            digest="0" * 64 if fault == "digest" else None,
            length=len(data) + 1 if fault == "length" else None,
        )
    assert published(directory) == []


def test_replaced_cached_transfer_is_rechecked_natively_and_fetched_again(tmp_path, native_hook_force):
    data = malformed("valid")
    directory = tmp_path / "cache"
    digest = hashlib.sha256(data).hexdigest()
    cached = directory / "archives" / (digest + ".zip")
    cached.parent.mkdir(parents=True)
    cached.write_bytes(malformed("tampered"))
    fetched = []

    def fetch(*_):
        fetched.append(True)
        return data

    reference = {"sha256": digest, "length": len(data), "location": "synthetic-archive"}
    # Native refuses the damaged cache entry before publishing anything from it;
    # the transfer is then fetched once more instead of failing every refresh.
    cache_io.stage_archive(directory, reference, fetch, invoke=native_invoke(native_hook_force))
    assert fetched == [True]
    assert cached.read_bytes() == data
    assert published(directory) == [hashlib.sha256(b"{}").hexdigest() + ".json"]


def test_cached_transfer_refused_again_after_refetch_publishes_nothing(tmp_path, native_hook_force):
    data = malformed("compressed")
    directory = tmp_path / "cache"
    digest = hashlib.sha256(data).hexdigest()
    cached = directory / "archives" / (digest + ".zip")
    cached.parent.mkdir(parents=True)
    cached.write_bytes(data)
    with pytest.raises(ValueError, match="offline_pack_invalid"):
        stage(directory, data, native_hook_force)
    assert published(directory) == []


def test_unavailable_runtime_keeps_the_cached_transfer(tmp_path):
    data = malformed("valid")
    directory = tmp_path / "cache"
    digest = hashlib.sha256(data).hexdigest()
    cached = directory / "archives" / (digest + ".zip")
    cached.parent.mkdir(parents=True)
    cached.write_bytes(data)

    def fetch(*_):
        raise AssertionError("fetched while the runtime was unavailable")

    def unavailable(*_, **__):
        raise ValueError("native_pack_lifecycle_unavailable: source compiler timed out")

    reference = {"sha256": digest, "length": len(data), "location": "synthetic-archive"}
    with pytest.raises(ValueError, match="native_pack_lifecycle_unavailable"):
        cache_io.stage_archive(directory, reference, fetch, invoke=unavailable)
    assert cached.read_bytes() == data
    assert not (directory / "objects").exists()


@pytest.mark.parametrize(
    "reference", [{"sha256": "../" + "0" * 61, "length": 1}, {"sha256": "0" * 64, "length": 32 * 1024 * 1024 + 1}]
)
def test_unbounded_reference_is_refused_before_fetch(tmp_path, reference):
    def fetch(*_):
        raise AssertionError("fetched an unbounded transfer")

    with pytest.raises(ValueError, match="pack transfer"):
        cache_io.stage_archive(tmp_path, {**reference, "location": "synthetic"}, fetch)
    assert not (tmp_path / "archives").exists()
