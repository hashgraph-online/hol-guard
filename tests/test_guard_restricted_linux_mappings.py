"""Privileged setup consumes exact evidence and cannot silently weaken mounts."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_linux_mappings as mapping


def _record(path):
    path.write_bytes(b"synthetic approved executable")
    return {
        "path": str(path),
        "identity": list(mapping._identity(path.stat())),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "targets": [str(path)],
    }


def test_valid_mapping_evidence_keeps_exact_targets(tmp_path):
    path = tmp_path / "approved"
    record = _record(path)
    validated = mapping.validate_records([record], approved_paths={path})
    assert validated == [(path, tuple(record["identity"]), record["sha256"], (path,))]


def test_private_snapshot_is_an_independent_complete_copy(tmp_path):
    original, copy = tmp_path / "original", tmp_path / "copy"
    record = _record(original)
    descriptor = mapping._seal_copy(original, tuple(record["identity"]), record["sha256"], copy)
    try:
        assert os.fstat(descriptor).st_ino != original.stat().st_ino
        assert copy.read_bytes() == original.read_bytes()
        assert copy.stat().st_mode & 0o777 == 0o500
        original.write_bytes(b"changed host original")
        assert copy.read_bytes() == b"synthetic approved executable"
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("mutation", ["identity", "hash", "existing-destination"])
def test_unverified_snapshot_cannot_become_a_mapping(tmp_path, mutation):
    original, copy = tmp_path / "original", tmp_path / "copy"
    record = _record(original)
    if mutation == "identity":
        original.write_bytes(b"changed")
    elif mutation == "hash":
        record["sha256"] = "0" * 64
    else:
        copy.write_bytes(b"do not overwrite")
    with pytest.raises((ValueError, OSError)):
        mapping._seal_copy(original, tuple(record["identity"]), record["sha256"], copy)
    if mutation == "existing-destination":
        assert copy.read_bytes() == b"do not overwrite"


@pytest.mark.parametrize(
    "mutation", ["extra", "relative", "parent", "unbound", "boolean", "size", "hash", "alias", "duplicate"]
)
def test_malformed_mapping_evidence_is_rejected(tmp_path, mutation):
    path = tmp_path / "approved"
    record = _record(path)
    records, approved = [record], {path}
    if mutation == "extra":
        record["override"] = True
    elif mutation == "relative":
        record["path"] = "relative"
    elif mutation == "parent":
        record["targets"] = [str(path), "/tmp/../escape"]
    elif mutation == "unbound":
        approved = set()
    elif mutation == "boolean":
        record["identity"][0] = True
    elif mutation == "size":
        record["identity"][2] = 1024**3
    elif mutation == "hash":
        record["sha256"] = "z" * 64
    elif mutation == "alias":
        record["targets"] = [str(path), str(path)]
    else:
        records.append(record)
    with pytest.raises(ValueError):
        mapping.validate_records(records, approved_paths=approved)


def test_noexec_remounts_preserve_devices_and_readonly_mounts():
    raw = (
        b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
        b"2 1 0:2 / /dev rw,nosuid - tmpfs tmpfs rw\n"
        b"3 1 0:3 / /lib ro,nodev - bind bind ro\n"
        b"4 1 0:4 / /space\\040name rw,nodev - bind bind rw\n"
    )
    targets = dict(mapping.mount_targets(raw))
    assert targets[Path("/")] == 2 | 8 | (1 << 24)
    assert targets[Path("/dev")] == 2 | 8 | (1 << 24)  # NODEV would break private null/random devices.
    assert targets[Path("/lib")] == 1 | 2 | 4 | 8 | (1 << 24)
    assert Path("/space name") in targets


@pytest.mark.parametrize(
    "options, flags",
    [
        (b"noatime", 1024),
        (b"noatime,nodiratime", 1024 | 2048),
        (b"relatime", 1 << 21),
        (b"strictatime", 1 << 24),
        (b"nodiratime", (1 << 24) | 2048),
    ],
)
def test_noexec_remount_preserves_locked_atime_flags(options, flags):
    raw = b"1 0 0:1 / / rw," + options + b" - tmpfs tmpfs rw\n"
    assert dict(mapping.mount_targets(raw))[Path("/")] == 2 | 8 | flags


@pytest.mark.parametrize("raw", [b"", b"broken", b"1 0 0:1 / / ro,rw - tmpfs tmpfs rw\n"])
def test_invalid_mount_snapshot_is_not_ignored(raw):
    with pytest.raises(ValueError):
        mapping.mount_targets(raw)


@pytest.mark.parametrize("option", [38, 47, 24])
def test_failed_capability_drop_prevents_repository_execution(option):
    def prctl(command, *args):
        return -1 if command == option else 0

    libc = SimpleNamespace(prctl=prctl)
    with pytest.raises(ValueError):
        mapping.drop_capabilities(libc)
