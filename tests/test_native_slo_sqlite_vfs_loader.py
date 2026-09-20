"""Real SQLite loader lifetime, descriptor bounds, and unchanged admission."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import native_slo_sqlite_vfs as observer_module
from scripts import native_slo_sqlite_vfs_loader as loader
from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation
from scripts.native_slo_sqlite_vfs_identity import pinned_extension
from tests.test_native_slo_sqlite_vfs import sqlite_vfs_build as sqlite_vfs_build

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or sys.version_info < (3, 12),
    reason="Linux and Python 3.12 SQLite descriptor loader required",
)


def _database(path: Path) -> Path:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("create table proof(value integer)")
        connection.commit()
    path.chmod(0o600)
    return path


def test_two_real_images_and_repeated_first_image_keep_distinct_resident_loader_aliases(tmp_path, sqlite_vfs_build):
    images = [tmp_path / "first.so", tmp_path / "second.so"]
    for image in images:
        shutil.copyfile(sqlite_vfs_build["extension"], image)
        image.chmod(0o600)
    assert images[0].stat().st_ino != images[1].stat().st_ino
    database = _database(tmp_path / "proof.db")
    reports, descriptors = [], []
    for index, image in enumerate((*images, images[0])):
        observer = SQLiteVFSObservation(
            database=database, extension=image, extension_sha256=sqlite_vfs_build["extension_sha256"]
        )
        with observer:
            with contextlib.closing(observer.connect()) as connection:
                connection.execute("insert into proof values (?)", (index,))
                connection.commit()
            identity = observer.identity["extension"]
            descriptors.append(loader._IMAGES[(identity["device"], identity["inode"])].descriptor)
        report = observer.report()
        assert report["closed"] and report["all_vfs_files_closed"]
        assert report["extension_identity_unchanged"]
        assert report["identity"]["actual_observer_mapping"]["inode"] == image.stat().st_ino
        assert report["loader"]["selected_image_descriptor_retained"]
        assert report["loader"]["selected_descriptor_close_on_exec"]
        assert report["loader"]["database_and_vfs_descriptors_included"] is False
        assert os.fstat(descriptors[-1]).st_ino == image.stat().st_ino
        assert os.get_inheritable(descriptors[-1]) is False
        reports.append(report)
    assert descriptors[0] == descriptors[2] != descriptors[1]
    assert reports[1]["loader"]["retained_image_descriptors"] == reports[0]["loader"]["retained_image_descriptors"] + 1
    assert reports[2]["loader"] == reports[1]["loader"]
    with contextlib.closing(sqlite3.connect(database)) as connection:
        assert connection.execute("select value from proof order by value").fetchall() == [(0,), (1,), (2,)]


def test_reused_loaded_image_still_requires_current_digest_and_metadata(tmp_path, sqlite_vfs_build):
    image = tmp_path / "stable.so"
    shutil.copyfile(sqlite_vfs_build["extension"], image)
    image.chmod(0o600)
    database = _database(tmp_path / "stable.db")
    digest = sqlite_vfs_build["extension_sha256"]
    with SQLiteVFSObservation(database=database, extension=image, extension_sha256=digest) as observer:
        original = observer.report()["loader"]["retained_image_descriptors"]
    with pytest.raises(ValueError, match="admitted SHA256"):
        SQLiteVFSObservation(database=database, extension=image, extension_sha256="0" * 64)
    # Changing permissions is safe for already mapped code, but invalidates its
    # prior admission identity even though the complete file digest is unchanged.
    image.chmod(0o640)
    assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
    with pytest.raises(ValueError, match="changed after its prior admission"):
        SQLiteVFSObservation(database=database, extension=image, extension_sha256=digest)
    assert len(loader._IMAGES) == original


def test_duplicate_is_closed_when_failure_precedes_the_loader_attempt(tmp_path):
    image = tmp_path / "not-loaded"
    image.write_bytes(b"not passed to the dynamic loader")
    image.chmod(0o600)
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    descriptors = []
    original_dup = os.dup
    before = len(loader._IMAGES)

    def duplicate(descriptor):
        value = original_dup(descriptor)
        descriptors.append(value)
        return value

    def reject_inheritance(_descriptor, _inheritable):
        raise RuntimeError("pre-load sentinel")

    with (
        contextlib.closing(sqlite3.connect(":memory:")) as connection,
        pinned_extension(image, expected_sha256=digest) as (descriptor, identity),
        patch.object(loader.os, "dup", duplicate),
        patch.object(loader.os, "set_inheritable", reject_inheritance),
        pytest.raises(RuntimeError, match="pre-load sentinel"),
    ):
        loader.load_verified_extension(connection, descriptor, identity)
    assert len(loader._IMAGES) == before
    assert len(descriptors) == 1
    with pytest.raises(OSError) as error:
        os.fstat(descriptors[0])
    assert error.value.errno == errno.EBADF


def test_failed_loads_are_quarantined_and_the_real_sixteen_image_cap_precedes_loading(tmp_path):
    # The cap consumes process-lifetime leases, so exercise it in an owned child
    # rather than releasing retained aliases for the other controls in this run.
    code = r"""
import hashlib, json, os, sqlite3, sys
from pathlib import Path
from scripts import native_slo_sqlite_vfs_loader as loader
from scripts.native_slo_sqlite_vfs_identity import pinned_extension
root = Path(sys.argv[1])
class Connection(sqlite3.Connection):
    calls = []
    def load_extension(self, path, *, entrypoint=None):
        self.calls.append(path)
        return super().load_extension(path, entrypoint=entrypoint)
connection = sqlite3.connect(':memory:', factory=Connection)
connection.enable_load_extension(True)
for index in range(16):
    path = root / f'invalid-{index}.so'
    path.write_bytes(f'verified owned non-ELF image {index}'.encode())
    path.chmod(0o600)
    with pinned_extension(path, expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest()) as (fd, identity):
        for attempt in range(2 if index == 0 else 1):
            try:
                loader.load_verified_extension(connection, fd, identity)
            except sqlite3.OperationalError:
                pass
            else:
                raise AssertionError('invalid ELF unexpectedly loaded')
assert connection.calls[0] == connection.calls[1]
assert len(connection.calls) == 17 and len(set(connection.calls)) == 16
assert len(loader._IMAGES) == loader.MAX_LOADER_IMAGES == 16
for image in loader._IMAGES.values():
    assert os.fstat(image.descriptor).st_ino == image.identity['inode']
    assert not os.get_inheritable(image.descriptor)
path = root / 'seventeenth.so'
path.write_bytes(b'new verified but unoffered image')
path.chmod(0o600)
with pinned_extension(path, expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest()) as (fd, identity):
    try:
        loader.load_verified_extension(connection, fd, identity)
    except ValueError as error:
        assert 'sixteen-image descriptor bound' in str(error)
    else:
        raise AssertionError('descriptor bound was not enforced')
assert len(connection.calls) == 17 and len(loader._IMAGES) == 16
connection.close()
report = loader.loader_descriptor_report(next(iter(loader._IMAGES.values())).identity, admitted_images=0)
assert report['retained_image_descriptors'] == report['unadmitted_image_descriptors'] == 16
assert report['admitted_image_descriptors'] == 0
assert report['selected_image_descriptor_retained']
print(json.dumps(report))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True, check=False, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert len(result.stdout) < 4096
    report = json.loads(result.stdout)
    assert report["descriptor_lifetime"] == "process_exit"
    assert report["maximum_retained_image_descriptors"] == report["retained_image_descriptors"] == 16
    assert report["database_and_vfs_descriptors_included"] is False


def test_failed_callback_attestation_never_enters_the_admitted_registry(tmp_path, sqlite_vfs_build):
    image = tmp_path / "failed-attestation.so"
    shutil.copyfile(sqlite_vfs_build["extension"], image)
    image.chmod(0o600)
    database = _database(tmp_path / "failure.db")
    key = (image.stat().st_dev, image.stat().st_ino)
    with (
        patch.object(observer_module, "code_mapping", return_value={"device": -1, "inode": -1}),
        pytest.raises(RuntimeError, match="verified extension inode"),
    ):
        SQLiteVFSObservation(database=database, extension=image, extension_sha256=sqlite_vfs_build["extension_sha256"])
    assert key not in observer_module._LOADED_IMAGES
    retained = loader._IMAGES[key]
    assert os.fstat(retained.descriptor).st_ino == key[1]
    with pytest.raises(ValueError, match="already mapped without admission"):
        SQLiteVFSObservation(database=database, extension=image, extension_sha256=sqlite_vfs_build["extension_sha256"])
    assert loader._IMAGES[key] is retained
