"""Optional data-only placement for test_native_offline_cache, never a RAM bound.

Admission precedes prefetch/export/import/preparation. Package construction and
all executables stay on disk. Admission uncertainty chooses disk; failures after
yield propagate without retry. Each worker owns a private root and function case.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.offline_resource_census import census

MIB = 1024 * 1024
GIB = 1024 * MIB
SHM = Path("/dev/shm")


@dataclass(frozen=True)
class Budget:
    """Allocation allowance, not Python/native RSS or total kernel memory."""

    tree_data_bytes: int
    derived_bytes: int
    small_file_bytes: int
    metadata_reserve_bytes: int
    transient_reserve_bytes: int
    inodes: int

    @property
    def bytes(self):
        return (
            self.tree_data_bytes
            + self.derived_bytes
            + self.small_file_bytes
            + self.metadata_reserve_bytes
            + self.transient_reserve_bytes
        )


def allocation(captured: dict) -> Budget:
    """Three live trees; at most two preparations in the function-owned tree.

    cache.rs::finish: 2*(1+ceil(32768/64)) objects <=64KiB, two sets
    <=512B. Base files include ALL publication assets and one-level members.
    Small files: three roots <=64KiB, four one-byte leases (including failed
    uncached/reject roots), two sentinel copies. Thirty-two extra directories
    cover owner/case, objects/archives/sets and unsuccessful destinations.
    One page per directory/entry is an additional metadata planning allowance;
    it does not establish a complete kernel allocation bound.
    """
    page = captured["page_size"]

    def rounded(value):
        return (value + page - 1) // page * page

    files = 3 * captured["counted_file_count"] + 1028 + 3 + 4 + 2 + 1
    directories = 3 * captured["conservative_directory_count"] + 32
    return Budget(
        tree_data_bytes=3 * captured["counted_data_page_bytes"],
        derived_bytes=1026 * rounded(65536) + 2 * rounded(512),
        small_file_bytes=3 * rounded(65536) + 6 * page,
        metadata_reserve_bytes=(files + directories) * page,
        transient_reserve_bytes=rounded(32 * MIB),
        inodes=files + directories,
    )


def _workers(environment):
    value = environment.get("PYTEST_XDIST_WORKER_COUNT", "")
    if not value and "PYTEST_XDIST_WORKER" not in environment:
        return 1
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 64:
        raise ValueError("unknown worker count")
    return int(value)


def _read(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("system metadata exceeds bound")
    return data.decode("ascii")


def _host(environment):
    return (
        sys.platform == "linux"
        and environment.get("GITHUB_ACTIONS") == "true"
        and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and environment.get("RUNNER_OS") == "Linux"
        and not Path("/.dockerenv").exists()
        and not Path("/run/.containerenv").exists()
    )


def _capacity(path, page_size):
    """Read actual mount type/device, free allocation, inodes and MemAvailable."""
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("tmpfs path is aliased")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        device = os.fstat(descriptor).st_dev
        expected_device = f"{os.major(device)}:{os.minor(device)}"
        mounts = []
        for line in _read(Path("/proc/self/mountinfo"), MIB).splitlines():
            before, after = line.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            if len(fields) < 6 or len(filesystem) < 3:
                raise ValueError("invalid mount metadata")
            if fields[4] == str(path):
                mounts.append((fields, filesystem))
        if len(mounts) != 1:
            raise ValueError("ambiguous tmpfs mount")
        fields, filesystem = mounts[0]
        if fields[2] != expected_device or filesystem[0] != "tmpfs" or "rw" not in fields[5].split(","):
            raise ValueError("not a writable tmpfs")
        values = []
        for line in _read(Path("/proc/meminfo"), 65536).splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) != 3 or parts[2] != "kB" or not parts[1].isdecimal():
                    raise ValueError("invalid available memory")
                values.append(int(parts[1]) * 1024)
        if len(values) != 1:
            raise ValueError("unknown available memory")
        space = os.fstatvfs(descriptor)
        if space.f_flag & os.ST_RDONLY or space.f_frsize != page_size or space.f_favail <= 0:
            raise ValueError("unknown tmpfs capacity")
        return space.f_bavail * space.f_frsize, space.f_favail, values[0]
    finally:
        os.close(descriptor)


def _admit(publication, report, root_data, environment):
    if not _host(environment):
        return None
    if report.get("profile") != "normal" or len(root_data) > 65536:
        raise ValueError("fixture outside audited model")
    page = os.sysconf("SC_PAGE_SIZE")
    captured = census(
        publication, page_size=page, metadata_reserve_bytes=0, transient_reserve_bytes=0, standalone_fixture=True
    )
    if (
        captured["publication_files"] != report["assets"]
        or captured["asset_bytes"] != report["asset_bytes"]
        or captured["publication_root_sha256"] != hashlib.sha256(root_data).hexdigest()
    ):
        raise ValueError("fixture report differs from verified publication")
    budget = allocation(captured)
    workers = _workers(environment)
    free, inodes, available = _capacity(SHM, page)
    total = workers * budget.bytes
    # Reserve at least half each current resource and 2GiB for non-data work.
    if free < 2 * total or inodes < 2 * workers * budget.inodes or available < max(2 * total, total + 2 * GIB):
        return None
    return budget


@contextmanager
def data_owner(publication, report, root_data, disk, *, environment=None):
    """Select once before native data work; private cleanup on all exits."""
    environment = os.environ if environment is None else environment
    try:
        budget = _admit(publication, report, root_data, environment)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, zipfile.BadZipFile, zlib.error):
        budget = None
    # Allocate before yielding. There is intentionally no exception handler
    # around native work: neither a native failure nor ENOSPC triggers a retry.
    storage = "tmpfs" if budget else "disk"
    try:
        owner = tempfile.TemporaryDirectory(prefix="offline-data-", dir=SHM if budget else disk)
    except OSError:
        if budget is None:
            raise
        owner = tempfile.TemporaryDirectory(prefix="offline-data-", dir=disk)
        storage = "disk"
    with owner as directory:
        print(json.dumps({"offline_fixture_storage": storage}), flush=True)
        yield Path(directory)


@pytest.fixture(scope="module")
def offline_data_owner(packaged):
    authority, base, report = packaged
    with data_owner(base / "published", report, authority.data, base) as directory:
        yield directory


@pytest.fixture
def offline_data_path(offline_data_owner):
    # Complete + export + exactly one test-owned tree, including failed paths.
    with tempfile.TemporaryDirectory(prefix="case-", dir=offline_data_owner) as directory:
        yield Path(directory)
