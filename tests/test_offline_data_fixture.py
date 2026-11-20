"""Pure tooling proofs; no native imports, mount operations or capacity claims."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import offline_data_fixture as placement


@pytest.fixture
def publication(tmp_path):
    root = tmp_path / "published"
    data = b"opaque object"
    digest = hashlib.sha256(data).hexdigest()
    asset = "object-" + digest + ".json"
    (root / "release").mkdir(parents=True)
    (root / "release" / asset).write_bytes(data)
    root_data = b"root"
    (root / "asset-plan.jsonl").write_text(
        json.dumps(
            {
                "location": {"tag": "release", "asset": asset},
                "sha256": digest,
                "length": len(data),
            }
        )
        + "\n"
    )
    (root / "installed-bundle-assets.v1.json").write_text(
        json.dumps(
            {
                "schema": "guard.installed-bundle-assets.v1",
                "source_sha": "a" * 40,
                "root_sha256": hashlib.sha256(root_data).hexdigest(),
                "asset_count": 1,
            }
        )
    )
    return root, {"profile": "normal", "assets": 1, "asset_bytes": len(data)}, root_data


def test_allocation_includes_three_trees_derived_files_metadata_and_transient():
    captured = {
        "page_size": 8192,
        "counted_file_count": 100,
        "conservative_directory_count": 7,
        "counted_data_page_bytes": 500 * 8192,
    }
    budget = placement.allocation(captured)
    assert budget.tree_data_bytes == 3 * 500 * 8192
    assert budget.derived_bytes == 1026 * 65536 + 2 * 8192
    assert budget.small_file_bytes == 3 * 65536 + 6 * 8192
    assert budget.inodes == 3 * 100 + 1028 + 3 + 4 + 2 + 1 + 3 * 7 + 32
    assert budget.metadata_reserve_bytes == budget.inodes * 8192
    assert budget.transient_reserve_bytes == 32 * placement.MIB
    assert budget.bytes > budget.tree_data_bytes + budget.derived_bytes + 32 * placement.MIB


@pytest.mark.parametrize(
    "environment,expected",
    [
        ({}, 1),
        ({"PYTEST_XDIST_WORKER_COUNT": "4"}, 4),
        ({"PYTEST_XDIST_WORKER": "gw0"}, None),
        ({"PYTEST_XDIST_WORKER_COUNT": "0"}, None),
        ({"PYTEST_XDIST_WORKER_COUNT": "65"}, None),
        ({"PYTEST_XDIST_WORKER_COUNT": "²"}, None),
    ],
)
def test_unknown_worker_concurrency_is_not_admitted(environment, expected):
    if expected is None:
        with pytest.raises(ValueError):
            placement._workers(environment)
    else:
        assert placement._workers(environment) == expected


def test_host_requires_linux_github_hosted_and_no_container(monkeypatch):
    original = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda path: False if str(path) in {"/.dockerenv", "/run/.containerenv"} else original(path)
    )
    environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
    monkeypatch.setattr(placement.sys, "platform", "linux")
    assert placement._host(environment)
    for key in environment:
        assert not placement._host({k: v for k, v in environment.items() if k != key})
    assert not placement._host({**environment, "RUNNER_ENVIRONMENT": "self-hosted"})
    monkeypatch.setattr(Path, "exists", lambda path: str(path) == "/.dockerenv")
    assert not placement._host(environment)
    monkeypatch.setattr(placement.sys, "platform", "darwin")
    assert not placement._host(environment)


def _system_metadata(monkeypatch, tmp_path, *, filesystem="tmpfs", options="rw", memory="4194304 kB"):
    device = tmp_path.stat().st_dev
    major_minor = f"{os.major(device)}:{os.minor(device)}"
    mount = f"1 0 {major_minor} / {tmp_path} {options} - {filesystem} tmpfs rw\n"
    metadata = {"/proc/self/mountinfo": mount, "/proc/meminfo": f"MemTotal: 1 kB\nMemAvailable: {memory}\n"}
    monkeypatch.setattr(placement, "_read", lambda path, limit: metadata[str(path)])
    monkeypatch.setattr(
        placement.os,
        "fstatvfs",
        lambda fd: SimpleNamespace(f_flag=0, f_frsize=4096, f_favail=1000000, f_bavail=1000000),
    )
    return metadata


def test_actual_descriptor_capacity_is_bound_to_mount_device_and_memavailable(monkeypatch, tmp_path):
    metadata = _system_metadata(monkeypatch, tmp_path)
    assert placement._capacity(tmp_path, 4096) == (4096000000, 1000000, 4 * placement.GIB)
    metadata["/proc/self/mountinfo"] = metadata["/proc/self/mountinfo"].replace(" tmpfs ", " ext4 ")
    with pytest.raises(ValueError, match="tmpfs"):
        placement._capacity(tmp_path, 4096)


@pytest.mark.parametrize("fault", ["device", "duplicate-mount", "readonly", "no-memory", "bad-memory", "no-inodes"])
def test_uncertain_system_capacity_is_rejected(monkeypatch, tmp_path, fault):
    metadata = _system_metadata(monkeypatch, tmp_path)
    if fault == "device":
        fields = metadata["/proc/self/mountinfo"].split()
        fields[2] = "999:999"
        metadata["/proc/self/mountinfo"] = " ".join(fields)
    elif fault == "duplicate-mount":
        metadata["/proc/self/mountinfo"] *= 2
    elif fault == "readonly":
        metadata["/proc/self/mountinfo"] = metadata["/proc/self/mountinfo"].replace(" rw ", " ro ", 1)
    elif fault == "no-memory":
        metadata["/proc/meminfo"] = "MemTotal: 1 kB\n"
    elif fault == "bad-memory":
        metadata["/proc/meminfo"] = "MemAvailable: 10 MB\n"
    else:
        monkeypatch.setattr(placement.os, "fstatvfs", lambda fd: SimpleNamespace(f_flag=0, f_frsize=4096, f_favail=0))
    with pytest.raises(ValueError):
        placement._capacity(tmp_path, 4096)


def test_bounded_system_reads_and_alias_rejection(tmp_path):
    source = tmp_path / "metadata"
    source.write_bytes(b"a" * 9)
    with pytest.raises(ValueError, match="bound"):
        placement._read(source, 8)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="aliased"):
        placement._capacity(alias, 4096)


def test_mismatched_tmpfs_allocation_unit_falls_back_before_data_work(monkeypatch, publication, tmp_path):
    fake_tmpfs, disk = tmp_path / "fake-tmpfs", tmp_path / "disk"
    fake_tmpfs.mkdir()
    disk.mkdir()
    _system_metadata(monkeypatch, fake_tmpfs)
    monkeypatch.setattr(placement, "SHM", fake_tmpfs)
    monkeypatch.setattr(placement, "_host", lambda env: True)
    monkeypatch.setattr(
        placement.os,
        "fstatvfs",
        lambda fd: SimpleNamespace(
            f_flag=0, f_frsize=2 * os.sysconf("SC_PAGE_SIZE"), f_favail=1000000, f_bavail=1000000
        ),
    )
    with placement.data_owner(*publication, disk) as directory:
        assert directory.parent == disk
        assert list(fake_tmpfs.iterdir()) == []


def test_admission_checks_verified_current_assets_root_report_and_each_resource(monkeypatch, publication):
    root, report, data = publication
    monkeypatch.setattr(placement, "_host", lambda env: True)
    monkeypatch.setattr(placement, "_capacity", lambda path, page: (10**12, 10**9, 10**12))
    budget = placement._admit(root, report, data, {"PYTEST_XDIST_WORKER_COUNT": "4"})
    assert budget is not None
    required = 4 * budget.bytes
    for capacity in [
        (2 * required - 1, 10**9, 10**12),
        (10**12, 8 * budget.inodes - 1, 10**12),
        (10**12, 10**9, required + 2 * placement.GIB - 1),
    ]:
        monkeypatch.setattr(placement, "_capacity", lambda path, page, value=capacity: value)
        assert placement._admit(root, report, data, {"PYTEST_XDIST_WORKER_COUNT": "4"}) is None
    for changed, root_data in [
        ({**report, "profile": "complete-offline"}, data),
        ({**report, "assets": 2}, data),
        (report, b"wrong root"),
    ]:
        with pytest.raises(ValueError):
            placement._admit(root, changed, root_data, {})
    next((root / "release").iterdir()).write_bytes(b"mutated")
    with pytest.raises(ValueError):
        placement._admit(root, report, data, {})


def test_disk_fallback_precedes_work_and_private_roots_cleanup(monkeypatch, publication, tmp_path):
    disk = tmp_path / "disk"
    disk.mkdir()
    monkeypatch.setattr(placement, "_admit", lambda *args: (_ for _ in ()).throw(ValueError("uncertain")))
    with placement.data_owner(*publication, disk, environment={}) as first:
        assert first.parent == disk
        with placement.data_owner(*publication, disk, environment={}) as second:
            assert first != second
            (second / "data").write_text("private")
        assert not second.exists()
    assert not first.exists()


def test_tmpfs_choice_native_failure_propagates_once_without_disk_retry(monkeypatch, publication, tmp_path):
    fake_tmpfs, disk = tmp_path / "fake-tmpfs", tmp_path / "disk"
    fake_tmpfs.mkdir()
    disk.mkdir()
    monkeypatch.setattr(placement, "SHM", fake_tmpfs)
    calls = []
    monkeypatch.setattr(placement, "_admit", lambda *args: calls.append("admitted") or True)
    with pytest.raises(RuntimeError, match="native failure"), placement.data_owner(*publication, disk) as directory:
        assert directory.parent == fake_tmpfs
        calls.append("native")
        raise RuntimeError("native failure")
    assert calls == ["admitted", "native"]
    assert not directory.exists() and list(disk.iterdir()) == []


def test_only_prework_tmpfs_creation_failure_can_fallback(monkeypatch, publication, tmp_path):
    disk = tmp_path / "disk"
    disk.mkdir()
    monkeypatch.setattr(placement, "_admit", lambda *args: True)
    create = placement.tempfile.TemporaryDirectory
    calls = []

    def allocate(*args, **kwargs):
        calls.append(kwargs["dir"])
        if kwargs["dir"] == placement.SHM:
            raise OSError("no capacity")
        return create(*args, **kwargs)

    monkeypatch.setattr(placement.tempfile, "TemporaryDirectory", allocate)
    with placement.data_owner(*publication, disk) as directory:
        assert directory.parent == disk
    assert calls == [placement.SHM, disk]


def test_function_case_cleanup_bounds_retained_trees_even_on_exception(tmp_path):
    for _ in range(4):
        generator = placement.offline_data_path.__wrapped__(tmp_path)
        directory = next(generator)
        (directory / "device").mkdir()
        (directory / "device" / "object").write_bytes(b"data")
        assert len(list(tmp_path.iterdir())) == 1
        with pytest.raises(RuntimeError):
            generator.throw(RuntimeError("test failed"))
        assert not directory.exists()


def test_source_package_sql_and_unrelated_test_paths_remain_disk():
    tree = ast.parse(Path(__file__).with_name("test_native_offline_cache.py").read_text())
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    packaged = functions["packaged"]
    assert "offline_data_owner" not in {node.id for node in ast.walk(packaged) if isinstance(node, ast.Name)}
    sql = functions["test_production_cleanup_captures_sql_pins_and_rejects_sql_loss"]
    assert "tmp_path" in {node.arg for node in sql.args.args}
    assert not {"offline_data_owner", "offline_data_path"} & {node.arg for node in sql.args.args}
    for name, node in functions.items():
        if "malicious_zip" in name or "unsigned_authority" in name:
            assert "offline_data_path" not in {node.arg for node in node.args.args}
