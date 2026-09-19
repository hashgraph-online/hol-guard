"""Pin collector Windows helpers while keeping the installed baseline separate."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import installed_transition_quiescence as proof
from scripts.ci.installed_transition_windows_api import private_file_api, source_module
from scripts.ci.installed_transition_windows_owner import _Accounting, _FileTime

_ROOT = Path(__file__).resolve().parents[1]
_WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows private file handles")


def test_collector_helpers_do_not_import_or_replace_installed_baseline_modules():
    code = """
import importlib.abc, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
class RejectInstalledModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'codex_plugin_scanner' or fullname.startswith('codex_plugin_scanner.'):
            raise ModuleNotFoundError(fullname)
sys.meta_path.insert(0, RejectInstalledModules())
from scripts.ci.installed_transition_windows_api import private_file_api, source_module
api = private_file_api()
assert private_file_api() is api
assert callable(api._windows_read_snapshot_bytes)
assert callable(api._windows_write_private_file_atomic)
paths = source_module('guard.windows_paths')
assert Path(paths.__file__).resolve() == Path(sys.argv[1]) / 'src/codex_plugin_scanner/guard/windows_paths.py'
assert not any(name == 'codex_plugin_scanner' or name.startswith('codex_plugin_scanner.') for name in sys.modules)
print(json.dumps({'installed_baseline_modules_loaded': False}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(_ROOT)],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == {"installed_baseline_modules_loaded": False}


def test_fixed_windows_kernel_structures_have_the_documented_widths():
    assert ctypes.sizeof(_Accounting) == 48
    assert _Accounting.total.offset == 36
    assert _Accounting.active.offset == 40
    assert _Accounting.terminated.offset == 44
    assert ctypes.sizeof(_FileTime) == 8


@pytest.mark.parametrize("changed_reason", [False, True])
def test_job_boundary_cannot_reclassify_a_different_legacy_start_failure(changed_reason):
    from tests.test_installed_transition_quiescence import _certified_report

    report = _certified_report()
    report["quiescence"].update(
        mechanism="windows_job_object",
        platform="win32",
        job_empty_before_close=True,
        breakaway_disabled=True,
        total_process_count=3,
        termination_requests=0,
        limit_terminated_count=0,
    )
    if changed_reason:
        report["failure"]["reason"] = "qualification_initial_capacity_not_ready"
        report["quiescence"]["worker_report_sha256"] = proof.digest_json(
            {
                key: value
                for key, value in report.items()
                if key not in {"quiescence", "cleanup_confirmed", "rejected_legacy_start_verified"}
            }
            | {"cleanup_confirmed": False}
        )
    assert proof.certificate_valid(report, prior_retirement_sha256="d" * 64) is (not changed_reason)
    assert report["retirement_verification"]["verified"] is False


@_WINDOWS
def test_private_checkpoint_roundtrip_and_replacement_use_actual_handles(tmp_path):
    path = tmp_path / "private" / "checkpoint.json"
    proof.write_private(path, {"phase": "candidate_reinstall", "nonce": "a" * 64})
    first = proof.file_pin(path)
    assert proof.private_json(path)["phase"] == "candidate_reinstall"
    private_file_api()._windows_verify_private_file(path)
    proof.write_private(path, {"phase": "baseline_rollback", "nonce": "b" * 64})
    second = proof.file_pin(path)
    assert proof.private_json(path) == {"phase": "baseline_rollback", "nonce": "b" * 64}
    assert first["sha256"] != second["sha256"]
    assert not path.with_suffix(".pending").exists()


@_WINDOWS
def test_file_pin_handle_prevents_concurrent_path_replacement(tmp_path):
    path = tmp_path / "private" / "checkpoint.json"
    proof.write_private(path, {"nonce": "a" * 64})
    replacement = path.with_name("replacement.json")
    proof.write_private(replacement, {"nonce": "b" * 64})
    descriptor = source_module("guard.windows_paths").open_windows_locked_regular_descriptor(path)
    try:
        with pytest.raises(OSError):
            replacement.replace(path)
        assert os.read(descriptor, 512) == path.read_bytes()
    finally:
        os.close(descriptor)
    replacement.replace(path)
    assert proof.private_json(path) == {"nonce": "b" * 64}


@_WINDOWS
def test_private_state_rejects_directory_and_oversized_bytes(tmp_path):
    root = tmp_path / "private"
    root.mkdir()
    error = source_module("guard.native_policy_snapshot_constants").NativePolicySnapshotError
    with pytest.raises(error):
        proof.private_json(root)
    with pytest.raises(ValueError, match="file_limit"):
        proof.write_private(root / "checkpoint.json", {"value": "x" * proof._STATE_LIMIT})


@pytest.mark.parametrize("mutation", [None, "breakaway", "early_close", "forced", "limit_kill", "wrong_platform"])
def test_windows_kernel_certificate_requires_unforced_empty_nonbreakaway_job(mutation):
    evidence = {
        "mechanism": "windows_job_object",
        "platform": "win32",
        "job_empty_before_close": True,
        "breakaway_disabled": True,
        "total_process_count": 3,
        "termination_requests": 0,
        "limit_terminated_count": 0,
    }
    if mutation is not None:
        field, value = {
            "breakaway": ("breakaway_disabled", False),
            "early_close": ("job_empty_before_close", False),
            "forced": ("termination_requests", 1),
            "limit_kill": ("limit_terminated_count", 1),
            "wrong_platform": ("platform", "darwin"),
        }[mutation]
        evidence[field] = value
    assert proof._kernel_valid(evidence) is (mutation is None)
