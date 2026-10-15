"""Private native index transport remains bounded and terminal on corruption."""

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_linux as transport
from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError


def test_large_native_index_uses_one_small_reply_and_cleans_private_snapshot(monkeypatch, tmp_path):
    rows = [{"path": "/workspace/" + "package/" * 80 + str(i), "device": 1, "inode": i} for i in range(5000)]
    raw = json.dumps(rows).encode()
    assert len(raw) > 2 * 1024 * 1024
    snapshots = []

    def native(operation, fields, expected):
        assert operation == "linux_read_grants"
        snapshot = fields["result_snapshot"]
        assert snapshot.parent.stat().st_mode & 0o077 == 0
        snapshot.write_bytes(raw)
        snapshot.chmod(0o600)
        snapshots.append(snapshot)
        return {"decoded_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    monkeypatch.setattr(transport, "linux_native", native)
    assert transport.read_grants(tmp_path, 240_000) == rows
    assert not snapshots[0].exists()


@pytest.mark.parametrize("corruption", ["digest", "length", "budget", "type", "inode"])
def test_native_index_transport_never_returns_corrupted_grants(monkeypatch, tmp_path, corruption):
    def native(operation, fields, expected):
        row = {"path": "/workspace/file", "device": 1, "inode": True if corruption == "inode" else 2}
        raw = json.dumps([row]).encode()
        fields["result_snapshot"].write_bytes(raw)
        fields["result_snapshot"].chmod(0o600)
        return {
            "decoded_bytes": True
            if corruption == "type"
            else (64 * 1024 * 1024 + 1 if corruption == "budget" else len(raw) + (corruption == "length")),
            "sha256": "0" * 64 if corruption == "digest" else hashlib.sha256(raw).hexdigest(),
        }

    monkeypatch.setattr(transport, "linux_native", native)
    with pytest.raises(LinuxContainmentUnavailableError, match="transport"):
        transport.read_grants(tmp_path, 240_000)


def test_namespace_transport_failure_has_no_python_policy_fallback(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.runtime import restricted_linux_namespace as namespace
    from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestPlan

    plan = RestrictedPytestPlan(
        profile_version="pytest-readonly-v2",
        backend="linux-bubblewrap",
        backend_executable=Path("/usr/bin/bwrap"),
        workspace=tmp_path,
        cwd=tmp_path,
        command=("/usr/bin/python",),
        executable=Path("/usr/bin/python"),
        allowed_executables=(Path("/usr/bin/python"),),
        denied_capabilities=(),
    )

    def unavailable(*args, **kwargs):
        raise LinuxContainmentUnavailableError("native unavailable")

    monkeypatch.setattr(namespace, "linux_native", unavailable)
    with pytest.raises(LinuxContainmentUnavailableError, match="unavailable"):
        namespace.linux_readonly_argv(plan, private_root=tmp_path)
