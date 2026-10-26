from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard import codex_hook_recovery as recovery


@pytest.mark.parametrize("boundary", ["entry", "open", "stat", "missing"])
def test_snapshot_does_not_admit_bytes_after_original_deadline(tmp_path, monkeypatch, boundary):
    path = tmp_path / "config.toml"
    path.write_bytes(b"[features]\nhooks = true\n")
    if boundary == "missing":
        path.unlink()
    clock = [0.0]
    accepted, opened = [], []
    monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])
    original_open, original_stat = recovery.os.open, recovery.os.fstat

    def delayed_open(*args, **kwargs):
        try:
            descriptor = original_open(*args, **kwargs)
        finally:
            if boundary in {"open", "missing"}:
                clock[0] = 2.0
        opened.append(descriptor)
        return descriptor

    def delayed_stat(*args, **kwargs):
        result = original_stat(*args, **kwargs)
        if boundary == "stat":
            clock[0] = 2.0
        return result

    monkeypatch.setattr(recovery.os, "open", delayed_open)
    monkeypatch.setattr(recovery.os, "fstat", delayed_stat)
    with pytest.raises(integrity.CodexHookIntegrityError) as failure, integrity.hook_validation_deadline(1.0):
        if boundary == "entry":
            clock[0] = 2.0
        accepted.append(recovery._snapshot(path))
    assert failure.value.reason == "codex_hook_validation_deadline_expired"
    assert not accepted
    if boundary == "entry":
        assert not opened
    for descriptor in opened:
        with pytest.raises(OSError):
            original_stat(descriptor)


def test_journal_read_expiry_refuses_before_secret_or_authentication(tmp_path, monkeypatch):
    clock = [0.0]
    secret_reads = []
    monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])

    def delayed_read(*_args, **_kwargs):
        clock[0] = 2.0
        return "{}"

    def unexpected_secret(*_args, **_kwargs):
        secret_reads.append(True)
        raise AssertionError("Expired journal read must not proceed to authentication")

    monkeypatch.setattr(recovery, "read_private_regular_text", delayed_read)
    monkeypatch.setattr(recovery, "load_hook_secret", unexpected_secret)
    with pytest.raises(integrity.CodexHookIntegrityError) as failure, integrity.hook_validation_deadline(1.0):
        recovery._load_record(tmp_path)
    assert failure.value.reason == "codex_hook_validation_deadline_expired"
    assert not secret_reads
