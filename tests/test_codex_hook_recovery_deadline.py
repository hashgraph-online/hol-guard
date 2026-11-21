from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard import codex_hook_recovery as recovery


@pytest.mark.parametrize("present", [True, False])
def test_snapshot_does_not_admit_bytes_after_original_deadline(tmp_path, monkeypatch, present):
    path = tmp_path / "config.toml"
    if present:
        path.write_bytes(b"[features]\nhooks = true\n")
    clock = [0.0]
    accepted = []
    monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])
    with pytest.raises(integrity.CodexHookIntegrityError) as failure, integrity.hook_validation_deadline(1.0):
        clock[0] = 2.0
        accepted.append(recovery._snapshot(path))
    assert failure.value.reason == "codex_hook_validation_deadline_expired"
    assert not accepted


def test_journal_read_expiry_refuses_before_secret_or_authentication(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])
    # No key exists: an authentication attempt would fail as a missing secret.
    with pytest.raises(integrity.CodexHookIntegrityError) as failure, integrity.hook_validation_deadline(1.0):
        clock[0] = 2.0
        recovery._load_record(tmp_path)
    assert failure.value.reason == "codex_hook_validation_deadline_expired"
