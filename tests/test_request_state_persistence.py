"""A replayed request must not succeed when its consumed nonce cannot be saved."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.routes import request_state


def test_a_failed_replace_raises_and_leaves_no_temporary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = request_state._ReplayState(tmp_path)

    def refuse(*_args: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(request_state.os, "replace", refuse)
    with pytest.raises(OSError):
        state.set("package_firewall_session_nonces", {"n": 1})
    assert [path.name for path in tmp_path.iterdir() if path.name.startswith(".")] == []


def test_an_oversized_state_raises_instead_of_dropping_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = request_state._ReplayState(tmp_path)
    monkeypatch.setattr(request_state, "_STATE_LIMIT_BYTES", 8)
    with pytest.raises(OSError):
        state.set("package_firewall_session_nonces", {"nonce": "consumed"})


def test_a_saved_value_reads_back(tmp_path: Path) -> None:
    state = request_state._ReplayState(tmp_path)
    state.set("package_firewall_session_nonces", {"n": 1})
    assert state.get("package_firewall_session_nonces") == {"n": 1}
