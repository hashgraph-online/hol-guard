from __future__ import annotations

import os

import pytest

from codex_plugin_scanner.guard import windows_paths
from codex_plugin_scanner.guard.mdm import device_key_native


def _owner_sid(monkeypatch: pytest.MonkeyPatch, answer: str | None) -> list[int]:
    asked: list[int] = []

    def fake_owner_sid(pid: int) -> str | None:
        asked.append(pid)
        return answer

    monkeypatch.setattr(windows_paths, "windows_process_owner_sid", fake_owner_sid)
    return asked


def test_the_runtime_names_this_process_token_user(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _owner_sid(monkeypatch, "sid:S-1-5-21-1-2-3-1001")

    assert device_key_native.windows_current_user_sid() == "S-1-5-21-1-2-3-1001"
    assert asked == [os.getpid()]


@pytest.mark.parametrize("answer", [None, "sid:", "sid:S-1-", "sid:not-a-sid", "S-1-5-18x"])
def test_a_missing_or_malformed_owner_sid_requires_system_context(
    monkeypatch: pytest.MonkeyPatch, answer: str | None
) -> None:
    _owner_sid(monkeypatch, answer)

    with pytest.raises(OSError, match="device_key_system_context_required"):
        device_key_native.windows_current_user_sid()


def test_windows_machine_context_needs_the_system_account(monkeypatch: pytest.MonkeyPatch) -> None:
    _owner_sid(monkeypatch, "sid:S-1-5-18")
    device_key_native.require_machine_context("Windows")

    _owner_sid(monkeypatch, "sid:S-1-5-21-1-2-3-1001")
    with pytest.raises(PermissionError, match="device_key_system_context_required"):
        device_key_native.require_machine_context("Windows")


@pytest.mark.skipif(os.name != "nt", reason="needs the Windows process-lifecycle runtime")
def test_the_native_runtime_reads_this_process_token_user() -> None:
    assert device_key_native.windows_current_user_sid().startswith("S-1-5-")
