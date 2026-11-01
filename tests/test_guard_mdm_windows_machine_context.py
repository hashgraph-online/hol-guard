from __future__ import annotations

import csv
import os
import subprocess

import pytest

from codex_plugin_scanner.guard import windows_paths
from codex_plugin_scanner.guard.mdm import device_key_native


@pytest.fixture(autouse=True)
def _fresh_sid_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(device_key_native, "_CURRENT_USER_SID", [])


def _owner_sid(monkeypatch: pytest.MonkeyPatch, answer: str | None) -> list[None]:
    asked: list[None] = []

    def fake_owner_sid() -> str | None:
        asked.append(None)
        return answer

    monkeypatch.setattr(windows_paths, "windows_current_owner_sid", fake_owner_sid)
    return asked


def test_the_runtime_names_this_process_token_user_once(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _owner_sid(monkeypatch, "sid:S-1-5-21-1-2-3-1001")

    assert device_key_native.windows_current_user_sid() == "S-1-5-21-1-2-3-1001"
    assert device_key_native.windows_current_user_sid() == "S-1-5-21-1-2-3-1001"
    assert len(asked) == 1


def test_a_failed_read_is_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    _owner_sid(monkeypatch, None)
    with pytest.raises(OSError, match="device_key_system_context_required"):
        device_key_native.windows_current_user_sid()

    _owner_sid(monkeypatch, "sid:S-1-5-18")
    assert device_key_native.windows_current_user_sid() == "S-1-5-18"


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

    monkeypatch.setattr(device_key_native, "_CURRENT_USER_SID", [])
    _owner_sid(monkeypatch, "sid:S-1-5-21-1-2-3-1001")
    with pytest.raises(PermissionError, match="device_key_system_context_required"):
        device_key_native.require_machine_context("Windows")


def test_the_runtime_reads_its_own_token_without_a_process_id(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, object]] = []

    def fake_answer(request: dict[str, object], **_kwargs: object) -> dict[str, object] | None:
        requests.append(request)
        return {"owner_sid": "sid:S-1-5-21-7"}

    monkeypatch.setattr(windows_paths.os, "name", "nt")
    monkeypatch.setattr(windows_paths, "_lifecycle_answer", fake_answer)

    assert windows_paths.windows_current_owner_sid() == "sid:S-1-5-21-7"
    assert requests == [{"op": "current_owner_sid"}]


@pytest.mark.parametrize("owner_sid", [None, "", "sid:", "S-1-5-18", 7])
def test_a_malformed_current_owner_sid_is_no_answer(monkeypatch: pytest.MonkeyPatch, owner_sid: object) -> None:
    monkeypatch.setattr(windows_paths.os, "name", "nt")
    monkeypatch.setattr(windows_paths, "_lifecycle_answer", lambda _request, **_kwargs: {"owner_sid": owner_sid})

    assert windows_paths.windows_current_owner_sid() is None


def test_an_older_runtime_is_asked_for_this_process_by_id(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[int] = []

    def fake_owner_sid(pid: int) -> str | None:
        asked.append(pid)
        return "sid:S-1-5-21-9"

    monkeypatch.setattr(windows_paths.os, "name", "nt")
    monkeypatch.setattr(windows_paths, "_lifecycle_answer", lambda _request, **_kwargs: None)
    monkeypatch.setattr(windows_paths, "windows_process_owner_sid", fake_owner_sid)

    assert windows_paths.windows_current_owner_sid() == "sid:S-1-5-21-9"
    assert asked == [os.getpid()]


@pytest.mark.skipif(os.name != "nt", reason="needs the Windows process-lifecycle runtime")
def test_the_native_runtime_reads_this_process_token_user(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_fallback(_pid: int) -> str | None:
        raise AssertionError("the native runtime must answer without the per-process fallback")

    monkeypatch.setattr(windows_paths, "windows_process_owner_sid", no_fallback)
    monkeypatch.setattr(device_key_native, "_CURRENT_USER_SID", [])
    # `whoami` reports the SID from its own token, which is this user's.
    listed = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True, timeout=30
    ).stdout
    expected = next(csv.reader([listed.strip()]))[-1]

    assert device_key_native.windows_current_user_sid() == expected
