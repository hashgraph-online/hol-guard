"""The requests the Muse and Devin settings shim sends the native kind, and the answers it refuses."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import harness_hook_settings as settings
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime_transition import TransitionFile

_TEXT = '{\n  "hooks": {}\n}\n'
_STATE = '{\n  "managed_settings_path": "x"\n}\n'


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: dict[str, object]) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    queue = list(answers)

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        assert kind == "harness_settings_file"
        sent.append(request)
        return queue.pop(0)

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _install(
    tmp_path: Path, harness: settings.HookHarness = "muse", before: bytes | None = b"{}"
) -> tuple[tuple[TransitionFile, ...], list[str]]:
    config = tmp_path / "settings.json"
    if before is not None:
        config.write_bytes(before)
        config.chmod(0o640)
    return settings.prepare_settings_install(
        harness,
        config_path=config,
        config_before=before,
        backup_path=tmp_path / "state" / "settings.json.backup",
        state_path=tmp_path / "state" / "install.state.json",
        command="guard hook",
        timing_seconds=35,
    )


def test_install_sends_the_captured_bytes_and_builds_the_three_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _fake(monkeypatch, {"text": _TEXT, "state": _STATE, "notes": ["added"]})

    files, notes = _install(tmp_path, before=b"{\xff}")

    assert sent == [
        {
            "op": "install",
            "harness": "muse",
            "content": base64.b64encode(b"{\xff}").decode("ascii"),
            "config_path": str(tmp_path / "settings.json"),
            "command": "guard hook",
            "bridge_seconds": 35,
        }
    ]
    assert notes == ["added"]
    backup, config, state = files
    # A first install backs up the settings it found, with their mode.
    assert (backup.before, backup.after, backup.after_mode) == (None, b"{\xff}", 0o640)
    assert (config.before, config.after, config.after_mode) == (b"{\xff}", _TEXT.encode(), 0o640)
    assert (state.before, state.after, state.after_mode) == (None, _STATE.encode(), 0o600)


def test_devin_install_without_a_file_sends_null_and_its_wait(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _fake(monkeypatch, {"text": _TEXT, "state": _STATE, "notes": []})

    files, _notes = _install(tmp_path, "devin", None)

    assert sent[0]["content"] is None
    assert sent[0]["wait_seconds"] == 35
    assert "bridge_seconds" not in sent[0]
    assert files[1].after_mode == 0o600


def test_an_install_refusal_raises_its_message(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, {"refusal": "Muse settings must be a JSON object before installation."})

    with pytest.raises(ValueError, match="must be a JSON object") as refused:
        _install(tmp_path)
    assert not isinstance(refused.value, NativeRunnerAuthorityError)


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"refusal": 5},
        {"refusal": "x", "text": _TEXT},
        {"text": _TEXT, "state": _STATE},
        {"text": _TEXT, "state": _STATE, "notes": "x"},
        {"text": _TEXT, "state": _STATE, "notes": [5]},
        {"text": None, "state": _STATE, "notes": []},
        {"text": _TEXT, "state": None, "notes": []},
        {"text": _TEXT, "state": _STATE, "notes": [], "extra": 1},
    ],
)
def test_malformed_install_answers_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        _install(tmp_path)


@pytest.mark.parametrize(
    "answer",
    [
        {"text": None},
        {"text": 5, "notes": []},
        {"text": None, "notes": [], "state": _STATE},
        {"refusal": "x"},
    ],
)
def test_malformed_uninstall_answers_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        settings.plan_settings_uninstall("devin", tmp_path / "config.json")


def test_uninstall_tells_a_missing_file_from_an_unreadable_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _fake(monkeypatch, {"text": None, "notes": ["a"]}, {"text": _TEXT, "notes": ["b"]})
    config = tmp_path / "config.json"

    assert settings.plan_settings_uninstall("devin", config) == (None, ["a"])
    config.write_bytes(b"{}")
    assert settings.plan_settings_uninstall("devin", config) == (_TEXT, ["b"])
    assert sent == [
        {"op": "uninstall", "harness": "devin", "content": None, "present": False},
        {"op": "uninstall", "harness": "devin", "content": base64.b64encode(b"{}").decode("ascii"), "present": True},
    ]


@pytest.mark.parametrize("adapter_name", ["muse", "devin"])
def test_a_refused_uninstall_prune_leaves_the_launcher_and_settings(
    adapter_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.adapters import devin, muse
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    module = muse if adapter_name == "muse" else devin
    adapter = muse.MuseHarnessAdapter() if adapter_name == "muse" else devin.DevinHarnessAdapter()
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config = adapter._user_settings_path(context) if adapter_name == "muse" else adapter._user_config_path(context)  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
    config.parent.mkdir(parents=True)
    original = json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "echo user"}]}]}})
    config.write_text(original, encoding="utf-8")
    removed: list[str] = []
    monkeypatch.setattr(module, "remove_guard_shim", lambda *_args, **_kwargs: removed.append("shim"))
    asked: list[str] = []

    def refuse(kind: str, _request: dict[str, object]) -> dict[str, object]:
        asked.append(kind)
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", refuse)
    with pytest.raises(NativeRunnerAuthorityError):
        adapter.uninstall(context)
    assert asked == ["harness_settings_file"]
    assert removed == []
    assert config.read_text(encoding="utf-8") == original
