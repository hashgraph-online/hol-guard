"""Parity and fail-closed behavior of the native Guard configuration loader."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_guard_config
from codex_plugin_scanner.guard.config import ConfigFileTrustError, load_guard_config
from codex_plugin_scanner.guard.native_guard_config import (
    clear_native_guard_config_memo,
    load_native_guard_config,
)

_CASES = json.loads((Path(__file__).parent / "fixtures" / "guard_config_parity.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _fresh_memo() -> None:
    clear_native_guard_config_memo()


def _prepare(root: Path, case: dict[str, object]) -> tuple[Path, Path | None]:
    (root / "home").mkdir()
    (root / "ws").mkdir()
    files = case["files"]
    assert isinstance(files, dict)
    for relative, text in files.items():
        (root / relative).write_text(text, encoding="utf-8")
    workspace = root / "ws" if any(key.startswith("ws/") for key in files) else None
    return root / "home", workspace


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_native_loader_matches_recorded_python_results(tmp_path: Path, case: dict[str, object]) -> None:
    guard_home, workspace = _prepare(tmp_path, case)
    expected = case["expected"]
    assert isinstance(expected, dict)
    if "config" in expected:
        loaded = load_native_guard_config(
            guard_home, workspace, require_canonical_workspace=False, managed=case["managed"]
        )
        assert loaded == expected["config"]
    else:
        with pytest.raises(ConfigFileTrustError):
            load_native_guard_config(guard_home, workspace, require_canonical_workspace=False, managed=case["managed"])


def test_load_guard_config_builds_dataclass_from_native_fields(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text('mode = "enforce"\nsecurity_level = "strict"\n', encoding="utf-8")

    config = load_guard_config(tmp_path)

    assert config.mode == "enforce"
    assert config.security_level == "strict"
    assert isinstance(config.runtime_detector_disabled_ids, tuple)


def test_loader_fails_closed_when_runtime_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.native_runtime._run_native_process", lambda *a, **k: None)
    with pytest.raises(ConfigFileTrustError):
        load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)


def test_loader_rejects_malformed_native_responses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for output in (
        "not json",
        "[]",
        '{"ok":true}',
        '{"ok":true,"config":[]}',
        '{"ok":false,"error":"config_malformed"}',
    ):
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.native_runtime._run_native_process", lambda *a, _o=output, **k: _o
        )
        with pytest.raises(ConfigFileTrustError):
            load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)


def _age_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend a minute has passed so freshly written files leave the racy window."""

    real = time.time_ns
    monkeypatch.setattr(native_guard_config, "time", SimpleNamespace(time_ns=lambda: real() + 60_000_000_000))


def test_unchanged_old_config_is_served_from_memo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('mode = "enforce"\n', encoding="utf-8")
    _age_clock(monkeypatch)
    calls: list[str] = []
    real_spawn = native_guard_config._spawn

    def counting_spawn(request_text: str) -> dict[str, object]:
        calls.append(request_text)
        return real_spawn(request_text)

    monkeypatch.setattr(native_guard_config, "_spawn", counting_spawn)

    first = load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)
    second = load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)
    second["mode"] = "mutated"
    third = load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)

    assert len(calls) == 1
    assert first["mode"] == "enforce"
    assert third["mode"] == "enforce"

    config_path.write_text('mode = "observe"\n', encoding="utf-8")
    changed = load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)
    assert changed["mode"] == "observe"
    assert len(calls) == 2


def test_freshly_written_config_is_never_memoized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "config.toml").write_text('mode = "enforce"\n', encoding="utf-8")
    calls: list[str] = []
    real_spawn = native_guard_config._spawn
    monkeypatch.setattr(native_guard_config, "_spawn", lambda text: (calls.append(text), real_spawn(text))[1])

    load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)
    load_native_guard_config(tmp_path, None, require_canonical_workspace=False, managed=None)

    assert len(calls) == 2
