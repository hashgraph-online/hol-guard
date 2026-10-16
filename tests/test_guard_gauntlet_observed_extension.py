"""Gauntlet extensions carry each hook on the transport an install would use."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ci.gauntlet import observed_extension
from codex_plugin_scanner.guard.adapters.pi_extension_native_hook import PI_HOOK_BRIDGE_SWITCH


def test_the_extension_keeps_the_transport_the_installed_runtime_chooses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Forcing the loopback fetch here would hide the native bridge, which is the
    # lane installed users actually run; observer.ts records both.
    seen: list[str | None] = []

    def generate(extension: Path, **_: object) -> None:
        seen.append(os.environ.get(PI_HOOK_BRIDGE_SWITCH))

    monkeypatch.delenv(PI_HOOK_BRIDGE_SWITCH, raising=False)
    monkeypatch.setattr(observed_extension.probe, "_generate_extension", generate)
    observed_extension.generate_observed_extension(
        tmp_path / "guard.ts", guard_home=tmp_path, home=tmp_path, settings_path=tmp_path / "settings.json"
    )
    assert seen == [None]
    assert PI_HOOK_BRIDGE_SWITCH not in os.environ


def test_the_bridge_runtime_is_withheld_under_the_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters import pi_extension_native_hook

    monkeypatch.setenv(PI_HOOK_BRIDGE_SWITCH, "fetch")
    assert pi_extension_native_hook.pi_native_hook_runtime(guard_home=Path("/nonexistent")) is None
