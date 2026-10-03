"""The migration identity must not follow changes to the current Pi adapter."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_source as active
from codex_plugin_scanner.guard.adapters.pi_extension_legacy_source import legacy_managed_extension_source


def _arguments(root: Path) -> dict[str, object]:
    return {
        "guard_home": root / "guard",
        "home_dir": root / "home",
        "settings_path": root / "settings.json",
        # The former combined Pi install used the Pi identity for its OMP copy.
        "harness": "pi",
        "display_name": "Pi",
    }


@pytest.mark.parametrize("component", ["build_header", "build_body", "build_tail"])
def test_active_adapter_changes_cannot_break_legacy_identification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    arguments = _arguments(tmp_path)
    expected = legacy_managed_extension_source(**arguments)

    def changed_component(**_kwargs: object) -> str:
        return "// Future active adapter with a different response contract.\n"

    changed = replace(active._ACTIVE_SOURCE_VARIANT_V1, **{component: changed_component})
    monkeypatch.setattr(active, "_ACTIVE_SOURCE_VARIANT_V1", changed)
    assert "Future active adapter" in active.managed_extension_source(**arguments)
    assert legacy_managed_extension_source(**arguments) == expected


def test_active_timeout_tuning_cannot_rewrite_the_legacy_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _arguments(tmp_path)
    expected = legacy_managed_extension_source(**arguments)
    monkeypatch.setattr(
        active, "_ACTIVE_SOURCE_VARIANT_V1", replace(active._ACTIVE_SOURCE_VARIANT_V1, hook_timeout_ms=1234)
    )
    assert active.managed_extension_source(**arguments) != expected
    assert legacy_managed_extension_source(**arguments) == expected


def test_legacy_identity_remains_bound_to_its_installation_paths(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path)
    expected = legacy_managed_extension_source(**arguments)
    for field in ("guard_home", "home_dir", "settings_path"):
        assert legacy_managed_extension_source(**{**arguments, field: tmp_path / "different"}) != expected
