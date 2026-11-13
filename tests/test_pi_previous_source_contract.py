"""The retained previous-source identity stays bound to the paths it was installed with."""

from __future__ import annotations

from pathlib import Path

from tests.pi_extension_support import previous_managed_extension_source


def _arguments(root: Path) -> dict[str, object]:
    return {
        "guard_home": root / "guard",
        "home_dir": root / "home",
        "settings_path": root / "settings.json",
        # The former combined Pi install used the Pi identity for its OMP copy.
        "harness": "pi",
        "display_name": "Pi",
    }


def test_legacy_identity_remains_bound_to_its_installation_paths(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path)
    expected = previous_managed_extension_source(**arguments)
    for field in ("guard_home", "home_dir", "settings_path"):
        assert previous_managed_extension_source(**{**arguments, field: tmp_path / "different"}) != expected
