"""Settings reset must obey the same bounded revision contract as mode writes."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config, reset_guard_settings, update_guard_settings
from codex_plugin_scanner.guard.presentation_settings import (
    PresentationSettingsUpdate,
    apply_presentation_settings_update,
    next_presentation_revision,
)

MAX_REVISION = 2**53 - 1


def _config(home: Path, revision: int) -> Path:
    home.mkdir()
    path = home / "config.toml"
    path.write_text(
        'presentation_mode = "technical"\n'
        "presentation_mode_explicit = true\n"
        f"presentation_revision = {revision}\n"
        'security_level = "strict"\n'
        'sandbox_analysis = "suspicious"\n',
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("revision", [MAX_REVISION, MAX_REVISION + 1])
def test_reset_rejects_exhausted_revision_without_changing_any_settings(tmp_path: Path, revision: int) -> None:
    home = tmp_path / "guard"
    path = _config(home, revision)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="revision is exhausted"):
        reset_guard_settings(home)
    assert path.read_bytes() == before
    config = load_guard_config(home)
    assert (config.presentation_mode, config.presentation_revision, config.security_level) == (
        "technical",
        revision,
        "strict",
    )
    assert config.sandbox_analysis == "suspicious"
    assert not list(home.glob(".config-*"))


def test_reset_can_use_last_safe_revision_but_cannot_wrap_or_reuse_it(tmp_path: Path) -> None:
    home = tmp_path / "guard"
    path = _config(home, MAX_REVISION - 1)
    reset = reset_guard_settings(home)
    assert (reset.presentation_mode, reset.presentation_revision, reset.presentation_mode_explicit) == (
        "everyday",
        MAX_REVISION,
        False,
    )
    assert reset.sandbox_analysis == "suspicious"
    before = path.read_bytes()
    with pytest.raises(ValueError, match="revision is exhausted"):
        reset_guard_settings(home)
    with pytest.raises(ValueError, match="another surface"):
        update_guard_settings(home, {"presentation_mode": "technical", "presentation_revision": MAX_REVISION - 1})
    assert path.read_bytes() == before


@pytest.mark.parametrize("revision", [0, MAX_REVISION - 1])
def test_revision_increment_stays_in_wire_range(revision: int) -> None:
    assert next_presentation_revision(revision) == revision + 1


@pytest.mark.parametrize("revision", [MAX_REVISION, MAX_REVISION + 1])
def test_exhausted_increment_does_not_partially_change_projection(revision: int) -> None:
    payload = {"presentation_mode": "everyday", "security_level": "strict", "presentation_revision": revision}
    before = dict(payload)
    update = PresentationSettingsUpdate(requested=True, changed=True, mode="technical", explicit=True)
    with pytest.raises(ValueError, match="revision is exhausted"):
        apply_presentation_settings_update(payload, update, current_revision=revision)
    assert payload == before
