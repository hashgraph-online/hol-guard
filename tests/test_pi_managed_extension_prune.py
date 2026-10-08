"""Pi managed extension cleanup regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_support import enable_managed_extension


def test_enable_managed_extension_prunes_stale_hol_guard_extensions(tmp_path: Path) -> None:
    settings_path = tmp_path / ".pi" / "agent" / "settings.json"
    current_extension = tmp_path / ".pi" / "agent" / "extensions" / "hol-guard.ts"
    stale_global_extension = tmp_path / ".pi" / "old" / "extensions" / "hol-guard.ts"
    stale_project_extension = tmp_path / "project" / ".pi" / "extensions" / "hol-guard.ts"
    custom_extension = tmp_path / ".pi" / "agent" / "extensions" / "custom.ts"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "extensions": [
                    str(stale_global_extension),
                    str(custom_extension),
                    str(stale_project_extension),
                ],
            }
        ),
        encoding="utf-8",
    )

    enable_managed_extension(settings_path=settings_path, extension_path=current_extension)

    extensions = json.loads(settings_path.read_text(encoding="utf-8"))["extensions"]
    assert extensions == [str(custom_extension), str(current_extension)]


def test_enable_managed_extension_rejects_symlink_and_foreign_name(tmp_path: Path) -> None:
    settings_path = tmp_path / ".pi" / "agent" / "settings.json"
    other = tmp_path / "elsewhere.json"
    settings_path.parent.mkdir(parents=True)
    other.write_text("{}", encoding="utf-8")
    settings_path.symlink_to(other)
    extension = tmp_path / "hol-guard.ts"
    with pytest.raises(ValueError, match="settings path"):
        enable_managed_extension(settings_path=settings_path, extension_path=extension)
    assert other.read_text(encoding="utf-8") == "{}"

    foreign = tmp_path / "notes.txt"
    with pytest.raises(ValueError, match="settings path"):
        enable_managed_extension(settings_path=foreign, extension_path=extension)
    assert not foreign.exists()
