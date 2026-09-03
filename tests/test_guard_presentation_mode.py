from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.config import (
    GuardConfig,
    editable_guard_settings,
    load_guard_config,
    update_guard_settings,
)
from codex_plugin_scanner.guard.presentation_mode import (
    PRESENTATION_SCHEMA_VERSION,
    coerce_persisted_presentation_mode,
    resolve_presentation_mode,
)


def _presentation_settings(config: GuardConfig) -> dict[str, object]:
    settings = editable_guard_settings(config)
    return cast(dict[str, object], settings["presentation"])


def test_new_install_defaults_to_everyday(tmp_path: Path) -> None:
    config = load_guard_config(tmp_path / "guard")
    assert config.presentation_mode == "everyday"
    assert config.presentation_mode_explicit is False
    assert _presentation_settings(config)["source"] == "default"


@pytest.mark.parametrize("legacy_key", ["presentation_density", "display_density", "density"])
def test_obsolete_presentation_keys_are_ignored(tmp_path: Path, legacy_key: str) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(f'{legacy_key} = "advanced"\n', encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.presentation_mode == "everyday"
    assert config.presentation_mode_explicit is False
    assert config.presentation_source == "default"
    assert config.presentation_diagnostic is None


def test_workspace_cannot_override_local_presentation_preference(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    guard_home.mkdir()
    workspace.mkdir()
    (guard_home / "config.toml").write_text(
        'presentation_mode = "technical"\npresentation_mode_explicit = true\n',
        encoding="utf-8",
    )
    (workspace / ".hol-guard.toml").write_text(
        'presentation_mode = "everyday"\npresentation_mode_explicit = true\n',
        encoding="utf-8",
    )
    config = load_guard_config(guard_home, workspace)
    assert config.presentation_mode == "technical"
    assert _presentation_settings(config)["source"] == "local-explicit"


def test_obsolete_presentation_value_falls_back_without_migration(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('presentation_mode = "advanced"\n', encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.presentation_mode == "everyday"
    assert config.presentation_mode_explicit is False
    assert config.presentation_source == "default"
    assert config.presentation_diagnostic == "unknown_presentation_mode_fell_back_to_everyday"


def test_unknown_mode_falls_back_with_safe_diagnostic() -> None:
    mode = coerce_persisted_presentation_mode("future-mode")
    assert mode.value == "everyday"
    assert mode.diagnostic == "unknown_presentation_mode_fell_back_to_everyday"
    assert "future-mode" not in mode.diagnostic


def test_session_preview_does_not_persist_or_consult_policy() -> None:
    resolved = resolve_presentation_mode(local_value="everyday", session_preview="technical", cloud_profile="everyday")
    assert resolved.value == "technical"
    assert resolved.source == "session-preview"


def test_presentation_only_write_round_trips_and_increments_revision(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    initial = load_guard_config(guard_home)
    updated = update_guard_settings(
        guard_home,
        {"presentation_mode": "technical", "presentation_revision": initial.presentation_revision},
        skip_approval_gate=True,
    )
    assert updated.presentation_mode == "technical"
    assert updated.presentation_mode_explicit is True
    assert updated.presentation_schema_version == PRESENTATION_SCHEMA_VERSION
    assert updated.presentation_revision == 1
    reloaded = load_guard_config(guard_home)
    assert reloaded.presentation_mode == "technical"


def test_stale_presentation_revision_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    update_guard_settings(guard_home, {"presentation_mode": "technical"}, skip_approval_gate=True)
    with pytest.raises(ValueError, match="another surface"):
        update_guard_settings(
            guard_home,
            {"presentation_mode": "everyday", "presentation_revision": 0},
            skip_approval_gate=True,
        )


def test_stale_revision_is_rejected_for_no_op_presentation_write(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    current = update_guard_settings(guard_home, {"presentation_mode": "technical"}, skip_approval_gate=True)
    with pytest.raises(ValueError, match="another surface"):
        update_guard_settings(
            guard_home,
            {"presentation_mode": "technical", "presentation_revision": current.presentation_revision - 1},
            skip_approval_gate=True,
        )


def test_no_op_write_preserves_unsupported_future_schema(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    config_path = guard_home / "config.toml"
    config_path.write_text(
        'presentation_mode = "future"\n'
        "presentation_mode_explicit = false\n"
        "presentation_schema_version = 99\n"
        "presentation_revision = 7\n",
        encoding="utf-8",
    )
    current = load_guard_config(guard_home)
    assert _presentation_settings(current)["writable"] is False
    updated = update_guard_settings(
        guard_home,
        {
            "presentation_mode_explicit": False,
            "presentation_revision": current.presentation_revision,
        },
        skip_approval_gate=True,
    )
    assert updated.presentation_revision == 7
    persisted = config_path.read_text(encoding="utf-8")
    assert 'presentation_mode = "future"' in persisted
    assert "presentation_schema_version = 99" in persisted


def test_revision_only_write_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    initial = load_guard_config(guard_home)
    with pytest.raises(ValueError, match="presentation preference change"):
        update_guard_settings(
            guard_home,
            {"presentation_revision": initial.presentation_revision + 1},
            skip_approval_gate=True,
        )
    assert load_guard_config(guard_home).presentation_revision == initial.presentation_revision


def test_invalid_mode_and_schema_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    with pytest.raises(ValueError, match="everyday or technical"):
        update_guard_settings(guard_home, {"presentation_mode": "developer"}, skip_approval_gate=True)
    with pytest.raises(ValueError, match="schema"):
        update_guard_settings(guard_home, {"presentation_schema_version": 99}, skip_approval_gate=True)


def test_action_explanation_schema_is_strict() -> None:
    schema_path = Path(__file__).parents[1] / "src/codex_plugin_scanner/guard/schemas/guard_action_explanation_v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "guard.action-explanation.v1"
    assert schema["additionalProperties"] is False
    assert "unknown_action" in schema["properties"]["kind"]["enum"]
