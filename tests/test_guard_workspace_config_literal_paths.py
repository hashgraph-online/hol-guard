"""Preserve literal workspace paths instead of treating them as shell input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config
from tests.test_guard_workspace_config_symlink_containment import _observe_target_opens


@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
@pytest.mark.parametrize("relative_name", ("~", "workspace"), ids=("literal-tilde", "ordinary-relative"))
def test_workspace_path_never_redirects_to_environment_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, relative_name: str
) -> None:
    workspace = tmp_path / relative_name
    workspace.mkdir()
    (workspace / filename).write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )
    environment_home = tmp_path / "environment-home"
    environment_home.mkdir()
    home_config = environment_home / filename
    home_config.write_text('workspace_marker = "outside"\n', encoding="utf-8")
    home_identity = home_config.stat()

    with monkeypatch.context() as observation:
        observation.chdir(tmp_path)
        observation.setenv("HOME", str(environment_home))
        observation.setenv("USERPROFILE", str(environment_home))
        was_home_opened = _observe_target_opens(observation, home_identity)
        loaded = config._load_workspace_guard_config(Path(relative_name))

    print(
        "WORKSPACE_LITERAL_PATH_OBSERVATION "
        + json.dumps(
            {
                "literal_tilde": relative_name == "~",
                "home_config_opened": was_home_opened(),
                "workspace_content_selected": loaded.get("workspace_marker") == "inside",
                "blocked_policy_keys_removed": "mode" not in loaded and "protection_posture" not in loaded,
            },
            sort_keys=True,
        )
    )
    assert was_home_opened() is False
    assert loaded == {"workspace_marker": "inside"}
