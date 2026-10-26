"""Wheel inclusion edits reject competing owners of a contribution path."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.render_native import contribution_path
from codex_plugin_scanner.guard.extension_builder.repository_edits import edit_pyproject
from tests.extension_builder_support import metadata


@pytest.mark.parametrize("reuse", ["directory", "file"])
def test_competing_wheel_destination_is_rejected_when_mapping_is_reused(reuse: str) -> None:
    contribution = metadata("mcp")
    destination = "codex_plugin_scanner/guard/contracts/data/mcp_servers/contributions/mcp.builder-demo.json"
    project = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    anchor = "[tool.hatch.build.targets.wheel.force-include]"
    assert project.count(anchor) == 1
    assert (
        '"contributions/mcp-servers" = "codex_plugin_scanner/guard/contracts/data/mcp_servers/contributions"' in project
    )
    added = f'"unrelated/payload.json" = "{destination}"'
    if reuse == "file":
        added += f'\n"{contribution_path(contribution)}" = "{destination}"'
    project = project.replace(anchor, f"{anchor}\n{added}", 1)

    with pytest.raises(BuilderError, match="already owns this contribution destination"):
        edit_pyproject(project, contribution)
