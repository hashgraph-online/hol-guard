"""Contributor-facing command Extension directory contract tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_command_extension_directory.py"
DIRECTORY_PATH = REPO_ROOT / "docs" / "guard" / "extensions" / "README.md"


def _load_renderer() -> ModuleType:
    spec = importlib.util.spec_from_file_location("render_command_extension_directory", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_extension_directory_matches_canonical_registry() -> None:
    renderer = _load_renderer()
    current = DIRECTORY_PATH.read_text(encoding="utf-8")

    assert renderer.render_document(current) == current
    for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        assert current.count(f"`{extension.extension_id}`") == 1


def test_future_extension_ids_use_a_non_breaking_directory_fallback() -> None:
    renderer = _load_renderer()

    assert renderer._category("command.future-capability") == "Other extensions"


def test_readme_and_contribution_guide_expose_complete_entry_path() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs" / "guard" / "extensions" / "contributing.md").read_text(encoding="utf-8")
    pr_template = (REPO_ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "command-extension.md").read_text(
        encoding="utf-8"
    )

    assert "docs/guard/extensions/README.md" in readme
    assert "docs/guard/extensions/contributing.md" in readme
    assert "docs/guard/extensions/contributing.md" in contributing
    for requirement in (
        "destructive examples reach both side-effect-free inspection and runtime review",
        "safe previews",
        "privacy",
        "draft pull request",
    ):
        assert requirement.lower() in guide.lower()
    for requirement in (
        "Upstream source and version",
        "Capability boundary",
        "safe/read-only counterparts",
        "Allow edits from maintainers",
    ):
        assert requirement.lower() in pr_template.lower()
