"""Regression checks for the GitHub Action bundle and Marketplace packaging."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_action_metadata_includes_marketplace_branding_and_fallback_install() -> None:
    action_text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")

    assert 'name: "HOL Codex Plugin Scanner"' in action_text
    assert "branding:" in action_text
    assert 'icon: "check-circle"' in action_text
    assert 'color: "blue"' in action_text
    assert 'pip install codex-plugin-scanner' in action_text
    assert 'pip install "$LOCAL_SOURCE"' in action_text


def test_publish_workflow_attaches_marketplace_action_bundle() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "Build GitHub Action bundle" in workflow_text
    assert "hol-codex-plugin-scanner-action-v${VERSION}.zip" in workflow_text
    assert 'cp action/action.yml "${BUNDLE_ROOT}/action.yml"' in workflow_text


def test_action_bundle_has_root_ready_readme_and_marketplace_guide() -> None:
    action_readme = (ROOT / "action" / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "github-action-marketplace.md").read_text(encoding="utf-8")

    assert "single root `action.yml`" in action_readme
    assert "must not contain any workflow files" in guide
    assert "dedicated public action repository" in guide
