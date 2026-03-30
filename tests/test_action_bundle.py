"""Regression checks for the GitHub Action bundle and Marketplace packaging."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_action_metadata_includes_marketplace_branding_and_fallback_install() -> None:
    action_text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")

    assert 'name: "HOL Codex Plugin Scanner"' in action_text
    assert "branding:" in action_text
    assert 'icon: "check-circle"' in action_text
    assert 'color: "blue"' in action_text
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in action_text
    assert "pip install codex-plugin-scanner" in action_text
    assert 'pip install "$LOCAL_SOURCE"' in action_text
    assert "submission_enabled:" in action_text
    assert "submission_issue_urls:" in action_text
    assert "python3 -m codex_plugin_scanner.action_runner" in action_text
    assert "value: ${{ steps.scan.outputs.score }}" in action_text
    assert "value: ${{ steps.scan.outputs.grade }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_eligible }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_performed }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_issue_urls }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_issue_numbers }}" in action_text


def test_publish_workflow_attaches_marketplace_action_bundle() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "Build GitHub Action bundle" in workflow_text
    assert "hol-codex-plugin-scanner-action-v${VERSION}.zip" in workflow_text
    assert 'cp action/action.yml "${BUNDLE_ROOT}/action.yml"' in workflow_text


def test_publish_action_repo_workflow_syncs_action_repository() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish-action-repo.yml").read_text(encoding="utf-8")

    assert "Publish GitHub Action Repository" in workflow_text
    assert "ACTION_REPO_TOKEN" in workflow_text
    assert "hashgraph-online/hol-codex-plugin-scanner-action" in workflow_text
    assert "Validate publication credentials" in workflow_text
    assert "if: secrets.ACTION_REPO_TOKEN != ''" not in workflow_text
    assert "inputs.create_repository && 'true' || 'false'" in workflow_text
    assert "SOURCE_REF" in workflow_text
    assert 'gh repo create "${ACTION_REPOSITORY}"' in workflow_text
    assert 'cp "${GITHUB_WORKSPACE}/action/action.yml" action.yml' in workflow_text
    assert "git push origin refs/tags/v1 --force" in workflow_text
    assert 'gh release create "${TAG}"' in workflow_text
    assert "Published automatically from ${SOURCE_SERVER_URL}/${SOURCE_REPOSITORY}/tree/${SOURCE_REF}" in workflow_text


def test_action_bundle_docs_live_in_action_readme() -> None:
    action_readme = (ROOT / "action" / "README.md").read_text(encoding="utf-8")

    assert "single root `action.yml`" in action_readme
    assert "no workflow files" in action_readme
    assert "dedicated Marketplace repository" in action_readme
    assert "Source Of Truth" in action_readme
    assert "submission issue" in action_readme
    assert "awesome-codex-plugins" in action_readme
    assert "publish-action-repo.yml" in action_readme


def test_readme_uses_stable_apache_license_badge() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "https://img.shields.io/badge/license-Apache--2.0-blue.svg" in readme
    assert "https://img.shields.io/github/license/hashgraph-online/codex-plugin-scanner" not in readme
    assert "publish-action-repo.yml" in readme
    assert "docs/github-action-marketplace.md" not in readme
