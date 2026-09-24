from __future__ import annotations

from pathlib import Path


def test_hosted_dashboard_asset_artifact_uses_exact_merged_source_tree() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "service-recovery-dashboard-assets.yml"
    ).read_text(encoding="utf-8")

    assert "push:" in workflow
    assert "- feat/service-recovery" in workflow
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "fetch-depth: 0" in workflow
    assert 'PR_INFO="$(gh api \\' in workflow
    assert "repos/$GITHUB_REPOSITORY/pulls?state=open&head=$GITHUB_REPOSITORY_OWNER:feat/service-recovery" in workflow
    assert 'git fetch --no-tags origin "$PR_BASE_SHA"' in workflow
    assert 'merge --no-commit --no-ff "$PR_BASE_SHA"' in workflow
    assert 'git diff --name-only --diff-filter=U' in workflow
    assert 'git -C "$GITHUB_WORKSPACE" add src/codex_plugin_scanner/guard/daemon/static/assets' in workflow
    assert "write-tree" in workflow
    assert '"sourceTreeSha"' in workflow
    assert 'name: service-recovery-dashboard-assets-${{ github.event.pull_request.head.sha || github.sha }}' in workflow


def test_hosted_asset_merge_uses_current_base_branch_tip_when_pr_snapshot_lags() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "service-recovery-dashboard-assets.yml"
    ).read_text(encoding="utf-8")

    assert "github.event.pull_request.base.ref || 'main'" in workflow
    assert 'repos/$GITHUB_REPOSITORY/branches/$PR_BASE_REF' in workflow
    assert "REPORTED_PR_BASE_SHA" in workflow
    assert '"reportedPrBaseSha"' in workflow
    assert "github.event.pull_request.head.sha || github.sha" in workflow


def test_hosted_asset_merge_sets_a_local_committer_identity() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "service-recovery-dashboard-assets.yml"
    ).read_text(encoding="utf-8")

    assert 'git -c user.name="HOL Guard CI"' in workflow
    assert '-c user.email="hol-guard-ci@users.noreply.github.com"' in workflow
