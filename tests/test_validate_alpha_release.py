from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.validate_alpha_release import ALPHA_BRANCH, validate_alpha_release


def test_accepts_public_guard_3_alpha_version_from_v3_branch() -> None:
    release = validate_alpha_release("3.0.0a1", ALPHA_BRANCH)

    assert release.version == "3.0.0a1"
    assert release.git_ref == ALPHA_BRANCH


@pytest.mark.parametrize(
    "version",
    [
        "2.1.0a1",
        "3.0.0b1",
        "3.0.0rc1",
        "3.0.0",
        "3.0.0a1.dev1",
        "3.0.0a1.post1",
        "3.0.0a1+local",
    ],
)
def test_rejects_versions_that_are_not_public_guard_3_alphas(version: str) -> None:
    with pytest.raises(ValueError, match=r"3\.x alpha"):
        validate_alpha_release(version, ALPHA_BRANCH)


def test_rejects_alpha_release_from_any_other_branch() -> None:
    with pytest.raises(ValueError, match="feat/guard-policy-v3"):
        validate_alpha_release("3.0.0a1", "refs/heads/main")


def test_release_workflows_keep_stable_and_alpha_channels_isolated() -> None:
    root = Path(__file__).parent.parent
    publish = yaml.safe_load((root / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    inputs = publish[True]["workflow_dispatch"]["inputs"]

    assert inputs["release_channel"]["options"] == ["stable", "alpha"]
    assert inputs["alpha_version"]["required"] is False

    jobs = publish["jobs"]
    alpha_matrix = jobs["alpha-cross-platform"]["strategy"]["matrix"]["os"]
    assert alpha_matrix == ["ubuntu-latest", "windows-latest"]
    assert "refs/heads/feat/guard-policy-v3" in jobs["publish-pypi"]["if"]
    assert jobs["publish-pypi"]["needs"] == ["build", "alpha-cross-platform"]
    assert jobs["release-alpha"]["needs"] == ["build", "publish-pypi"]

    alpha_publish_steps = jobs["publish-pypi"]["steps"]
    prune_step = next(
        step for step in alpha_publish_steps if step.get("name") == "Keep only the Guard alpha distribution"
    )
    assert prune_step["if"] == "needs.build.outputs.channel == 'alpha'"
    assert "plugin_scanner" in prune_step["run"]


def test_v3_branch_runs_standard_cross_platform_ci() -> None:
    root = Path(__file__).parent.parent
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    assert "feat/guard-policy-v3" in ci[True]["push"]["branches"]
    assert "feat/guard-policy-v3" in ci[True]["pull_request"]["branches"]
    assert "windows-latest" in ci["jobs"]["cross-platform"]["strategy"]["matrix"]["os"]
