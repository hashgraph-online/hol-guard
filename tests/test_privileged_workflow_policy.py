"""Regression coverage for privileged workflow toolchain policy."""

from __future__ import annotations

from pathlib import Path

import yaml

from scripts.check_privileged_workflows import validate_privileged_workflows

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACTION = "actions/checkout@0123456789abcdef0123456789abcdef01234567"
PINNED_UV = "astral-sh/setup-uv@abcdef0123456789abcdef0123456789abcdef01"


def _write_workflow(root: Path, content: str) -> None:
    workflow = root / ".github" / "workflows" / "fixture.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")


def test_repository_privileged_workflows_pass_policy() -> None:
    assert validate_privileged_workflows(ROOT) == ()


def test_privileged_job_rejects_mutable_action_revision(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        """
permissions:
  contents: read
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
""",
    )

    violations = validate_privileged_workflows(tmp_path)

    assert [violation.code for violation in violations] == ["action-not-commit-pinned"]
    assert violations[0].job == "release"


def test_privileged_job_rejects_floating_uv_version(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        f"""
permissions:
  contents: read
jobs:
  release:
    permissions:
      id-token: write
    steps:
      - uses: {PINNED_UV}
        with:
          version: latest
""",
    )

    violations = validate_privileged_workflows(tmp_path)

    assert [violation.code for violation in violations] == ["uv-version-not-pinned"]


def test_read_only_job_is_not_subject_to_privileged_policy(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        """
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
""",
    )

    assert validate_privileged_workflows(tmp_path) == ()


def test_job_level_read_permissions_remove_inherited_write_capability(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        """
permissions:
  id-token: write
jobs:
  test:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
""",
    )

    assert validate_privileged_workflows(tmp_path) == ()


def test_privileged_job_accepts_commit_pins_and_exact_uv_version(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        f"""
jobs:
  release:
    permissions:
      packages: write
    steps:
      - uses: {PINNED_ACTION}
      - uses: {PINNED_UV}
        with:
          version: "0.9.26"
""",
    )

    assert validate_privileged_workflows(tmp_path) == ()


def test_dependabot_action_pins_are_individually_reviewable() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    action_updates = next(update for update in config["updates"] if update.get("package-ecosystem") == "github-actions")

    assert action_updates["schedule"]["interval"] == "weekly"
    assert "groups" not in action_updates
    assert "github-actions" in action_updates["labels"]
