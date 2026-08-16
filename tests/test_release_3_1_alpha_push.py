"""Regression contract that release/3.1 cannot publish on push."""

from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_release_3_1_push_cannot_publish() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "branches: [release/3.1]" not in text
    assert "compute_alpha_release_version.py" not in text
    assert "validate_alpha_release.py" not in text
    assert "alpha/v3.1.0a" not in text


def test_release_3_1_has_no_registry_or_release_steps() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "testpypi" not in text.lower()
    assert "environment: pypi" not in text
    assert "gh release" not in text
    assert "packages-dir" not in text
