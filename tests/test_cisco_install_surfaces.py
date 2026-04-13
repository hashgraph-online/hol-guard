"""Regression coverage for Cisco packaging and repo install surfaces."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_keeps_cisco_mcp_scanner_optional() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = " ".join(project["dependencies"])
    cisco_extra = " ".join(project["optional-dependencies"]["cisco"])

    assert "cisco-ai-mcp-scanner" not in dependencies
    assert "cisco-ai-mcp-scanner~=4.5" in cisco_extra
    assert "python_version >= '3.11'" in cisco_extra
    assert "cisco-ai-a2a-scanner" not in dependencies
    assert "cisco-ai-a2a-scanner" not in cisco_extra
    assert "cisco-aibom" not in dependencies
    assert "cisco-aibom" not in cisco_extra


def test_readme_distinguishes_baseline_and_full_cisco_installs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Lean baseline install" in readme
    assert "Full Cisco coverage" in readme
    assert 'pip install "hol-guard[cisco]"' in readme
    assert 'pip install "plugin-scanner[cisco]"' in readme
    assert "Python 3.11+" in readme
    assert "deferred" in readme
    assert "cisco-ai-a2a-scanner" in readme
    assert "cisco-aibom" in readme


def test_repo_controlled_surfaces_prefer_cisco_extra_where_supported() -> None:
    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    publish_workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    docker_requirements = (ROOT / "docker-requirements.txt").read_text(encoding="utf-8")

    assert "cisco-full" in ci_workflow
    assert "uv sync --frozen --extra dev --extra cisco --python 3.12" in ci_workflow
    assert "uv sync --frozen --extra dev --python ${{ matrix.python-version }}" in ci_workflow
    assert "uv sync --frozen --extra dev --extra publish --extra cisco" in publish_workflow
    assert 'uv tool install "hol-guard[cisco]==' in publish_workflow
    assert "COPY docker-requirements.txt LICENSE README.md /app/" in dockerfile
    assert "RUN python3 -m pip install --require-hashes -r /app/docker-requirements.txt" in dockerfile
    requirements_copy_index = dockerfile.index("COPY docker-requirements.txt LICENSE README.md /app/")
    source_copy_index = dockerfile.index("COPY src /app/src")
    assert requirements_copy_index < source_copy_index
    assert "cisco-ai-mcp-scanner==" in docker_requirements
    assert "--hash=sha256:" in docker_requirements
    assert "uv sync --extra dev --extra cisco" in contributing
