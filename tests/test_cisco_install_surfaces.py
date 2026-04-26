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
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    dependency_entries = project["dependencies"]
    dependencies = " ".join(dependency_entries)
    cisco_extra = " ".join(project["optional-dependencies"]["cisco"])
    override_entries = pyproject["tool"]["uv"]["override-dependencies"]

    assert "cisco-ai-mcp-scanner" not in dependencies
    assert "cisco-ai-mcp-scanner~=4.6" in cisco_extra
    assert "python_version >= '3.11'" in cisco_extra
    assert "cisco-ai-skill-scanner~=2.0.9" in dependency_entries
    assert "click==8.1.8" in override_entries
    assert "jsonschema==4.23.0" in override_entries
    assert "litellm>=1.83.7" in override_entries
    assert "openai==2.30.0" in override_entries
    assert "python-dotenv>=1.2.2" in override_entries
    assert "python-multipart>=0.0.26" in override_entries
    assert "cisco-ai-a2a-scanner" not in dependencies
    assert "cisco-ai-a2a-scanner" not in cisco_extra
    assert "cisco-aibom" not in dependencies
    assert "cisco-aibom" not in cisco_extra


def test_pyproject_exposes_guard_and_scanner_commands_without_codex_alias() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    scripts = project["scripts"]

    assert scripts["hol-guard"] == "codex_plugin_scanner.cli:main"
    assert scripts["plugin-scanner"] == "codex_plugin_scanner.cli:main"
    assert scripts["plugin-guard"] == "codex_plugin_scanner.cli:main"
    assert scripts["plugin-ecosystem-scanner"] == "codex_plugin_scanner.cli:main"
    assert "codex-plugin-scanner" not in scripts


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
    patched_litellm_versions = (
        "litellm==1.83.7",
        "litellm==1.83.8",
        "litellm==1.83.9",
        "litellm==1.83.10",
        "litellm==1.83.11",
        "litellm==1.83.12",
        "litellm==1.83.13",
        "litellm==1.83.14",
    )
    assert any(version in docker_requirements for version in patched_litellm_versions)
    assert "python-dotenv==1.2.2" in docker_requirements
    assert "python-multipart==0.0.26" in docker_requirements
    assert "--hash=sha256:" in docker_requirements
    assert "uv sync --extra dev --extra cisco" in contributing


def test_publish_workflow_builds_only_guard_and_scanner_packages() -> None:
    publish_workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")

    assert "Build Guard package (hol-guard)" in publish_workflow
    assert "Build scanner package (plugin-scanner)" in publish_workflow
    assert "Build codex compatibility alias" not in publish_workflow
    assert 'name = "codex-plugin-scanner"' not in publish_workflow
    assert 'codex-plugin-scanner = "codex_plugin_scanner.cli:main"' not in publish_workflow
    assert 'uv tool install codex-plugin-scanner==' not in publish_workflow
