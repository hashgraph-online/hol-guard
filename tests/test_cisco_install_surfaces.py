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
    requires_python = project["requires-python"]
    dependency_entries = project["dependencies"]
    dependencies = " ".join(dependency_entries)
    cisco_extra = " ".join(project["optional-dependencies"]["cisco"])
    cisco_mcp_group = " ".join(pyproject["dependency-groups"]["cisco-mcp"])
    override_entries = pyproject["tool"]["uv"]["override-dependencies"]

    assert requires_python == ">=3.10"
    assert "cisco-ai-mcp-scanner" not in dependencies
    assert "cisco-ai-mcp-scanner" not in cisco_extra
    assert "cisco-ai-mcp-scanner==4.8.1" in cisco_mcp_group
    assert "litellm==1.93.0" in cisco_extra
    assert "python_version >= '3.11'" in cisco_extra
    assert "python_version < '3.15'" in cisco_extra
    assert "python_version >= '3.11.4'" in cisco_mcp_group
    assert "cisco-ai-skill-scanner~=2.0.12" in dependency_entries
    assert "requests>=2.32,<3" in dependency_entries
    assert "aiohttp==3.14.1" in override_entries
    assert "click==8.4.1" in override_entries
    assert "cisco-ai-skill-scanner==2.0.12" in override_entries
    assert "importlib-metadata==8.9.0" in override_entries
    assert "jsonschema==4.26.0" in override_entries
    assert "litellm==1.93.0" in override_entries
    assert "magika==1.0.3" in override_entries
    assert "openai==2.41.1" in override_entries
    assert "pyjwt==2.13.0" in override_entries
    assert "python-dotenv==1.2.2" in override_entries
    assert "python-multipart==0.0.32" in override_entries
    assert "starlette==1.3.1" in override_entries
    assert "tokenizers==0.23.1" in override_entries
    assert "urllib3==2.7.0" in override_entries
    assert "cisco-ai-a2a-scanner" not in dependencies
    assert "cisco-ai-a2a-scanner" not in cisco_extra
    assert "rich>=14.0,<15" in dependency_entries
    assert "rich>=15.0.0" not in dependency_entries


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
    assert "Python 3.10 through 3.14" in readme
    assert "Resolver-safe Cisco extra" in readme
    assert 'pip install "hol-guard[cisco]"' in readme
    assert 'pip install "plugin-scanner[cisco]"' in readme
    assert "Python 3.11 through 3.14" in readme
    assert "published `cisco` extra remains resolver-safe" in readme
    assert "repo-controlled Docker image or `cisco-mcp` uv group" in readme
    assert "LiteLLM 1.93" in readme
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
    assert "python3.13 -m pip install --dry-run --no-deps --require-hashes -r docker-requirements.txt" in ci_workflow
    assert "uv sync --frozen --extra dev --extra cisco --group cisco-mcp --python 3.13" in ci_workflow
    assert "uv sync --frozen --extra dev --python ${{ matrix.python-version }}" in ci_workflow
    assert "uv sync --frozen --extra dev --extra publish --extra cisco" in publish_workflow
    assert 'uv tool install "hol-guard[cisco]==' in publish_workflow
    assert "COPY docker-requirements.txt LICENSE README.md /app/" in dockerfile
    assert "FROM python:3.13-slim@" in dockerfile
    assert "FROM python:3.14-slim" not in dockerfile
    assert "python3 -m pip install --no-deps --require-hashes -r /app/docker-requirements.txt" in dockerfile
    assert "apt-get install -y --no-install-recommends gcc libc6-dev" in dockerfile
    assert "apt-get purge -y --auto-remove gcc libc6-dev" in dockerfile
    assert "apt-get clean" in dockerfile
    requirements_copy_index = dockerfile.index("COPY docker-requirements.txt LICENSE README.md /app/")
    build_deps_index = dockerfile.index("apt-get install -y --no-install-recommends gcc libc6-dev")
    pip_install_index = dockerfile.index(
        "python3 -m pip install --no-deps --require-hashes -r /app/docker-requirements.txt"
    )
    purge_index = dockerfile.index("apt-get purge -y --auto-remove gcc libc6-dev")
    source_copy_index = dockerfile.index("COPY src /app/src")
    assert requirements_copy_index < pip_install_index
    assert requirements_copy_index < source_copy_index
    assert build_deps_index < pip_install_index
    assert pip_install_index < purge_index
    assert "aiohttp==3.14.1" in docker_requirements
    assert "cisco-ai-mcp-scanner==" in docker_requirements
    assert "importlib-metadata==8.9.0" in docker_requirements
    assert "litellm==1.93.0" in docker_requirements
    assert "python-dotenv==1.2.2" in docker_requirements
    assert "python-multipart==0.0.32" in docker_requirements
    assert "pyjwt==2.13.0" in docker_requirements
    assert "starlette==1.3.1" in docker_requirements
    assert "tokenizers==0.23.1" in docker_requirements
    assert "--hash=sha256:" in docker_requirements
    assert "uv sync --extra dev" in contributing
    assert "uv sync --extra dev --extra cisco --group cisco-mcp" in contributing


def test_publish_workflow_builds_only_guard_and_scanner_packages() -> None:
    publish_workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")

    assert "Build Guard package (hol-guard)" in publish_workflow
    assert "Build scanner package (plugin-scanner)" in publish_workflow
    assert "Build codex compatibility alias" not in publish_workflow
    assert 'name = "codex-plugin-scanner"' not in publish_workflow
    assert 'codex-plugin-scanner = "codex_plugin_scanner.cli:main"' not in publish_workflow
    assert "uv tool install codex-plugin-scanner==" not in publish_workflow
