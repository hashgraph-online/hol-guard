"""Phase 12 Python evaluator behavior tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .guard_python_phase12_support import (
    WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
    write_text,
)


def test_evaluate_package_request_artifact_blocks_exact_vulnerable_pip_version(
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
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install requests==2.31.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "2.31.0"


def test_evaluate_package_request_artifact_resolves_constraint_versions_for_python_ranges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(workspace_dir / "constraints.txt", "httpx==0.27.1\n")
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="httpx",
                    version="0.27.1",
                    default_action="block",
                    recommended_fix_version="0.27.2",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture(
        'pip install -c constraints.txt "httpx[socks]>=0.26,!=0.27.0,<0.28"',
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "0.27.1"


def test_evaluate_package_request_artifact_allows_recommended_safe_python_version(
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
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install requests==2.32.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "allow"
    assert result.policy_action == "allow"


@pytest.mark.parametrize(
    ("command", "manifest_name", "manifest_text", "lockfile_name", "lockfile_text", "package_name", "version"),
    [
        (
            "poetry add requests@^2.31",
            "pyproject.toml",
            "[tool.poetry]\nname = 'demo'\nversion = '0.1.0'\n[tool.poetry.dependencies]\nrequests = '^2.31'\n",
            "poetry.lock",
            """
[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]
""",
            "requests",
            "2.31.0",
        ),
        (
            "uv add fastapi>=0.110,<0.116",
            "pyproject.toml",
            "[project]\nname = 'demo'\nversion = '0.1.0'\ndependencies = ['fastapi>=0.110,<0.116']\n",
            "uv.lock",
            """
version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }
""",
            "fastapi",
            "0.115.0",
        ),
        (
            "pipenv install flask~=3.0",
            "Pipfile",
            "[packages]\nflask = '~=3.0'\n",
            "Pipfile.lock",
            """
{"default":{"flask":{"version":"==3.0.0"}}}
""",
            "flask",
            "3.0.0",
        ),
    ],
)
def test_evaluate_package_request_artifact_resolves_ranges_from_supported_python_lockfiles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    manifest_name: str,
    manifest_text: str,
    lockfile_name: str,
    lockfile_text: str,
    package_name: str,
    version: str,
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
                    name=package_name,
                    version=version,
                    default_action="block",
                    recommended_fix_version=None,
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == version


@pytest.mark.parametrize(
    ("command", "expected_next_step"),
    [
        ("uv add fastapi==0.115.0", "uv add fastapi==0.115.1"),
        ("poetry add requests@2.31.0", "poetry add requests@2.32.0"),
        ("pipenv install flask==3.0.0", "pipenv install flask==3.0.1"),
    ],
)
def test_evaluate_package_request_artifact_uses_manager_specific_python_fix_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    expected_next_step: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(workspace_dir / "pyproject.toml", "[project]\nname = 'demo'\n")
    write_text(workspace_dir / "Pipfile", "[packages]\nflask = '*'\n")
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    package_name = "fastapi" if "fastapi" in command else "requests" if "requests" in command else "flask"
    fix_version = "0.115.1" if package_name == "fastapi" else "2.32.0" if package_name == "requests" else "3.0.1"
    current_version = "0.115.0" if package_name == "fastapi" else "2.31.0" if package_name == "requests" else "3.0.0"
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name=package_name,
                    version=current_version,
                    default_action="block",
                    recommended_fix_version=fix_version,
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.user_copy.next_step == expected_next_step
    assert expected_next_step in result.user_copy.harness_message
