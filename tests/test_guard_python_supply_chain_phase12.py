"""Phase 12 Python evaluator behavior tests."""

from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as supply_chain_package_eval_module
from codex_plugin_scanner.guard.runtime.supply_chain_bundle import load_supply_chain_bundle_response
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


def test_evaluate_package_request_artifact_resolves_versions_from_nested_requirements_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "deps" / "prod.txt",
        """
requests==2.31.0 \\
    --hash=sha256:aaaaaaaa
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
                    name="requests",
                    version="2.31.0",
                    default_action="block",
                    recommended_fix_version="2.32.0",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture(
        'pip install -r deps/prod.txt "requests>=2.31,<2.32"',
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "2.31.0"


def test_evaluate_package_request_artifact_resolves_marker_qualified_exact_requirements_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "requirements.txt",
        'requests==2.31.0 ; python_version < "3.13"\n',
    )
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

    artifact = artifact_from_command_fixture(
        'pip install -r requirements.txt "requests>=2.31,<2.32"',
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "2.31.0"


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


def test_resolved_target_version_uses_fake_pypi_registry_metadata_for_ranges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    def fake_urlopen_json_with_timeout_retry(
        *, request: urllib.request.Request, timeout_seconds: int, retry_timeout_seconds: int
    ) -> dict[str, object]:
        captured["url"] = request.full_url
        assert timeout_seconds == 1
        assert retry_timeout_seconds == 1
        return {
            "releases": {
                "2.30.9": [{}],
                "2.31.0": [{}],
                "2.31.4": [{}],
                "2.32.0": [{}],
            }
        }

    monkeypatch.setattr(
        supply_chain_package_eval_module, "_urlopen_json_with_timeout_retry", fake_urlopen_json_with_timeout_retry
    )
    resolved = supply_chain_package_eval_module._resolved_target_version(
        target={
            "ecosystem": "pypi",
            "name": "requests",
            "normalized_name": "requests",
            "namespace": None,
            "range": ">=2.31,<2.32",
            "version": None,
            "source_url": None,
        },
        lockfile_versions={},
    )

    assert captured["url"].endswith("/requests/json")
    assert resolved == "2.31.4"


def test_evaluate_package_request_artifact_scopes_offline_decisions_to_python_ecosystem(
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
    npm_package["riskScore"] = 999
    pypi_package = package_fixture(
        name="requests",
        version="2.31.0",
        default_action="block",
        recommended_fix_version="2.32.0",
    )
    pypi_package["riskScore"] = 200
    pypi_package["knownExploited"] = False
    pypi_package["malwareState"] = "none"
    pypi_package["normalizedSeverity"] = "medium"
    pypi_package["exploitLevel"] = "none"
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(packages=[npm_package, pypi_package]),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install requests==2.31.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"
    assert result.packages[0]["decision"] == "monitor"


def test_evaluate_package_request_artifact_does_not_allow_fix_versions_from_other_ecosystems(
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

    artifact = artifact_from_command_fixture("pip install requests==2.32.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"


def test_transitive_lockfile_results_scope_python_matches_to_python_ecosystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        "[project]\nname = 'demo'\nversion = '0.1.0'\ndependencies = ['fastapi>=0.110,<0.116']\n",
    )
    write_text(
        workspace_dir / "uv.lock",
        """
version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""".strip()
        + "\n",
    )
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
    npm_package["riskScore"] = 999
    pypi_package = package_fixture(
        name="requests",
        version="2.31.0",
        default_action="block",
        recommended_fix_version="2.32.0",
    )
    pypi_package["riskScore"] = 200
    pypi_package["knownExploited"] = False
    pypi_package["malwareState"] = "none"
    pypi_package["normalizedSeverity"] = "medium"
    pypi_package["exploitLevel"] = "none"
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(packages=[npm_package, pypi_package]),
        "2026-05-19T00:00:00Z",
    )
    bundle_response = load_supply_chain_bundle_response(bundle_response_fixture(packages=[npm_package, pypi_package]))
    artifact = artifact_from_command_fixture("uv add fastapi>=0.110,<0.116", workspace=workspace_dir)
    results = supply_chain_package_eval_module._transitive_lockfile_results(
        bundle_response=bundle_response,
        artifact=artifact,
        workspace_dir=workspace_dir,
    )

    assert len(results) == 1
    assert results[0]["ecosystem"] == "pypi"
    assert results[0]["name"] == "requests"
    assert results[0]["decision"] == "warn"


def test_evaluate_package_request_artifact_uses_manager_specific_fix_commands_for_python_transitives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "pyproject.toml",
        "[project]\nname = 'demo'\nversion = '0.1.0'\ndependencies = ['fastapi>=0.110,<0.116']\n",
    )
    write_text(
        workspace_dir / "uv.lock",
        """
version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
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
                    name="requests",
                    version="2.31.0",
                    default_action="block",
                    recommended_fix_version="2.32.0",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )
    artifact = artifact_from_command_fixture("uv add fastapi>=0.110,<0.116", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.user_copy.next_step == "uv add requests==2.32.0"


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
        ("uv pip install fastapi==0.115.0", "uv pip install fastapi==0.115.1"),
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
