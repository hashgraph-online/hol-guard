"""Phase 13 tier2 evaluator behavior tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .guard_tier2_phase13_support import (
    WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
    write_text,
)


def test_evaluate_package_request_artifact_blocks_vulnerable_cargo_version_from_cargo_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "Cargo.toml",
        """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
clap = "4.5"
""".strip()
        + "\n",
    )
    write_text(
        workspace_dir / "Cargo.lock",
        """
version = 3

[[package]]
name = "demo"
version = "0.1.0"

[[package]]
name = "clap"
version = "4.5.7"
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
                    ecosystem="cargo",
                    name="clap",
                    version="4.5.7",
                    default_action="block",
                    recommended_fix_version="4.5.8",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("cargo add clap@^4.5", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "4.5.7"
    assert result.packages[0]["supportLevel"] == "beta"


def test_evaluate_package_request_artifact_requires_review_on_cargo_local_path_without_leaking_path(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    artifact = artifact_from_command_fixture("cargo add demo --path crates/demo", workspace=workspace_dir)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    payload = json.dumps(result.to_dict())

    assert result.decision == "ask"
    assert result.packages[0]["reasons"][0]["code"] == "local_path_dependency_source"
    assert result.packages[0]["supportLevel"] == "beta"
    assert "crates/demo" not in payload


def test_evaluate_package_request_artifact_requires_review_on_cargo_git_sources(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    artifact = artifact_from_command_fixture(
        "cargo add demo --git https://github.com/serde-rs/serde",
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    assert result.decision == "ask"
    assert result.packages[0]["reasons"][0]["code"] == "git_dependency_source"
    assert result.packages[0]["supportLevel"] == "beta"


def test_evaluate_package_request_artifact_blocks_vulnerable_go_version_from_go_mod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "go.mod",
        """
module example.com/demo

go 1.23

require github.com/gin-gonic/gin v1.10.0
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
                    ecosystem="go",
                    name="github.com/gin-gonic/gin",
                    version="v1.10.0",
                    default_action="block",
                    recommended_fix_version="v1.11.0",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("go get github.com/gin-gonic/gin", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "v1.10.0"
    assert result.packages[0]["supportLevel"] == "beta"


def test_evaluate_package_request_artifact_requires_review_on_go_replace_local_path_without_leaking_path(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "go.mod",
        """
module example.com/demo

go 1.23

require github.com/gin-gonic/gin v1.10.0

replace github.com/gin-gonic/gin => ../forks/gin
""".strip()
        + "\n",
    )

    artifact = artifact_from_command_fixture("go get github.com/gin-gonic/gin", workspace=workspace_dir)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    payload = json.dumps(result.to_dict())

    assert result.decision == "ask"
    assert result.packages[0]["reasons"][0]["code"] == "go_replace_local_source"
    assert result.packages[0]["supportLevel"] == "beta"
    assert "../forks/gin" not in payload


@pytest.mark.parametrize(
    (
        "command",
        "manifest_name",
        "manifest_text",
        "lockfile_name",
        "lockfile_text",
        "ecosystem",
        "package_name",
        "version",
    ),
    [
        (
            "mvn dependency:get -Dartifact=org.example:demo",
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.3</version></dependency></dependencies></project>\n",
            None,
            None,
            "maven",
            "org.example:demo",
            "1.2.3",
        ),
        (
            "./gradlew addDependency --dependency org.example:demo",
            "build.gradle",
            'dependencies { implementation("org.example:demo:1.2.3") }\n',
            None,
            None,
            "maven",
            "org.example:demo",
            "1.2.3",
        ),
        (
            "composer require laravel/framework",
            "composer.json",
            '{"require":{"laravel/framework":"^11.0"}}\n',
            "composer.lock",
            '{"packages":[{"name":"laravel/framework","version":"11.1.0"}]}\n',
            "packagist",
            "laravel/framework",
            "11.1.0",
        ),
        (
            "bundle add rspec",
            "Gemfile",
            'source "https://rubygems.org"\ngem "rspec"\n',
            "Gemfile.lock",
            "GEM\n  specs:\n    rspec (3.13.0)\n",
            "rubygems",
            "rspec",
            "3.13.0",
        ),
    ],
)
def test_evaluate_package_request_artifact_blocks_tier2_versions_from_manifest_or_lockfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    manifest_name: str,
    manifest_text: str,
    lockfile_name: str | None,
    lockfile_text: str | None,
    ecosystem: str,
    package_name: str,
    version: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(workspace_dir / manifest_name, manifest_text)
    if lockfile_name is not None and lockfile_text is not None:
        write_text(workspace_dir / lockfile_name, lockfile_text)
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    ecosystem=ecosystem,
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
    assert result.packages[0]["supportLevel"] == "beta"


def test_evaluate_package_request_artifact_warns_for_system_package_managers_in_monitor_only_mode(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    artifact = artifact_from_command_fixture("brew install jq", workspace=workspace_dir)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    assert result.decision == "warn"
    assert result.policy_action == "warn"
    assert result.packages[0]["ecosystem"] == "homebrew"
    assert result.packages[0]["supportLevel"] == "monitor-only"
    assert result.packages[0]["reasons"][0]["code"] == "homebrew_package_manager_monitor_only"


def test_evaluate_package_request_artifact_uses_monitor_only_fallback_for_unsupported_ecosystems(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    artifact = artifact_from_command_fixture(
        "helm install ingress ingress-nginx/ingress-nginx",
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    assert result.decision == "monitor"
    assert result.packages[0]["supportLevel"] == "monitor-only"
    assert result.packages[0]["reasons"][0]["code"] == "unsupported_ecosystem_monitor_only"


def test_evaluate_package_request_artifact_fails_closed_when_tier2_range_lockfile_parse_error_hides_cached_advisory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    write_text(
        workspace_dir / "Cargo.toml",
        """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
clap = "4.5"
""".strip()
        + "\n",
    )
    write_text(workspace_dir / "Cargo.lock", "version = [\n")
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    ecosystem="cargo",
                    name="clap",
                    version="4.5.7",
                    default_action="block",
                    recommended_fix_version="4.5.8",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("cargo add clap@^4.5", workspace=workspace_dir)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert any(reason["code"] == "lockfile_parse_error" for reason in result.reasons)
    assert result.packages[0]["supportLevel"] == "beta"
