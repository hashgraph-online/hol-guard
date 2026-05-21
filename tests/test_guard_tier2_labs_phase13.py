"""Phase 13 tier2 fixture-lab coverage."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .guard_tier2_phase13_support import (
    WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
)

FIXTURES = Path(__file__).parent / "fixtures" / "tier2"


@pytest.mark.parametrize(
    ("fixture_name", "command", "ecosystem", "package_name", "blocked_version", "expected_decision"),
    [
        ("cargo-vulnerable", "cargo add clap@^4.5", "cargo", "clap", "4.5.7", "block"),
        ("cargo-safe", "cargo add clap@^4.5", "cargo", "clap", "4.5.7", "monitor"),
        (
            "go-vulnerable",
            "go get github.com/gin-gonic/gin",
            "go",
            "github.com/gin-gonic/gin",
            "v1.10.0",
            "block",
        ),
        (
            "go-safe",
            "go get github.com/gin-gonic/gin",
            "go",
            "github.com/gin-gonic/gin",
            "v1.10.0",
            "monitor",
        ),
        (
            "maven-vulnerable",
            "mvn dependency:get -Dartifact=org.example:demo",
            "maven",
            "org.example:demo",
            "1.2.3",
            "block",
        ),
        (
            "maven-safe",
            "mvn dependency:get -Dartifact=org.example:demo",
            "maven",
            "org.example:demo",
            "1.2.3",
            "monitor",
        ),
        (
            "gradle-vulnerable",
            "./gradlew addDependency --dependency org.example:demo",
            "maven",
            "org.example:demo",
            "1.2.3",
            "block",
        ),
        (
            "gradle-safe",
            "./gradlew addDependency --dependency org.example:demo",
            "maven",
            "org.example:demo",
            "1.2.3",
            "monitor",
        ),
        (
            "composer-vulnerable",
            "composer require laravel/framework",
            "packagist",
            "laravel/framework",
            "11.1.0",
            "block",
        ),
        (
            "composer-safe",
            "composer require laravel/framework",
            "packagist",
            "laravel/framework",
            "11.1.0",
            "monitor",
        ),
        ("rubygems-vulnerable", "bundle add rspec", "rubygems", "rspec", "3.13.0", "block"),
        ("rubygems-safe", "bundle add rspec", "rubygems", "rspec", "3.13.0", "monitor"),
    ],
)
def test_tier2_fixture_labs_cover_safe_and_vulnerable_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_name: str,
    command: str,
    ecosystem: str,
    package_name: str,
    blocked_version: str,
    expected_decision: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    shutil.copytree(FIXTURES / fixture_name, workspace_dir)
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    ecosystem=ecosystem,
                    name=package_name,
                    version=blocked_version,
                    default_action="block",
                    recommended_fix_version=None,
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == expected_decision
    assert result.packages[0]["supportLevel"] == "beta"
