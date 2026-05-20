"""Phase 11 lockfile resolution regressions for JavaScript package evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import (
    WORKSPACE_ID,
    _artifact_from_command,
    _bundle_response,
    _package,
    _write_text,
)


def test_evaluate_package_request_artifact_preserves_direct_version_when_package_lock_contains_nested_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.0","react":"17.0.0"}}\n',
    )
    _write_text(
        workspace_dir / "package-lock.json",
        (
            '{"dependencies":{"minimist":{"version":"1.2.9"},"react":{"version":"17.0.0",'
            '"dependencies":{"minimist":{"version":"1.2.8"}}}}}\n'
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["dependencyPath"] == "react/node_modules/minimist"
    assert any(
        package["resolvedVersion"] == "1.2.9" and package["decision"] == "allow"
        for package in result.packages
    )


def test_evaluate_package_request_artifact_resolves_alias_range_from_package_lock_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"guard-safe":"npm:minimist@^1.2.0"}}\n')
    _write_text(
        workspace_dir / "package-lock.json",
        (
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"guard-safe":"npm:minimist@^1.2.0"}},'
            '"node_modules/guard-safe":{"name":"minimist","version":"1.2.8"}}}\n'
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install guard-safe@npm:minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "1.2.8"
    assert result.user_copy.next_step == "npm install guard-safe@npm:minimist@1.2.9"
