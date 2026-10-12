"""Phase 11 lockfile resolution regressions for JavaScript package evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_workspace import bind_workspace
from tests.test_guard_js_supply_chain_phase11 import (
    WORKSPACE_ID,
    _artifact_from_command,
    _bundle_response,
    _package,
    _write_text,
)

pytestmark = pytest.mark.usefixtures("package_intent_native")


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
    bind_workspace(store, WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["dependencyPath"] == "react/node_modules/minimist"
    assert any(package["resolvedVersion"] == "1.2.9" and package["decision"] == "allow" for package in result.packages)


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
    bind_workspace(store, WORKSPACE_ID)
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


def test_incomplete_lockfile_evidence_contains_hash_and_reason_without_contents(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    malformed_lockfile = '{"lockfileVersion":3,"packages":{"node_modules/secret-fixture":'
    _write_text(workspace_dir / "package-lock.json", malformed_lockfile)
    store = GuardStore(home_dir)

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    package = result.packages[0]
    assert package["lockfileParseError"] == "syntax_error"
    assert package["lockfileHash"] == stable_digest_hex(malformed_lockfile.encode("utf-8"))
    evidence_payload = json.dumps(store.list_evidence(), sort_keys=True)
    assert package["lockfileHash"] in evidence_payload
    assert "lockfile_parse_incomplete" in evidence_payload
    assert malformed_lockfile not in evidence_payload


def test_incomplete_lockfile_without_direct_package_target_still_fails_closed(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package-lock.json", '{"lockfileVersion":3,"packages":')
    store = GuardStore(tmp_path / "home")

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert result.packages[0]["name"] == "unresolved-lockfile"
    assert result.packages[0]["lockfileParseComplete"] is False
    assert any(reason["code"] == "lockfile_parse_incomplete" for reason in result.reasons)


def test_incomplete_lockfile_blocks_in_strict_mode(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    _write_text(workspace_dir / "package-lock.json", '{"lockfileVersion":99,"packages":{}}\n')
    store = GuardStore(home_dir)
    store.guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(store.guard_home / "config.toml", 'security_level = "strict"\n')

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.packages[0]["lockfileParseError"] == "unsupported_version"
