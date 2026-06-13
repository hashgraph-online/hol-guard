"""Phase 06 workspace audit daemon and inventory proofs."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.local_supply_chain import (
    audit_receipt_metadata,
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_supply_chain_audit_workspace_dir,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import (
    _dashboard_token_for,
    _read_json_response,
    _request,
)
from tests.test_guard_supply_chain_evaluator import (
    WORKSPACE_ID,
    _artifact_for_targets,
    _bundle_response,
    _force_cloud_fallback,
    _package,
)

WORKSPACE_AUDIT_NOW = "2026-06-08T12:00:00.000Z"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _seed_premium_entitlement(store: GuardStore) -> None:
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        WORKSPACE_AUDIT_NOW,
        workspace_id=WORKSPACE_ID,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": WORKSPACE_ID},
        WORKSPACE_AUDIT_NOW,
    )


def _audit_payload_for_workspace(
    tmp_path: Path,
    *,
    files: dict[str, str],
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> dict[str, object]:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    for relative_path, text in files.items():
        _write_text(workspace_dir / relative_path, text)
    store = GuardStore(home_dir)
    _seed_premium_entitlement(store)
    if monkeypatch is not None:
        monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
        store.cache_supply_chain_bundle(
            WORKSPACE_ID,
            _bundle_response(
                packages=[
                    _package(
                        ecosystem="npm",
                        name="minimist",
                        version="1.2.8",
                        default_action="block",
                        recommended_fix_version="1.2.9",
                    )
                ]
            ),
            WORKSPACE_AUDIT_NOW,
        )
        _force_cloud_fallback(monkeypatch)
    config = load_guard_config(store.guard_home)
    payload, _exit_code = build_workspace_audit_payload(
        command_name="audit",
        config=config,
        now=WORKSPACE_AUDIT_NOW,
        sbom_paths=(),
        store=store,
        workspace_dir=workspace_dir,
    )
    return payload


@pytest.mark.parametrize(
    ("manifest_name", "manifest_text", "lockfile_name", "lockfile_text", "expected_package"),
    [
        (
            "package.json",
            '{"dependencies":{"minimist":"^1.2.0"}}',
            "package-lock.json",
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"minimist": "^1.2.0"}},
                        "node_modules/minimist": {"version": "1.2.8"},
                    }
                }
            ),
            "minimist",
        ),
        (
            "package.json",
            '{"dependencies":{"minimist":"^1.2.0"}}',
            "pnpm-lock.yaml",
            """
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      minimist:
        specifier: ^1.2.0
        version: 1.2.8
packages:
  minimist@1.2.8:
    resolution: {integrity: sha512-demo}
""",
            "minimist",
        ),
        (
            "package.json",
            '{"dependencies":{"minimist":"^1.2.0"}}',
            "yarn.lock",
            """
__metadata:
  version: 4
  cacheKey: 8

"minimist@^1.2.0":
  version "1.2.8"
""",
            "minimist",
        ),
        (
            "package.json",
            '{"dependencies":{"minimist":"^1.2.0"}}',
            "bun.lock",
            """
[[package]]
name = "minimist"
version = "1.2.8"
resolved = "npm:minimist@1.2.8"
dependencies = []
""",
            "minimist",
        ),
        (
            "requirements.txt",
            "requests==2.31.0\n",
            None,
            None,
            "requests",
        ),
        (
            "pyproject.toml",
            '[project]\nname = "demo"\ndependencies = ["requests>=2.31.0"]\n',
            None,
            None,
            "requests",
        ),
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\nrequests = "^2.31.0"\n',
            "poetry.lock",
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            "requests",
        ),
        (
            "pyproject.toml",
            '[project]\nname = "demo"\ndependencies = ["requests>=2.31.0"]\n',
            "uv.lock",
            'version = 1\n[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            "requests",
        ),
        (
            "Pipfile",
            '[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n\n[packages]\nrequests = "*"\n',
            "Pipfile.lock",
            json.dumps(
                {
                    "_meta": {"hash": {"sha256": "demo"}},
                    "default": {"requests": {"version": "==2.31.0"}},
                }
            ),
            "requests",
        ),
        (
            "go.mod",
            "module example.com/demo\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
            "go.sum",
            "github.com/gin-gonic/gin v1.9.1 h1:demo\n",
            "github.com/gin-gonic/gin",
        ),
        (
            "Cargo.toml",
            '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
            "Cargo.lock",
            'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\n',
            "serde",
        ),
        (
            "composer.json",
            '{"require":{"laravel/framework":"^11.0"}}',
            "composer.lock",
            '{"packages":[{"name":"laravel/framework","version":"11.1.0"}]}',
            "laravel/framework",
        ),
        (
            "Gemfile",
            'source "https://rubygems.org"\ngem "rspec"\n',
            "Gemfile.lock",
            "GEM\n  specs:\n    rspec (3.13.0)\n",
            "rspec",
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.3</version></dependency></dependencies></project>\n",
            None,
            None,
            "org.example:demo",
        ),
        (
            "build.gradle",
            'dependencies { implementation("org.example:demo:1.2.3") }\n',
            "gradle.lockfile",
            "org.example:demo:1.2.3=compileClasspath\n",
            "org.example:demo",
        ),
    ],
)
def test_workspace_audit_inventory_includes_supported_lockfiles(
    tmp_path: Path,
    manifest_name: str,
    manifest_text: str,
    lockfile_name: str | None,
    lockfile_text: str | None,
    expected_package: str,
) -> None:
    files = {manifest_name: manifest_text}
    if lockfile_name is not None and lockfile_text is not None:
        files[lockfile_name] = lockfile_text
    payload = _audit_payload_for_workspace(tmp_path, files=files)
    assert manifest_name in payload["manifest_paths"]
    if lockfile_name is not None:
        assert lockfile_name in payload["lockfile_paths"]
    inventory = payload["inventory"]
    assert isinstance(inventory, dict)
    assert inventory["total_packages"] >= 1


def test_workspace_audit_returns_evaluation_not_posture_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _audit_payload_for_workspace(
        tmp_path,
        files={
            "package.json": '{"dependencies":{"minimist":"^1.2.0"}}',
            "package-lock.json": json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"minimist": "^1.2.0"}},
                        "node_modules/minimist": {"version": "1.2.8"},
                    }
                }
            ),
        },
        monkeypatch=monkeypatch,
    )
    evaluation = payload["evaluation"]
    assert isinstance(evaluation, dict)
    assert "decision" in evaluation
    assert "packages" in evaluation
    assert payload["inventory"]["total_packages"] >= 1


def test_workspace_audit_inference_uses_current_directory_with_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}')
    monkeypatch.chdir(workspace_dir)
    allowed_roots = (tmp_path.resolve(),)
    resolved = resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=None,
        workspace_value=None,
        allowed_roots=allowed_roots,
    )
    assert resolved == workspace_dir.resolve()


def test_workspace_audit_inference_accepts_workspace_alias(
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}')
    allowed_roots = (tmp_path.resolve(),)
    resolved = resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=None,
        workspace_value=str(workspace_dir),
        allowed_roots=allowed_roots,
    )
    assert resolved == workspace_dir.resolve()


def test_workspace_audit_inference_uses_active_managed_install_workspace(
    tmp_path: Path,
) -> None:
    active_dir = tmp_path / "active-workspace"
    active_dir.mkdir()
    _write_text(active_dir / "package.json", '{"name":"active"}')

    inactive_dir = tmp_path / "inactive-workspace"
    inactive_dir.mkdir()
    _write_text(inactive_dir / "package.json", '{"name":"inactive"}')

    store = GuardStore(tmp_path / "guard-home")
    store.set_managed_install("cursor", False, str(inactive_dir), {}, "2026-06-08T13:00:00.000Z")
    store.set_managed_install("codex", True, str(active_dir), {}, "2026-06-08T12:00:00.000Z")
    allowed_roots = (tmp_path.resolve(),)
    resolved = resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=None,
        workspace_value=None,
        allowed_roots=allowed_roots,
        managed_workspace_dirs=managed_install_audit_workspace_dirs(store),
    )
    assert resolved == active_dir.resolve()


def test_daemon_workspace_audit_uses_managed_install_workspace_when_cwd_is_not_a_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}')
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
    )
    store = GuardStore(tmp_path / "guard-home")
    store.set_managed_install("codex", True, str(workspace_dir), {}, WORKSPACE_AUDIT_NOW)
    _seed_premium_entitlement(store)
    monkeypatch.chdir(empty_dir)

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["operation"] == "audit"


def test_workspace_audit_never_reads_env_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_paths: list[str] = []
    original_read_text = Path.read_text

    def tracked_read_text(self: Path, *args: object, **kwargs: object) -> str:
        read_paths.append(str(self))
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", tracked_read_text)
    payload = _audit_payload_for_workspace(
        tmp_path,
        files={
            "package.json": '{"dependencies":{"minimist":"^1.2.0"}}',
            ".env": "SENTINEL_SHOULD_NOT_BE_READ=demo\n",
        },
    )
    assert payload["manifest_paths"] == ["package.json"]
    assert not any(path.endswith(".env") for path in read_paths)


def test_workspace_audit_reports_bun_lockb_warning(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"dependencies":{"minimist":"^1.2.0"}}')
    (workspace_dir / "bun.lockb").write_bytes(b"bunlock")
    store = GuardStore(tmp_path / "guard-home")
    config = load_guard_config(store.guard_home)
    payload, _exit_code = build_workspace_audit_payload(
        command_name="audit",
        config=config,
        now=WORKSPACE_AUDIT_NOW,
        sbom_paths=(),
        store=store,
        workspace_dir=workspace_dir,
    )
    warnings = payload.get("lockfile_warnings")
    assert isinstance(warnings, list)
    assert any(item.get("code") == "bun_lockfile_binary_fallback" for item in warnings if isinstance(item, dict))


def test_workspace_audit_inventory_marks_direct_and_transitive_packages(tmp_path: Path) -> None:
    payload = _audit_payload_for_workspace(
        tmp_path,
        files={
            "package.json": '{"dependencies":{"react":"^18.0.0"}}',
            "package-lock.json": json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"react": "^18.0.0"}},
                        "node_modules/react": {"version": "18.0.0"},
                        "node_modules/react/node_modules/minimist": {"version": "1.2.8"},
                    }
                }
            ),
        },
    )
    inventory = payload["inventory"]
    assert isinstance(inventory, dict)
    assert inventory["direct_package_count"] >= 1
    assert inventory["transitive_package_count"] >= 1


def test_workspace_audit_lockfile_evaluation_preserves_dependency_path_and_fix_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"dependencies":{"react":"^18.0.0"}}')
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"react": "^18.0.0"}},
                    "node_modules/react": {"version": "18.0.0"},
                    "node_modules/react/node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(
                    ecosystem="npm",
                    name="minimist",
                    version="1.2.8",
                    default_action="block",
                    recommended_fix_version="1.2.9",
                )
            ]
        ),
        WORKSPACE_AUDIT_NOW,
    )
    _force_cloud_fallback(monkeypatch)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now=WORKSPACE_AUDIT_NOW,
    )
    transitive = next(package for package in result.packages if package["name"] == "minimist")
    assert transitive["direct"] is False
    assert transitive["dependencyPath"] == "react/node_modules/minimist"
    assert transitive["recommendedFixVersion"] == "1.2.9"


def test_daemon_workspace_audit_persists_receipt_and_queues_cloud_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}')
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
    )
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=WORKSPACE_AUDIT_NOW,
        request_id="connect-1",
    )
    sync_finished = threading.Event()

    def fake_sync_local_guard_cloud_proof(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        sync_finished.set()
        return {"synced_at": WORKSPACE_AUDIT_NOW, "receipts_stored": 1}

    monkeypatch.setattr(daemon_server, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof, raising=False)
    monkeypatch.chdir(workspace_dir)

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["operation"] == "audit"
    assert payload["result"]["evaluation"]["decision"] in {"block", "ask", "monitor", "warn"}
    assert payload["cloud_sync"] == {
        "status": "queued",
        "message": "Guard Cloud sync started.",
    }
    assert sync_finished.wait(timeout=2)
    receipts = store.list_receipts(limit=5, harness="package-firewall")
    assert receipts
    assert receipts[0]["artifact_name"] == "Workspace supply-chain audit"
    evidence = receipts[0]["scanner_evidence"]
    assert isinstance(evidence, list)
    assert evidence[0]["operation"] == "audit"


def test_daemon_workspace_audit_requires_workspace_when_uninferable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    monkeypatch.chdir(empty_dir)
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "workspace_dir_required"


def test_audit_receipt_metadata_includes_prioritized_package_findings() -> None:
    metadata = audit_receipt_metadata(
        {
            "lockfile_paths": ["package-lock.json"],
            "manifest_paths": ["package.json"],
            "inventory": {"total_packages": 3},
            "evaluation": {
                "decision": "warn",
                "packages": [
                    {
                        "name": "clean-lib",
                        "ecosystem": "npm",
                        "decision": "monitor",
                        "reasons": [],
                    },
                    {
                        "name": "risky-lib",
                        "ecosystem": "npm",
                        "decision": "block",
                        "reasons": [{"code": "known_malware", "message": "known malware", "severity": "critical"}],
                    },
                ],
            },
        }
    )

    evidence = metadata["scanner_evidence"]
    assert isinstance(evidence, dict)
    findings = evidence.get("package_findings")
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0]["name"] == "risky-lib"


def test_workspace_audit_without_inventory_marks_incomplete_and_sync_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package-lock.json", "{}")
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    config = load_guard_config(store.guard_home)
    payload, exit_code = build_workspace_audit_payload(
        command_name="audit",
        config=config,
        now=WORKSPACE_AUDIT_NOW,
        sbom_paths=(),
        store=store,
        workspace_dir=workspace_dir,
    )
    assert exit_code == 1
    assert payload["audit_status"] == "incomplete"
    assert payload["audit_outcome"] == "sync_required"
    assert payload["lockfile_paths"] == ["package-lock.json"]
    metadata = audit_receipt_metadata(payload, workspace_dir=workspace_dir)
    evidence = metadata["scanner_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["audit_status"] == "incomplete"
    assert evidence["total_packages"] == 0


def test_workspace_audit_daemon_reports_incomplete_status_for_empty_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package-lock.json", "{}")
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={"workspace_dir": str(workspace_dir)},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["status"] == "incomplete"
    assert payload["result"]["audit_status"] == "incomplete"
    assert payload["result"]["exit_code"] == 1
