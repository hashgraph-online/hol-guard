"""Phase 16 workspace audit CLI coverage."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE_ID = "2de4fcb4-a5b2-447a-a67f-21c6eb4c5f3c"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _seed_premium_pairing(store: GuardStore, *, now: str) -> None:
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        now,
        workspace_id=WORKSPACE_ID,
    )
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "advisory_count": 2,
            "bundle_version": "1747612800000-deadbeef",
            "ecosystem_support": [
                {"ecosystem": "npm", "support_level": "protected", "label": "Protected"},
                {"ecosystem": "pypi", "support_level": "protected", "label": "Protected"},
            ],
            "feed_snapshot_hash": "feed-snapshot-1",
            "package_count": 2,
            "policy_hash": "policy-hash-1",
            "status": "synced",
            "synced_at": now,
            "tier": "premium",
            "workspace_id": WORKSPACE_ID,
        },
        now,
    )


class _FakeEvaluation:
    def __init__(self, *, decision: str) -> None:
        self.decision = decision

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "packages": [{"name": "minimist", "decision": self.decision}],
            "reasons": [{"code": "local_fallback", "message": "local fallback"}],
            "enforcement": "local_fallback",
        }


def test_guard_supply_chain_scan_uses_cloud_batch_for_premium_workspaces(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.0","chalk":"^5.3.0"}}\n',
    )
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0", "chalk": "^5.3.0"}},
                    "node_modules/minimist": {"version": "1.2.5"},
                    "node_modules/chalk": {"version": "5.3.0"},
                },
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    captured: dict[str, object] = {}

    def _fake_cloud_audit(**kwargs: object) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        captured.update(kwargs)
        return (
            {
                "decision": "block",
                "packages": [
                    {
                        "name": "minimist",
                        "ecosystem": "npm",
                        "namespace": None,
                        "decision": "block",
                        "reasons": [{"code": "known_malware", "message": "known malware"}],
                        "status": "known",
                        "requestedVersion": "^1.2.0",
                        "resolvedVersion": "1.2.5",
                        "recommendedFixVersion": "1.2.9",
                        "riskScore": 980,
                        "advisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                        "sourceKeys": ["ghsa"],
                        "sourceStale": False,
                    }
                ],
                "reasons": [{"code": "known_malware", "message": "known malware"}],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 2,
                "totalPackages": 2,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        )

    monkeypatch.setattr(local_supply_chain_module, "_run_cloud_workspace_audit", _fake_cloud_audit)

    rc = main(
        [
            "guard",
            "supply-chain",
            "scan",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert output["mode"] == "scan"
    assert output["source"] == "cloud"
    assert output["evaluation"]["decision"] == "block"
    assert output["inventory"]["total_packages"] == 2
    assert {item["name"] for item in captured["request_payload"]["packages"]} == {"minimist", "chalk"}


def test_guard_supply_chain_audit_alias_accepts_sbom_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    sbom_path = workspace_dir / "sbom.json"
    _write_text(
        sbom_path,
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "@scope/left-pad",
                        "version": "1.2.5",
                        "purl": "pkg:npm/%40scope/left-pad@1.2.5",
                    }
                ],
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    captured: dict[str, object] = {}

    def _fake_cloud_audit(**kwargs: object) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        captured.update(kwargs)
        return (
            {
                "decision": "warn",
                "packages": [],
                "reasons": [],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 1,
                "totalPackages": 1,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        )

    monkeypatch.setattr(local_supply_chain_module, "_run_cloud_workspace_audit", _fake_cloud_audit)

    rc = main(
        [
            "guard",
            "supply-chain",
            "audit",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--sbom",
            str(sbom_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["mode"] == "audit"
    assert output["sbom_paths"] == ["sbom.json"]
    assert output["inventory"]["sbom_package_count"] == 1
    assert captured["request_payload"]["packages"] == [
        {"direct": False, "ecosystem": "npm", "name": "left-pad", "namespace": "@scope", "version": "1.2.5"}
    ]


def test_guard_supply_chain_scan_falls_back_locally_when_cloud_audit_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")

    monkeypatch.setattr(
        local_supply_chain_module,
        "_run_cloud_workspace_audit",
        lambda **_kwargs: (
            None,
            {"code": "cloud_timeout", "message": "Guard cloud evaluation timed out, so Guard fell back locally."},
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _FakeEvaluation(decision="block"),
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "scan",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert output["source"] == "local"
    assert output["fallback_reason"]["code"] == "cloud_timeout"
    assert output["evaluation"]["decision"] == "block"


def test_guard_supply_chain_audit_payload_excludes_source_snippets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        json.dumps(
            {
                "name": "demo",
                "description": "do-not-upload-this-description",
                "scripts": {"postinstall": "echo super-secret-token"},
                "dependencies": {"minimist": "^1.2.0"},
            }
        )
        + "\n",
    )
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.5"},
                },
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    captured: dict[str, object] = {}

    def _fake_cloud_audit(**kwargs: object) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        captured.update(kwargs)
        return (
            {
                "decision": "monitor",
                "packages": [],
                "reasons": [],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 1,
                "totalPackages": 1,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        )

    monkeypatch.setattr(local_supply_chain_module, "_run_cloud_workspace_audit", _fake_cloud_audit)

    rc = main(
        [
            "guard",
            "supply-chain",
            "audit",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    request_json = json.dumps(captured["request_payload"], sort_keys=True)

    assert rc == 0
    assert "super-secret-token" not in request_json
    assert "do-not-upload-this-description" not in request_json
    assert str(workspace_dir) not in request_json


def test_guard_supply_chain_audit_ci_fail_on_high_returns_distinct_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")

    monkeypatch.setattr(
        local_supply_chain_module,
        "_run_cloud_workspace_audit",
        lambda **_kwargs: (
            {
                "decision": "warn",
                "packages": [
                    {
                        "name": "minimist",
                        "ecosystem": "npm",
                        "namespace": None,
                        "decision": "warn",
                        "reasons": [{"code": "high_risk", "message": "high risk", "severity": "high"}],
                        "status": "known",
                    }
                ],
                "reasons": [{"code": "high_risk", "message": "high risk", "severity": "high"}],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 1,
                "totalPackages": 1,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        ),
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "audit",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--ci",
            "--fail-on",
            "high",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 3
    assert output["ci"]["matched"] is True
    assert output["ci"]["threshold"] == "high"
    assert output["ci"]["matched_packages"] == ["minimist"]


def test_guard_supply_chain_audit_before_after_limits_inventory_to_changed_dependencies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    before_dir.mkdir()
    after_dir.mkdir()
    _write_text(
        before_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.0","chalk":"^5.3.0"}}\n',
    )
    _write_text(
        after_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.8","chalk":"^5.3.0"}}\n',
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    captured: dict[str, object] = {}

    def _fake_cloud_audit(**kwargs: object) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        captured.update(kwargs)
        return (
            {
                "decision": "monitor",
                "packages": [],
                "reasons": [],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 1,
                "totalPackages": 1,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        )

    monkeypatch.setattr(local_supply_chain_module, "_run_cloud_workspace_audit", _fake_cloud_audit)

    rc = main(
        [
            "guard",
            "supply-chain",
            "audit",
            "--home",
            str(home_dir),
            "--before-workspace",
            str(before_dir),
            "--after-workspace",
            str(after_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["diff"]["changed_package_count"] == 1
    assert captured["request_payload"]["packages"] == [
        {"direct": True, "ecosystem": "npm", "name": "minimist", "namespace": None, "range": "^1.2.8"}
    ]


def test_guard_supply_chain_audit_handles_large_workspace_and_prioritizes_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    dependencies = {f"pkg-{index}": "^1.0.0" for index in range(10_050)}
    _write_text(
        workspace_dir / "package.json",
        json.dumps({"name": "large-workspace", "dependencies": dependencies}, sort_keys=True) + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    captured: dict[str, object] = {}

    def _fake_cloud_audit(**kwargs: object) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        captured.update(kwargs)
        return (
            {
                "decision": "warn",
                "packages": [
                    {
                        "name": "critical-lib",
                        "ecosystem": "npm",
                        "namespace": None,
                        "decision": "block",
                        "reasons": [{"code": "known_malware", "message": "known malware", "severity": "critical"}],
                        "status": "known",
                    },
                    {
                        "name": "medium-lib",
                        "ecosystem": "npm",
                        "namespace": None,
                        "decision": "warn",
                        "reasons": [{"code": "outdated", "message": "outdated dependency", "severity": "medium"}],
                        "status": "known",
                    },
                ],
                "reasons": [{"code": "known_malware", "message": "known malware", "severity": "critical"}],
                "enforcement": "premium_cloud",
                "entitlementState": "premium",
                "cacheStatus": "miss",
                "processedCount": 10_050,
                "totalPackages": 10_050,
                "status": "completed",
                "workspaceId": WORKSPACE_ID,
            },
            None,
        )

    monkeypatch.setattr(local_supply_chain_module, "_run_cloud_workspace_audit", _fake_cloud_audit)

    rc = main(
        [
            "guard",
            "supply-chain",
            "audit",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    request_packages = captured["request_payload"]["packages"]

    assert rc == 0
    assert output["mode"] == "audit"
    assert output["source"] == "cloud"
    assert output["inventory"]["total_packages"] == 10_050
    assert isinstance(request_packages, list)
    assert len(request_packages) == 10_050
    assert output["evaluation"]["packages"][0]["name"] == "critical-lib"


def test_read_sbom_text_rejects_oversized_files(tmp_path: Path) -> None:
    sbom_path = tmp_path / "oversized-sbom.json"
    sbom_path.write_text("x" * ((10 * 1024 * 1024) + 1), encoding="utf-8")

    assert local_supply_chain_module._read_sbom_text(sbom_path) is None


def test_run_cloud_workspace_audit_falls_back_after_page_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse(io.StringIO):
        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            self.close()

    monkeypatch.setattr(
        local_supply_chain_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _FakeResponse(
            json.dumps(
                {
                    "decision": "monitor",
                    "packages": [],
                    "reasons": [],
                    "enforcement": "premium_cloud",
                    "entitlementState": "premium",
                    "cacheStatus": "miss",
                    "processedCount": 1,
                    "totalPackages": 1,
                    "status": "completed",
                    "workspaceId": WORKSPACE_ID,
                    "nextCursor": "repeat",
                }
            )
        ),
    )

    response, fallback_reason = local_supply_chain_module._run_cloud_workspace_audit(
        request_payload={
            "commandShape": {
                "argCount": 3,
                "flags": [],
                "packageManager": "npm",
                "redacted": True,
                "verb": "audit",
            },
            "harness": "guard-cli",
            "mode": "paged",
            "pageSize": 1,
            "packages": [{"direct": True, "ecosystem": "npm", "name": "minimist", "version": "1.2.5"}],
            "policyVersion": "policy-hash-1",
            "workspaceFingerprint": "workspace-fingerprint",
        },
        sync_url="https://hol.org/api/guard/receipts/sync",
        token="demo-token",
        workspace_id=WORKSPACE_ID,
    )

    assert response is None
    assert fallback_reason == {
        "code": "cloud_page_limit",
        "message": "Guard cloud evaluation exceeded the maximum page count, so Guard fell back locally.",
    }


def test_guard_supply_chain_scan_falls_back_when_oauth_refresh_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n',
    )
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.5"},
                },
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")

    monkeypatch.setattr(
        local_supply_chain_module,
        "_resolve_guard_sync_auth_context",
        lambda _store: (_ for _ in ()).throw(GuardSyncAuthorizationExpiredError("expired")),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _FakeEvaluation(decision="warn"),
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "scan",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["source"] == "local"
    assert output["evaluation"]["decision"] == "warn"
    assert output["fallback_reason"] == {
        "code": "cloud_auth_error",
        "message": "Guard cloud authorization could not be refreshed, so Guard fell back locally.",
    }
