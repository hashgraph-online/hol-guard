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


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


WORKSPACE_ID = "2de4fcb4-a5b2-447a-a67f-21c6eb4c5f3c"


def test_normalized_supply_chain_batch_url_preserves_sync_prefix() -> None:
    assert (
        local_supply_chain_module._normalized_supply_chain_batch_url(
            "https://guard.example/api/guard/receipts/sync", WORKSPACE_ID
        )
        == f"https://guard.example/api/guard/supply-chain/evaluate/batch?workspaceId={WORKSPACE_ID}"
    )
    assert (
        local_supply_chain_module._normalized_supply_chain_batch_url(
            "https://guard.example/registry/api/v1/guard/receipts/sync?workspaceId=old", WORKSPACE_ID
        )
        == f"https://guard.example/registry/api/v1/guard/supply-chain/evaluate/batch?workspaceId={WORKSPACE_ID}"
    )


def test_cloud_workspace_audit_renews_dpop_proof_for_each_page(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = local_supply_chain_module._runtime_runner_module()
    signed_proofs: list[str] = []
    request_bodies: list[dict[str, object]] = []

    def _fake_guard_sync_headers(
        auth_context: dict[str, object],
        *,
        request_url: str,
        method: str,
    ) -> dict[str, str]:
        del auth_context, request_url, method
        proof = f"proof-{len(signed_proofs) + 1}"
        signed_proofs.append(proof)
        return {
            "Authorization": "Bearer token",
            "Content-Type": "application/json",
            "DPoP": proof,
        }

    class _JsonResponse(io.StringIO):
        def __enter__(self) -> _JsonResponse:
            return self

        def __exit__(self, *args: object) -> None:
            self.close()

    def _fake_urlopen(request: object, timeout: int) -> _JsonResponse:
        del timeout
        assert isinstance(request, local_supply_chain_module.urllib.request.Request)
        dpop_header = dict(request.header_items()).get("Dpop")
        assert dpop_header == f"proof-{len(request_bodies) + 1}"
        body = request.data
        assert isinstance(body, bytes)
        request_bodies.append(json.loads(body.decode("utf-8")))
        if len(request_bodies) == 1:
            return _JsonResponse(
                json.dumps(
                    {
                        "decision": "monitor",
                        "packages": [{"ecosystem": "npm", "name": "react"}],
                        "reasons": [],
                        "nextCursor": "cursor-1",
                        "processedCount": 2,
                        "totalPackages": 3,
                    }
                )
            )
        return _JsonResponse(
            json.dumps(
                {
                    "decision": "monitor",
                    "packages": [{"ecosystem": "npm", "name": "scheduler"}],
                    "processedCount": 1,
                    "reasons": [],
                    "totalPackages": 2,
                }
            )
        )

    monkeypatch.setattr(runner, "_guard_sync_headers", _fake_guard_sync_headers)
    monkeypatch.setattr(local_supply_chain_module.urllib.request, "urlopen", _fake_urlopen)

    response, fallback = local_supply_chain_module._run_cloud_workspace_audit(
        auth_context={
            "access_token": "token",
            "sync_url": "https://guard.example/api/guard/receipts/sync",
        },
        request_payload={
            "mode": "paged",
            "packages": [
                {"ecosystem": "npm", "name": "react"},
                {"ecosystem": "npm", "name": "scheduler"},
            ],
            "pageSize": 1,
            "workspaceFingerprint": "fingerprint-1",
        },
        workspace_id=WORKSPACE_ID,
    )

    assert fallback is None
    assert response is not None
    assert [item["name"] for item in response["packages"]] == ["react", "scheduler"]
    assert response["processedCount"] == 3
    assert response["totalPackages"] == 3
    assert signed_proofs == ["proof-1", "proof-2"]
    assert request_bodies[0].get("cursor") is None
    assert request_bodies[1]["cursor"] == "cursor-1"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _seed_premium_pairing(store: GuardStore, *, now: str) -> None:
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
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


def test_sync_managed_workspace_audits_enqueues_persisted_job_mode_for_managed_workspaces(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"react":"18.2.0"}}\n',
    )
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"react": "18.2.0"}},
                    "node_modules/react": {"version": "18.2.0"},
                },
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    store.set_managed_install("codex", True, str(workspace_dir), {}, "2026-05-25T10:00:00+00:00")
    captured_payloads: list[dict[str, object]] = []

    def _fake_enqueue_job(**kwargs: object) -> dict[str, object]:
        request_payload = kwargs.get("request_payload")
        assert isinstance(request_payload, dict)
        captured_payloads.append(request_payload)
        return {"jobId": "job-1", "status": "queued"}

    monkeypatch.setattr(local_supply_chain_module, "_enqueue_cloud_workspace_audit_job", _fake_enqueue_job)
    monkeypatch.setattr(
        local_supply_chain_module,
        "_poll_cloud_workspace_audit_job",
        lambda **_kwargs: {"jobId": "job-1", "status": "completed"},
    )

    summary = local_supply_chain_module.sync_managed_workspace_audits(
        store,
        auth_context={
            "access_token": "token",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
    )

    assert captured_payloads
    assert captured_payloads[0]["mode"] == "job"
    assert captured_payloads[0]["pageSize"] == 1
    assert summary["status"] == "synced"
    assert summary["completed_jobs"] == 1
    assert summary["failed_jobs"] == 0
    assert summary["workspaces"][0]["job_id"] == "job-1"
    assert summary["workspaces"][0]["package_count"] == 1


def test_sync_managed_workspace_audits_reports_partial_when_cloud_visible_count_is_lower(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        json.dumps({"name": "demo", "dependencies": {"react": "18.2.0"}}, sort_keys=True) + "\n",
    )
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"react": "18.2.0"}},
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/scheduler": {"version": "0.23.2"},
                    "node_modules/loose-envify": {"version": "1.4.0"},
                },
            },
            sort_keys=True,
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_premium_pairing(store, now="2026-05-25T10:00:00+00:00")
    store.set_managed_install("codex", True, str(workspace_dir), {}, "2026-05-25T10:00:00+00:00")

    monkeypatch.setattr(
        local_supply_chain_module,
        "_enqueue_cloud_workspace_audit_job",
        lambda **_kwargs: {"jobId": "job-1", "status": "queued"},
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "_poll_cloud_workspace_audit_job",
        lambda **_kwargs: {
            "jobId": "job-1",
            "status": "completed",
            "processedCount": 2,
            "totalPackages": 2,
        },
    )

    summary = local_supply_chain_module.sync_managed_workspace_audits(
        store,
        auth_context={
            "access_token": "token",
            "sync_url": "https://guard.example/api/guard/receipts/sync",
        },
    )

    workspace = summary["workspaces"][0]
    assert summary["status"] == "partial"
    assert summary["incomplete_jobs"] == 1
    assert workspace["status"] == "partial"
    assert workspace["package_count"] == 3
    assert workspace["cloud_visible_count"] == 2
    assert "2 of 3 visible" in str(workspace["message"])


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


def test_build_cloud_audit_payload_includes_workspace_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    (workspace_dir / ".git").mkdir(parents=True)
    _write_text(
        workspace_dir / ".git" / "config",
        '[remote "origin"]\n\turl = git@github.com:hashgraph-online/hol-points-portal.git\n',
    )
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    _write_text(workspace_dir / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
    monkeypatch.setattr(local_supply_chain_module.socket, "gethostname", lambda: "macbook-pro")

    class _Store:
        def get_sync_payload(self, _key: str) -> dict[str, str]:
            return {"policy_hash": "policy-hash-1"}

    payload = local_supply_chain_module._build_cloud_audit_payload(
        workspace_dir=workspace_dir,
        workspace_id=WORKSPACE_ID,
        store=_Store(),
        manifest_paths=("package.json",),
        lockfile_paths=("pnpm-lock.yaml",),
        inventory=(
            {
                "direct": True,
                "ecosystem": "npm",
                "name": "minimist",
                "version": "1.2.5",
            },
        ),
    )

    assert payload["workspaceContext"] == {
        "agent": "guard-cli",
        "codebase": "hashgraph-online/hol-points-portal",
        "folderPath": local_supply_chain_module._redacted_workspace_folder_path(workspace_dir),
        "lockfilePaths": ["pnpm-lock.yaml"],
        "machine": "macbook-pro",
        "manifestPaths": ["package.json"],
        "packageManager": "npm",
        "workspaceName": "workspace",
    }


def test_workspace_context_redacts_path_and_handles_hostname_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_os_error() -> str:
        raise OSError("hostname unavailable")

    monkeypatch.setattr(local_supply_chain_module.socket, "gethostname", _raise_os_error)

    payload = local_supply_chain_module._build_workspace_context_payload(
        Path("/Users/alice/projects/app"),
        ("package.json",),
        ("package-lock.json",),
    )

    assert payload["codebase"] == "app"
    assert payload["folderPath"] == "~/projects/app"
    assert payload["machine"] is None
    assert local_supply_chain_module._redacted_workspace_folder_path(Path("/workspace/app")) == "…/workspace/app"
    assert (
        local_supply_chain_module._codebase_label_from_remote(
            "git@gitlab.com:team/backend/service.git",
        )
        == "team/backend/service"
    )


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


def test_audit_receipt_metadata_enriches_cloud_advisory_aliases_from_bundle(
    tmp_path: Path,
) -> None:
    from tests.test_guard_local_supply_chain_phase15 import _bundle_response, _package

    home_dir = tmp_path / "guard-home"
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(
                    name="minimist",
                    version="1.2.5",
                    default_action="block",
                )
            ]
        ),
        "2026-05-25T10:00:00+00:00",
    )

    payload = {
        "evaluation": {
            "decision": "block",
            "packages": [
                {
                    "name": "minimist",
                    "ecosystem": "npm",
                    "decision": "block",
                    "reasons": [{"code": "known_malware", "message": "known malware", "severity": "critical"}],
                    "advisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                }
            ],
        },
        "inventory": {"total_packages": 1},
        "manifest_paths": ["package.json"],
        "lockfile_paths": ["package-lock.json"],
    }
    metadata = local_supply_chain_module.audit_receipt_metadata(payload, store=store)
    findings = metadata["scanner_evidence"]["package_findings"]
    assert findings
    aliases = findings[0].get("advisoryAliases")
    assert isinstance(aliases, list)
    assert "GHSA-VH95-RMGR-6W4M" in aliases
    assert "CVE-2020-7598" in aliases
