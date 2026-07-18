"""Behavior tests for install-time Guard protection."""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from subprocess import CompletedProcess
from typing import ClassVar

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import protect
from codex_plugin_scanner.guard.advisory_model import ProtectTargetIdentity, advisory_matches_target
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.redaction import redact_text
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_sync_credentials(home_dir, sync_url: str, token: str = "demo-token") -> None:
    _seed_guard_cloud(GuardStore(home_dir), sync_url=sync_url, token=token)


class _SyncRequestHandler(BaseHTTPRequestHandler):
    response_payload: ClassVar[dict[str, object]] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.response_payload).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class _SyncAndEvaluateHandler(BaseHTTPRequestHandler):
    sync_payload: ClassVar[dict[str, object]] = {}
    evaluate_status: ClassVar[int] = 401

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        if "supply-chain/evaluate" in self.path:
            self.send_response(self.evaluate_status)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.sync_payload).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


def _seed_bundle_cache_only(
    home_dir: Path,
    *,
    ecosystem: str,
    package_name: str,
    package_version: str,
    action: str,
) -> None:
    from tests.test_guard_package_shims import WORKSPACE_ID, _bundle_response

    store = GuardStore(home_dir)
    response = _bundle_response(
        action=action,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
    )
    bundle = response["bundle"]
    assert isinstance(bundle, dict)
    now = str(bundle["generatedAt"])
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, now)
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": bundle["bundleVersion"],
            "key_id": bundle["keyId"],
            "policy_hash": bundle["policyHash"],
            "tier": bundle["tier"],
            "workspace_id": WORKSPACE_ID,
        },
        now,
    )


class TestGuardProtect:
    def test_guard_protect_blocks_advisory_before_install(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        store.cache_advisories(
            [
                {
                    "id": "adv-block-1",
                    "ecosystem": "claude-code",
                    "endpoint_indicators": ["evil.example/install"],
                    "severity": "high",
                    "action": "block",
                    "headline": "Known risky endpoint.",
                }
            ],
            _now(),
        )

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "claude",
                "mcp",
                "add",
                "remote-risk",
                "https://evil.example/install",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "block"
        assert output["executed"] is False
        assert output["matched_advisories"][0]["id"] == "adv-block-1"
        assert store.list_events(limit=1)[0]["event_name"] == "install_time_block"

    def test_guard_protect_executes_safe_custom_command(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        output_path = workspace_dir / "installed.txt"

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                sys.executable,
                "-c",
                f"from pathlib import Path; Path(r'{output_path}').write_text('ok', encoding='utf-8')",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["verdict"]["action"] == "allow"
        assert output["executed"] is True
        assert output["execution"]["returncode"] == 0
        assert output_path.read_text(encoding="utf-8") == "ok"

    def test_guard_protect_redacts_execution_output_before_json_payload(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        stdout_value = "Bearer sk-live-secret-token\nDATABASE_URL=postgres://user:pass@db.internal/app\n"
        stderr_value = "npm token=npm_super_secret_value\n"

        def fake_run(*args, **kwargs) -> CompletedProcess[str]:
            return CompletedProcess(
                args[0],
                0,
                stdout=stdout_value,
                stderr=stderr_value,
            )

        monkeypatch.setattr(protect.subprocess, "run", fake_run)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                sys.executable,
                "-c",
                "print('ok')",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["execution"]["stdout"] != stdout_value
        assert output["execution"]["stderr"] != stderr_value
        assert "sk-live-secret-token" not in output["execution"]["stdout"]
        assert "postgres://user:pass@db.internal/app" not in output["execution"]["stdout"]
        assert "npm_super_secret_value" not in output["execution"]["stderr"]
        assert output["execution"]["stdout_redactions"]["count"] >= 2
        assert output["execution"]["stderr_redactions"]["count"] >= 1

    def test_guard_protect_does_not_persist_allow_receipt_when_execution_fails(
        self,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                sys.executable,
                "-c",
                "import sys; sys.exit(7)",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 7
        assert output["verdict"]["action"] == "allow"
        assert output["executed"] is True
        assert output["execution"]["returncode"] == 7
        assert store.list_receipts(limit=10) == []

    def test_guard_protect_intercepts_codex_mcp_add_remote_endpoint(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "codex",
                "mcp",
                "add",
                "remote-risk",
                "--url",
                "https://evil.example/mcp",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "review"
        assert output["executed"] is False
        assert output["targets"][0]["artifact_type"] == "mcp_server"
        assert "remote server" in output["verdict"]["reason"].lower()

    def test_guard_protect_intercepts_claude_mcp_add_remote_endpoint(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "claude",
                "mcp",
                "add",
                "remote-risk",
                "https://evil.example/mcp",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "review"
        assert output["executed"] is False
        assert output["targets"][0]["artifact_type"] == "mcp_server"
        assert output["targets"][0]["artifact_id"] == "install:claude-code:mcp:remote-risk"
        assert "remote server" in output["verdict"]["reason"].lower()

    def test_guard_protect_intercepts_claude_mcp_add_remote_endpoint_after_flags(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "claude",
                "mcp",
                "add",
                "--transport",
                "http",
                "remote-risk",
                "https://evil.example/mcp",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "review"
        assert output["executed"] is False
        assert output["targets"][0]["artifact_id"] == "install:claude-code:mcp:remote-risk"
        assert output["targets"][0]["source_url"] == "https://evil.example/mcp"

    def test_guard_protect_intercepts_opencode_plugin_and_skill_installs(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        plugin_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "opencode",
                "plugin",
                "install",
                "fixture-plugin",
                "--url",
                "https://example.invalid/opencode-plugin.tgz",
            ]
        )
        plugin_output = json.loads(capsys.readouterr().out)

        skill_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "opencode",
                "skill",
                "install",
                "fixture-skill",
                "--url",
                "https://example.invalid/opencode-skill.tgz",
            ]
        )
        skill_output = json.loads(capsys.readouterr().out)

        assert plugin_rc == 2
        assert plugin_output["executed"] is False
        assert plugin_output["targets"][0]["artifact_type"] == "plugin"
        assert plugin_output["targets"][0]["artifact_id"] == "install:opencode:fixture-plugin"
        assert skill_rc == 2
        assert skill_output["executed"] is False
        assert skill_output["targets"][0]["artifact_type"] == "skill"
        assert skill_output["targets"][0]["artifact_id"] == "install:opencode:fixture-skill"

    def test_guard_protect_intercepts_gemini_skill_installs_and_mcp_additions(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        skill_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "gemini",
                "skills",
                "install",
                "https://example.invalid/skills/review-skill.git",
                "--scope",
                "user",
            ]
        )
        skill_output = json.loads(capsys.readouterr().out)

        mcp_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "gemini",
                "mcp",
                "add",
                "remote-risk",
                "https://evil.example/mcp",
                "--transport",
                "http",
                "--scope",
                "user",
            ]
        )
        mcp_output = json.loads(capsys.readouterr().out)

        assert skill_rc == 2
        assert skill_output["executed"] is False
        assert skill_output["targets"][0]["artifact_type"] == "skill"
        assert skill_output["targets"][0]["artifact_id"] == "install:gemini:skill:review-skill"
        assert mcp_rc == 2
        assert mcp_output["executed"] is False
        assert mcp_output["targets"][0]["artifact_type"] == "mcp_server"
        assert mcp_output["targets"][0]["artifact_id"] == "install:gemini:mcp:remote-risk"

    def test_guard_protect_keeps_gemini_stdio_mcp_targets_local(self) -> None:
        request = protect.parse_protect_command(
            [
                "gemini",
                "mcp",
                "add",
                "stdio-risk",
                "https://example.invalid/not-a-remote-endpoint",
                "--transport",
                "stdio",
            ]
        )

        assert request.targets[0].source_url is None
        assert "registers a remote server endpoint" not in protect._request_risk_signals(request)

    def test_guard_protect_parses_claude_add_json_payload(self) -> None:
        request = protect.parse_protect_command(
            [
                "claude",
                "mcp",
                "add-json",
                "remote-risk",
                '{"transport":"sse","url":"https://example.invalid/mcp"}',
            ]
        )

        assert request.harness == "claude-code"
        assert request.targets[0].artifact_id == "install:claude-code:mcp:remote-risk"
        assert request.targets[0].source_url == "https://example.invalid/mcp"

    def test_guard_protect_intercepts_antigravity_extension_and_mcp_registration(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)

        extension_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "antigravity",
                "--install-extension",
                "hashgraph.tools",
            ]
        )
        extension_output = json.loads(capsys.readouterr().out)

        mcp_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "antigravity",
                "--add-mcp",
                '{"name":"remote-risk","url":"https://evil.example/mcp"}',
            ]
        )
        mcp_output = json.loads(capsys.readouterr().out)

        assert extension_rc == 2
        assert extension_output["executed"] is False
        assert extension_output["targets"][0]["artifact_type"] == "extension"
        assert extension_output["targets"][0]["artifact_id"] == "install:antigravity:extension:hashgraph.tools"
        assert mcp_rc == 2
        assert mcp_output["executed"] is False
        assert mcp_output["targets"][0]["artifact_type"] == "mcp_server"
        assert mcp_output["targets"][0]["artifact_id"] == "install:antigravity:mcp:remote-risk"

    def test_guard_protect_uses_configurable_execution_timeout(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        captured: dict[str, object] = {}

        def fake_run(*args, **kwargs) -> CompletedProcess[str]:
            captured["timeout"] = kwargs["timeout"]
            return CompletedProcess(args[0], 0, stdout="", stderr="")

        monkeypatch.setenv("GUARD_PROTECT_TIMEOUT_SECONDS", "180")
        monkeypatch.setattr(protect.subprocess, "run", fake_run)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                sys.executable,
                "-c",
                "print('ok')",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["executed"] is True
        assert captured["timeout"] == 180

    def test_guard_protect_uses_default_execution_timeout_when_env_is_invalid(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        captured: dict[str, object] = {}

        def fake_run(*args, **kwargs) -> CompletedProcess[str]:
            captured["timeout"] = kwargs["timeout"]
            return CompletedProcess(args[0], 0, stdout="", stderr="")

        monkeypatch.setenv("GUARD_PROTECT_TIMEOUT_SECONDS", "invalid")
        monkeypatch.setattr(protect.subprocess, "run", fake_run)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                sys.executable,
                "-c",
                "print('ok')",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["executed"] is True
        assert captured["timeout"] == 300

    def test_guard_protect_defers_package_installs_to_canonical_evaluator(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        advisories = [
            {
                "id": f"adv-{index:03d}",
                "ecosystem": "npm",
                "package": f"pkg-{index:03d}",
                "severity": "low",
                "action": "allow",
                "headline": f"allow {index}",
            }
            for index in range(120)
        ]
        advisories.append(
            {
                "id": "adv-block-tail",
                "ecosystem": "npm",
                "package": "badpkg",
                "severity": "high",
                "action": "block",
                "headline": "Known exfiltration package.",
            }
        )
        store.cache_advisories(advisories, _now())

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "badpkg",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert "supply_chain_evaluation" in output
        assert any(item.get("id") == "adv-block-tail" for item in output.get("matched_advisories", []))
        assert output["verdict"]["action"] == "block"
        assert output.get("dry_run") is True
        assert rc == 2

    def test_guard_protect_honors_cached_package_url_blocks_for_package_installs(self, tmp_path, capsys) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        store.cache_advisories(
            [
                {
                    "id": "adv-purl-block",
                    "ecosystem": "npm",
                    "package_url": "pkg:npm/badpkg",
                    "severity": "high",
                    "action": "block",
                    "headline": "Known package URL match.",
                }
            ],
            _now(),
        )

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "badpkg@1.2.3",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert "supply_chain_evaluation" in output
        assert any(item.get("id") == "adv-purl-block" for item in output.get("matched_advisories", []))
        assert output["verdict"]["action"] == "block"
        assert output.get("dry_run") is True
        assert rc == 2

    def test_guard_protect_honors_cached_scoped_package_url_blocks_for_package_installs(
        self,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        store.cache_advisories(
            [
                {
                    "id": "adv-purl-scoped-block",
                    "ecosystem": "npm",
                    "package_url": "pkg:npm/@scope/badpkg",
                    "severity": "high",
                    "action": "block",
                    "headline": "Known scoped package URL match.",
                }
            ],
            _now(),
        )

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "@scope/badpkg@1.2.3",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert "supply_chain_evaluation" in output
        assert any(item.get("id") == "adv-purl-scoped-block" for item in output.get("matched_advisories", []))
        assert output["verdict"]["action"] == "block"
        assert output.get("dry_run") is True
        assert rc == 2

    def test_guard_protect_blocks_package_install_when_cached_advisory_overrides_bundle_allow(
        self,
        tmp_path: Path,
    ) -> None:
        from codex_plugin_scanner.guard.protect import build_protect_payload

        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        _seed_bundle_cache_only(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="badpkg",
            package_version="1.0.0",
            action="allow",
        )
        store.cache_advisories(
            [
                {
                    "id": "adv-cached-block",
                    "ecosystem": "npm",
                    "package": "badpkg",
                    "severity": "high",
                    "action": "block",
                    "headline": "Locally cached malicious package block.",
                }
            ],
            _now(),
        )

        payload, exit_code = build_protect_payload(
            command=["npm", "install", "badpkg@1.0.0"],
            store=store,
            workspace_dir=workspace_dir,
            dry_run=False,
            now=_now(),
        )

        assert exit_code == 2
        assert payload["executed"] is False
        assert payload["verdict"]["action"] == "block"
        assert payload["receipt"]["policy_decision"] == "block"
        assert any(item.get("id") == "adv-cached-block" for item in payload.get("matched_advisories", []))
        stored_receipts = store.list_receipts(limit=10)
        assert len(stored_receipts) == 1
        stored_receipt = stored_receipts[0]
        assert stored_receipt["policy_decision"] == "block"
        block_events = store.list_events(limit=10, event_name="install_time_block")
        assert len(block_events) == 1
        assert block_events[0]["payload"]["action"] == "block"
        assert block_events[0]["payload"].get("cached_advisory_override") is not True

    def test_cached_advisory_merge_preserves_action_change_receipt_and_event_contract(
        self,
        tmp_path: Path,
    ) -> None:
        store = GuardStore(tmp_path / "home")
        now = _now()
        receipt = GuardReceipt(
            receipt_id="cached-action-change-receipt",
            timestamp=now,
            harness="guard-cli",
            artifact_id="guard-cli:project:package-request:npm-change",
            artifact_hash="sha256:cached-action-change",
            policy_decision="allow",
            capabilities_summary="Package allowed before cached advisory refresh.",
            changed_capabilities=("badpkg@1.0.0",),
            provenance_summary="Initial package authority allowed execution.",
            artifact_name="npm install badpkg@1.0.0",
            source_scope="project",
        )
        store.add_receipt(receipt)
        payload: dict[str, object] = {
            "request": {"executor": "npm", "install_kind": "install"},
            "verdict": {
                "action": "allow",
                "reason": "Initial package authority allowed execution.",
                "risk_signals": [],
                "matched_advisories": [],
                "blocking": False,
            },
            "matched_advisories": [],
            "executed": False,
            "dry_run": False,
            "receipt": receipt.to_dict(),
        }
        cached_verdict = protect.ProtectVerdict(
            action="block",
            reason="Cached advisory blocks execution.",
            risk_signals=("Cached advisory blocks execution.",),
            matched_advisories=({"id": "adv-action-change", "action": "block"},),
        )

        merged_payload, returncode = protect._merge_cached_advisory_into_package_payload(
            (payload, 0),
            cached_verdict=cached_verdict,
            requested_dry_run=False,
            store=store,
            now=now,
        )

        assert returncode == 2
        assert merged_payload["verdict"]["action"] == "block"
        assert merged_payload["receipt"]["policy_decision"] == "block"
        stored_receipts = store.list_receipts(limit=10)
        assert len(stored_receipts) == 1
        assert stored_receipts[0]["policy_decision"] == "block"
        events = store.list_events(event_name="install_time_block")
        assert len(events) == 1
        assert events[0]["payload"]["cached_advisory_override"] is True

    def test_guard_protect_matches_review_advisory_by_remote_endpoint_indicator(
        self,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        store.cache_advisories(
            [
                {
                    "id": "adv-endpoint-review",
                    "ecosystem": "claude-code",
                    "endpoint_indicators": ["evil.example/mcp"],
                    "severity": "medium",
                    "action": "review",
                    "headline": "Known risky endpoint.",
                }
            ],
            _now(),
        )

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "claude",
                "mcp",
                "add",
                "remote-risk",
                "https://evil.example/mcp",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "review"
        assert output["matched_advisories"][0]["id"] == "adv-endpoint-review"

    def test_guard_protect_matches_review_advisory_by_remote_endpoint_indicator_url(
        self,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(home_dir)
        store.cache_advisories(
            [
                {
                    "id": "adv-endpoint-url-review",
                    "ecosystem": "claude-code",
                    "endpoint_indicators": ["https://evil.example/mcp/"],
                    "severity": "medium",
                    "action": "review",
                    "headline": "Known risky endpoint URL.",
                }
            ],
            _now(),
        )

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "claude",
                "mcp",
                "add",
                "remote-risk",
                "https://evil.example/mcp",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "review"
        assert output["matched_advisories"][0]["id"] == "adv-endpoint-url-review"

    def test_guard_protect_does_not_match_blank_source_url_advisory(self) -> None:
        advisory = {
            "id": "adv-blank-source",
            "ecosystem": "npm",
            "source_url": "   ",
            "action": "review",
        }
        target = ProtectTargetIdentity(
            artifact_id="install:npm:package:safe",
            artifact_name="safe",
            ecosystem="npm",
            package_name="safe",
            package_url="pkg:npm/safe",
            source_url=None,
        )

        assert advisory_matches_target(advisory, target) is False

    def test_guard_protect_does_not_match_blank_package_advisory(self) -> None:
        advisory = {
            "id": "adv-blank-package",
            "ecosystem": "*",
            "package": "   ",
            "action": "review",
        }
        target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:remote-risk",
            artifact_name="remote-risk",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://evil.example/mcp",
        )

        assert advisory_matches_target(advisory, target) is False

    def test_guard_protect_does_not_match_blank_publisher_advisory(self) -> None:
        advisory = {
            "id": "adv-blank-publisher",
            "ecosystem": "*",
            "publisher": "   ",
            "action": "review",
        }
        target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:remote-risk",
            artifact_name="remote-risk",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://evil.example/mcp",
        )

        assert advisory_matches_target(advisory, target) is False

    def test_guard_protect_matches_endpoint_indicators_on_url_boundaries(self) -> None:
        advisory = {
            "id": "adv-endpoint-boundary",
            "ecosystem": "claude-code",
            "endpoint_indicators": ["evil.example/mcp"],
            "action": "review",
        }
        exact_target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:exact",
            artifact_name="exact",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://evil.example/mcp",
        )
        child_target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:child",
            artifact_name="child",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://evil.example/mcp/subpath",
        )
        sibling_target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:sibling",
            artifact_name="sibling",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://evil.example/mcp-backup",
        )
        prefix_target = ProtectTargetIdentity(
            artifact_id="install:claude-code:mcp:prefix",
            artifact_name="prefix",
            ecosystem="claude-code",
            package_name=None,
            package_url=None,
            source_url="https://safe-evil.example/mcp",
        )

        assert advisory_matches_target(advisory, exact_target) is True
        assert advisory_matches_target(advisory, child_target) is True
        assert advisory_matches_target(advisory, sibling_target) is False
        assert advisory_matches_target(advisory, prefix_target) is False

    def test_guard_protect_redacts_indented_secret_and_connection_env_lines(self) -> None:
        output = redact_text("  API_TOKEN=super-secret-token\n\tDATABASE_URL=postgres://user:pass@db.internal/app\n")

        assert output.text == "  API_TOKEN=*****\n\tDATABASE_URL=*****\n"

    def test_guard_redaction_preserves_serialized_json_delimiters(self) -> None:
        payload = json.dumps(
            {
                "token": "_authToken:abcdefghi",
                "dsn": "postgres://user:pass@db.internal/app",
                "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            }
        )

        output = redact_text(payload)
        redacted_payload = json.loads(output.text)

        assert "abcdefghi" not in output.text
        assert "pass" not in output.text
        assert "secret" not in output.text
        assert redacted_payload["token"] == "_authToken=*****"
        assert redacted_payload["dsn"] == "*****"
        assert redacted_payload["key"] == "*****"

    def test_guard_store_keeps_distinct_advisories_without_ids(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")

        store.cache_advisories(
            [
                {
                    "publisher": "hol",
                    "headline": "Remote execution risk",
                    "package": "pkg-alpha",
                    "action": "review",
                },
                {
                    "publisher": "hol",
                    "headline": "Remote execution risk",
                    "package": "pkg-beta",
                    "action": "block",
                },
            ],
            _now(),
        )

        advisories = store.list_cached_advisories(limit=None)

        assert len(advisories) == 2
        assert {str(item["package"]) for item in advisories} == {"pkg-alpha", "pkg-beta"}

    def test_guard_protect_auto_syncs_cloud_advisories(self, tmp_path, capsys) -> None:
        from codex_plugin_scanner.guard.runtime.runner import sync_receipts
        from tests.test_guard_package_shims import WORKSPACE_ID

        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        _SyncAndEvaluateHandler.sync_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [
                {
                    "id": "adv-sync-block",
                    "ecosystem": "npm",
                    "package": "badpkg",
                    "severity": "high",
                    "action": "block",
                    "headline": "Known exfiltration package.",
                }
            ],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
                "watchlistEnabled": True,
                "advisoriesEnabled": True,
                "repeatedWarningsEnabled": True,
                "teamAlertsEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "exceptions": [],
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": [],
                "blockedArtifacts": [],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncAndEvaluateHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            store = GuardStore(home_dir)
            _seed_guard_cloud(
                store,
                workspace_id=WORKSPACE_ID,
                sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
                token="demo-token",
            )
            _seed_bundle_cache_only(
                home_dir=home_dir,
                ecosystem="npm",
                package_name="badpkg",
                package_version="1.0.0",
                action="block",
            )
            sync_receipts(store)
            login_rc = 0

            protect_rc = main(
                [
                    "guard",
                    "protect",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--json",
                    "npm",
                    "install",
                    "badpkg@1.0.0",
                ]
            )
            protect_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        assert login_rc == 0
        assert protect_rc == 2
        assert protect_output["verdict"]["action"] == "block"
        assert protect_output["supply_chain_evaluation"]["decision"] == "block"
        synced_advisories = GuardStore(home_dir).list_cached_advisories(limit=None)
        assert any(item.get("id") == "adv-sync-block" for item in synced_advisories)
