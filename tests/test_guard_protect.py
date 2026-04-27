"""Behavior tests for install-time Guard protection."""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from subprocess import CompletedProcess
from typing import ClassVar

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import protect
from codex_plugin_scanner.guard.advisory_model import ProtectTargetIdentity, advisory_matches_target
from codex_plugin_scanner.guard.redaction import redact_text
from codex_plugin_scanner.guard.store import GuardStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
                    "ecosystem": "npm",
                    "package": "badpkg",
                    "severity": "high",
                    "action": "block",
                    "headline": "Known exfiltration package.",
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
                "npm",
                "install",
                "badpkg",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "block"
        assert output["executed"] is False
        assert output["targets"][0]["package_name"] == "badpkg"
        assert output["matched_advisories"][0]["id"] == "adv-block-1"
        assert store.list_receipts(limit=1)[0]["artifact_id"] == "install:npm:badpkg"
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

    def test_guard_protect_checks_blocking_advisory_beyond_default_cache_limit(self, tmp_path, capsys) -> None:
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
                "npm",
                "install",
                "badpkg",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "block"
        assert any(item["id"] == "adv-block-tail" for item in output["matched_advisories"])

    def test_guard_protect_matches_blocking_advisory_by_package_url(self, tmp_path, capsys) -> None:
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
                "npm",
                "install",
                "badpkg@1.2.3",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "block"
        assert output["matched_advisories"][0]["id"] == "adv-purl-block"

    def test_guard_protect_matches_blocking_advisory_by_scoped_package_url(self, tmp_path, capsys) -> None:
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
                "npm",
                "install",
                "@scope/badpkg@1.2.3",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["verdict"]["action"] == "block"
        assert output["matched_advisories"][0]["id"] == "adv-purl-scoped-block"

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
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        _SyncRequestHandler.response_payload = {
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

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

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
                    "badpkg",
                ]
            )
            protect_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert protect_rc == 2
        assert protect_output["verdict"]["action"] == "block"
        assert protect_output["matched_advisories"][0]["id"] == "adv-sync-block"
