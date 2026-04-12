"""Behavior tests for install-time Guard protection."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from subprocess import CompletedProcess

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import protect
from codex_plugin_scanner.guard.store import GuardStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
