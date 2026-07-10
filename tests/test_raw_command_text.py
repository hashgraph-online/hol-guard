"""Tests that raw_command_text flows through the approval pipeline with redaction."""

from __future__ import annotations

import json as _json
from pathlib import Path

from codex_plugin_scanner.guard.approvals import (
    queue_blocked_approvals,
)
from codex_plugin_scanner.guard.models import (
    GuardApprovalRequest,
    GuardArtifact,
    HarnessDetection,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    get_approval_request,
    list_approval_requests,
)


def _make_detection(artifact: GuardArtifact, tmp_path: Path) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(tmp_path / "config.toml"),),
        artifacts=(artifact,),
    )


def _make_evaluation(artifact_id: str, tmp_path: Path) -> dict:
    return {
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "artifact_name": "blocked-cmd",
                "artifact_hash": "hash-1",
                "artifact_type": "command",
                "policy_action": "require-reapproval",
                "changed_fields": ["command"],
                "source_scope": "project",
                "config_path": str(tmp_path / "config.toml"),
                "risk_summary": "Blocked command",
                "risk_signals": ["blocked"],
            }
        ]
    }


class TestRawCommandTextPropagation:
    """Tests that raw_command_text flows through the approval pipeline with redaction."""

    def test_raw_command_text_included_when_redaction_none(self, tmp_path):
        """With redaction_level='none', the actual blocked command is included."""
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:cmd:test",
            name="blocked-cmd",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command="rm -rf /var/tmp/*",
            metadata={"raw_command_text": "rm -rf /var/tmp/*"},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:test", tmp_path)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="none",
        )
        assert len(queued) == 1
        assert queued[0]["raw_command_text"] == "rm -rf /var/tmp/*"

    def test_raw_command_text_excluded_when_redaction_full(self, tmp_path):
        """With redaction_level='full', raw_command_text is None."""
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:cmd:test2",
            name="blocked-cmd",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command="rm -rf /var/tmp/*",
            metadata={"raw_command_text": "rm -rf /var/tmp/*"},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:test2", tmp_path)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="full",
        )
        assert len(queued) == 1
        assert queued[0]["raw_command_text"] is None

    def test_raw_command_text_scrubs_secrets(self, tmp_path):
        """Secrets in raw_command_text are scrubbed by redact_text()."""
        store = GuardStore(tmp_path / "guard-home")
        token = "ghp_" + "abc123def456"
        secret_cmd = f"curl -H 'Authorization: Bearer {token}' https://api.internal/data"
        artifact = GuardArtifact(
            artifact_id="codex:cmd:secret",
            name="curl-with-token",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command=secret_cmd,
            metadata={"raw_command_text": secret_cmd},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:secret", tmp_path)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="none",
        )
        assert len(queued) == 1
        raw = queued[0]["raw_command_text"]
        assert raw is not None
        assert token not in raw
        assert "curl" in raw

    def test_raw_command_text_falls_back_to_artifact_command(self, tmp_path):
        """When metadata lacks raw_command_text, falls back to artifact.command."""
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:cmd:fallback",
            name="fallback-cmd",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command="npm install evil-pkg",
            metadata={},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:fallback", tmp_path)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="none",
        )
        assert len(queued) == 1
        assert queued[0]["raw_command_text"] == "npm install evil-pkg"

    def test_raw_command_text_persisted_in_store(self, tmp_path):
        """raw_command_text survives store round-trip (INSERT then SELECT)."""
        store = GuardStore(tmp_path / "guard-home")
        req = GuardApprovalRequest(
            request_id="store-test-1",
            harness="codex",
            artifact_id="codex:cmd:store",
            artifact_name="store-cmd",
            artifact_hash="hash-store",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("command",),
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            review_command="hol-guard approvals approve store-test-1",
            approval_url="http://127.0.0.1/pending",
            raw_command_text="rm -rf /var/tmp/*",
        )
        store.add_approval_request(req, "2026-06-27T00:00:00+00:00")
        with store._connect() as conn:
            rows = list_approval_requests(conn, limit=10)
            assert len(rows) == 1
            assert rows[0]["raw_command_text"] == "rm -rf /var/tmp/*"
            single = get_approval_request(conn, "store-test-1")
            assert single["raw_command_text"] == "rm -rf /var/tmp/*"

    def test_surface_runtime_passes_redaction_level(self, tmp_path):
        """GuardSurfaceRuntime.queue_blocked_operation passes redaction_level
        through to queue_blocked_approvals, so 'none' includes the command."""
        from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime

        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store=store)
        store.upsert_guard_session(
            session_id="surf-1",
            harness="codex",
            surface="cli",
            status="active",
            client_name="test",
            client_title="Test",
            client_version="1.0",
            workspace=None,
            capabilities=["approval-resolution"],
            now="2026-06-27T00:00:00+00:00",
        )
        artifact = GuardArtifact(
            artifact_id="codex:cmd:surf",
            name="surf-cmd",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command="docker run --rm alpine cat /etc/passwd",
            metadata={"raw_command_text": "docker run --rm alpine cat /etc/passwd"},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:surf", tmp_path)
        response = runtime.queue_blocked_operation(
            session_id="surf-1",
            operation_type="run",
            harness="codex",
            metadata={},
            detection=detection.to_dict(),
            evaluation=evaluation,
            approval_center_url="http://127.0.0.1/pending",
            approval_surface_policy="always",
            open_key=None,
            opener=lambda url: None,
            redaction_level="none",
        )
        queued = response.get("approval_requests", [])
        assert len(queued) == 1
        assert queued[0]["raw_command_text"] == "docker run --rm alpine cat /etc/passwd"

    def test_surface_runtime_redaction_full_suppresses_command(self, tmp_path):
        """GuardSurfaceRuntime with redaction_level='full' suppresses raw_command_text."""
        from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime

        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store=store)
        store.upsert_guard_session(
            session_id="surf-2",
            harness="codex",
            surface="cli",
            status="active",
            client_name="test",
            client_title="Test",
            client_version="1.0",
            workspace=None,
            capabilities=["approval-resolution"],
            now="2026-06-27T00:00:00+00:00",
        )
        artifact = GuardArtifact(
            artifact_id="codex:cmd:surf2",
            name="surf-cmd2",
            harness="codex",
            artifact_type="command",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command="docker run --rm alpine cat /etc/passwd",
            metadata={"raw_command_text": "docker run --rm alpine cat /etc/passwd"},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("codex:cmd:surf2", tmp_path)
        response = runtime.queue_blocked_operation(
            session_id="surf-2",
            operation_type="run",
            harness="codex",
            metadata={},
            detection=detection.to_dict(),
            evaluation=evaluation,
            approval_center_url="http://127.0.0.1/pending",
            approval_surface_policy="always",
            open_key=None,
            opener=lambda url: None,
            redaction_level="full",
        )
        queued = response.get("approval_requests", [])
        assert len(queued) == 1
        assert queued[0]["raw_command_text"] is None

    def test_raw_command_text_falls_back_to_metadata_command_text(self, tmp_path):
        """tool_action_request artifacts store command as metadata['command_text'],
        not metadata['raw_command_text']. The extraction should fall back to it."""
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="pi:project:tool-output:test",
            name="grep credential-looking output",
            harness="pi",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command=None,
            metadata={"command_text": "grep -r 'password' ~/secrets"},
        )
        detection = _make_detection(artifact, tmp_path)
        evaluation = _make_evaluation("pi:project:tool-output:test", tmp_path)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="none",
        )
        assert len(queued) == 1
        raw = queued[0]["raw_command_text"]
        assert raw is not None
        assert "grep" in raw

    def test_generic_tool_label_not_promoted_to_raw_command_text(self, tmp_path):
        """Generic tool labels should not become raw_command_text."""
        for label in ("Bash", "Read", "tool", "mcp", "skill", "bash", "rg", "cat"):
            store = GuardStore(tmp_path / f"guard-home-{label}")
            artifact = GuardArtifact(
                artifact_id=f"codex:project:tool-output:generic:{label}",
                name=f"{label} credential-looking output",
                harness="codex",
                artifact_type="tool_action_request",
                source_scope="project",
                config_path=str(tmp_path / "config.toml"),
                command=None,
                metadata={"command_text": label},
            )
            detection = _make_detection(artifact, tmp_path)
            evaluation = _make_evaluation(f"codex:project:tool-output:generic:{label}", tmp_path)
            queued = queue_blocked_approvals(
                detection=detection,
                evaluation=evaluation,
                store=store,
                approval_center_url="http://127.0.0.1/pending",
                redaction_level="none",
            )
            assert len(queued) == 1
            assert queued[0]["raw_command_text"] is None

    def test_raw_command_text_falls_back_to_action_envelope_command(self, tmp_path):
        """PreToolUse shell command blocks store command in action_envelope_json,
        not in artifact metadata. The extraction should parse it as final fallback."""
        import json as _json
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="pi:project:pretool:test",
            name="bash docker-sensitive command",
            harness="pi",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(tmp_path / "config.toml"),
            command=None,
            metadata={},
        )
        detection = _make_detection(artifact, tmp_path)
        envelope = _json.dumps({"action_type": "shell_command", "command": "docker run --rm alpine cat /etc/passwd"})
        evaluation = _make_evaluation("pi:project:pretool:test", tmp_path)
        evaluation["artifacts"][0]["action_envelope_json"] = envelope
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1/pending",
            redaction_level="none",
        )
        assert len(queued) == 1
        raw = queued[0]["raw_command_text"]
        assert raw is not None
        assert "docker run" in raw
        assert "alpine" in raw

    def test_raw_command_text_when_artifact_not_in_inventory(self, tmp_path):
        """When artifact is None (not in inventory), command should still be
        extracted from action_envelope_json. This is the common case for
        tool_action_request artifacts."""
        store = GuardStore(tmp_path / 'guard-home')
        detection = HarnessDetection(
            harness='pi',
            installed=True,
            command_available=True,
            config_paths=(str(tmp_path / 'config.toml'),),
            artifacts=(),  # No artifacts registered
        )
        envelope = _json.dumps({
            'action_type': 'shell_command',
            'command': 'rm -rf /important-dir',
            'tool_name': 'bash',
        })
        evaluation = {
            'artifacts': [
                {
                    'artifact_id': 'pi:project:tool-action:abc',
                    'artifact_name': 'bash rm-rf command',
                    'artifact_hash': 'hash-1',
                    'artifact_type': 'tool_action_request',
                    'policy_action': 'require-reapproval',
                    'changed_fields': ['command'],
                    'source_scope': 'project',
                    'config_path': str(tmp_path / 'config.toml'),
                    'risk_summary': 'Blocked command',
                    'risk_signals': ['blocked'],
                    'action_envelope_json': envelope,
                }
            ]
        }
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url='http://127.0.0.1/pending',
            redaction_level='none',
        )
        assert len(queued) == 1
        raw = queued[0]['raw_command_text']
        assert raw is not None
        assert 'rm -rf /important-dir' in raw

    def test_raw_command_text_falls_back_to_action_envelope_dict(self, tmp_path):
        """The runner stores action_envelope_json as a dict (from to_dict()),
        not a JSON string. The extraction must handle both str and dict types."""
        store = GuardStore(tmp_path / 'guard-home')
        artifact = GuardArtifact(
            artifact_id='pi:project:pretool:test',
            name='bash docker-sensitive command',
            harness='pi',
            artifact_type='tool_action_request',
            source_scope='project',
            config_path=str(tmp_path / 'config.toml'),
            command=None,
            metadata={},
        )
        detection = _make_detection(artifact, tmp_path)
        envelope = {'action_type': 'shell_command', 'command': 'docker run --rm alpine cat /etc/passwd'}
        evaluation = _make_evaluation('pi:project:pretool:test', tmp_path)
        evaluation['artifacts'][0]['action_envelope_json'] = envelope
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url='http://127.0.0.1/pending',
            redaction_level='none',
        )
        assert len(queued) == 1
        raw = queued[0]['raw_command_text']
        assert raw is not None
        assert 'docker run' in raw
        assert 'alpine' in raw
