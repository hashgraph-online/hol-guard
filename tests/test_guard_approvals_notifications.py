"""Approval notification creation, retries and preferences."""

from __future__ import annotations

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_queue_sends_only_request_notification_without_setup_preview(self, tmp_path, monkeypatch):
        notice_calls: list[str] = []

        def fake_notify(notification, **_kwargs):
            notice_calls.append(notification.request_id)
            return True

        monkeypatch.setattr("codex_plugin_scanner.guard.approvals.notify_pending_approval_once", fake_notify)
        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:setup_notice",
            name="danger_lab:setup_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="setup_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queued = queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": "hash-runtime",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": "setup_notice",
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )

        assert notice_calls == [queued[0]["request_id"]]

    def test_guard_queue_notifies_desktop_once_for_new_request(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HOL_GUARD_DESKTOP_NOTIFICATIONS", raising=False)
        notifications: list[str] = []

        def fake_send(notification):
            notifications.append(notification.request_id)
            return True

        from codex_plugin_scanner.guard import desktop_notifications

        with desktop_notifications._NOTIFIED_APPROVAL_IDS_LOCK:
            desktop_notifications._NOTIFIED_APPROVAL_IDS.clear()
            desktop_notifications._NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.desktop_notifications.send_desktop_approval_notification",
            fake_send,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.approvals.notify_pending_approval_once",
            lambda notification, **kwargs: desktop_notifications.notify_pending_approval_once(
                notification,
                asynchronous=False,
                **kwargs,
            ),
        )
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:desktop_notice",
            name="danger_lab:desktop_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="desktop_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )
        evaluation: dict[str, object] = {
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-runtime",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "changed_fields": ["runtime_tool_call"],
                    "policy_action": "require-reapproval",
                    "launch_target": "desktop_notice",
                    "risk_summary": "Needs approval.",
                    "risk_signals": ["sensitive action"],
                }
            ]
        }

        first = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )
        with desktop_notifications._NOTIFIED_APPROVAL_IDS_LOCK:
            desktop_notifications._NOTIFIED_APPROVAL_IDS.clear()
            desktop_notifications._NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()
        second = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:01:00+00:00",
        )

        assert first[0]["request_id"] == second[0]["request_id"]
        assert notifications == [first[0]["request_id"]]

    def test_guard_queue_retries_failed_desktop_notification_for_requeued_request(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HOL_GUARD_DESKTOP_NOTIFICATIONS", raising=False)
        notifications: list[tuple[str, bool]] = []
        outcomes = [False, True]

        def fake_send(notification):
            outcome = outcomes.pop(0)
            notifications.append((notification.request_id, outcome))
            return outcome

        from codex_plugin_scanner.guard import desktop_notifications

        with desktop_notifications._NOTIFIED_APPROVAL_IDS_LOCK:
            desktop_notifications._NOTIFIED_APPROVAL_IDS.clear()
            desktop_notifications._NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.desktop_notifications.send_desktop_approval_notification",
            fake_send,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.approvals.notify_pending_approval_once",
            lambda notification, **kwargs: desktop_notifications.notify_pending_approval_once(
                notification,
                asynchronous=False,
                **kwargs,
            ),
        )
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:retry_notice",
            name="danger_lab:retry_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="retry_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )
        evaluation = {
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-runtime",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "changed_fields": ["runtime_tool_call"],
                    "policy_action": "require-reapproval",
                    "launch_target": "retry_notice",
                }
            ]
        }

        first = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )
        with desktop_notifications._NOTIFIED_APPROVAL_IDS_LOCK:
            desktop_notifications._NOTIFIED_APPROVAL_IDS.clear()
            desktop_notifications._NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()
        second = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:01:00+00:00",
        )

        assert first[0]["request_id"] == second[0]["request_id"]
        assert notifications == [(first[0]["request_id"], False), (first[0]["request_id"], True)]

    def test_guard_queue_blocked_approvals_emits_created_event_once_for_new_pending_request(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace = tmp_path / "workspace"
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:event_notice",
            name="danger_lab:event_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(workspace / ".codex" / "config.toml"),
            command="event_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )
        evaluation = {
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-runtime",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "changed_fields": ["runtime_tool_call"],
                    "policy_action": "require-reapproval",
                    "launch_target": "event_notice",
                }
            ]
        }

        first = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )
        second = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:01:00+00:00",
        )
        events = store.list_events_after(0, limit=10, event_names=("approval.created",))
        payload = events[0]["payload"]

        assert first[0]["request_id"] == second[0]["request_id"]
        assert len(events) == 1
        assert isinstance(payload, dict)
        assert payload == {
            "request_id": first[0]["request_id"],
            "harness": "codex",
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_type": artifact.artifact_type,
            "policy_action": "require-reapproval",
            "recommended_scope": "artifact",
            "source_scope": "project",
            "workspace": str(workspace),
            "publisher": None,
        }

    def test_guard_queue_respects_disabled_desktop_notifications(self, tmp_path, monkeypatch):
        notifications: list[str] = []

        def fake_notify(notification, **_kwargs):
            notifications.append(notification.request_id)
            return True

        monkeypatch.setattr("codex_plugin_scanner.guard.approvals.notify_pending_approval_once", fake_notify)
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        (guard_home / "config.toml").write_text("desktop_notifications = false\n", encoding="utf-8")
        store = GuardStore(guard_home)
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:no_notice",
            name="danger_lab:no_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="no_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": "hash-runtime",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": "no_notice",
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )

        assert notifications == []

    def test_guard_queue_respects_workspace_disabled_desktop_notifications(self, tmp_path, monkeypatch):
        notifications: list[str] = []

        def fake_notify(notification, **_kwargs):
            notifications.append(notification.request_id)
            return True

        monkeypatch.setattr("codex_plugin_scanner.guard.approvals.notify_pending_approval_once", fake_notify)
        guard_home = tmp_path / "guard-home"
        workspace = tmp_path / "workspace"
        guard_home.mkdir()
        workspace.mkdir()
        (guard_home / "config.toml").write_text("desktop_notifications = true\n", encoding="utf-8")
        (workspace / ".hol-guard.toml").write_text("desktop_notifications = false\n", encoding="utf-8")
        store = GuardStore(guard_home)
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:workspace_no_notice",
            name="danger_lab:workspace_no_notice",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(workspace / ".codex" / "config.toml"),
            command="workspace_no_notice",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": "hash-runtime",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": "workspace_no_notice",
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )

        assert notifications == []
