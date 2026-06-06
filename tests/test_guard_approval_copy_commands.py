"""Tests for T732-T737: harness copy rule and approval CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import (
    approval_center_hint,
    attach_primary_approval_link,
    build_approval_request_url,
    first_approval_url,
    primary_approval_request,
    primary_approval_url,
)
from codex_plugin_scanner.guard.cli import approval_commands as approval_commands_module
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_KNOWN_HARNESSES = ["codex", "claude-code", "opencode", "copilot", "gemini"]


def _make_queue_item(harness: str, request_id: str) -> dict:
    return {
        "request_id": request_id,
        "harness": harness,
        "artifact_id": f"{harness}:project:tool",
        "artifact_name": "Test tool",
        "policy_action": "block",
        "recommended_scope": "artifact",
    }


def _make_request(
    *,
    request_id: str,
    harness: str = "codex",
    status: str = "pending",
    approval_url: str | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:project:tool",
        artifact_name="Test tool",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/tmp/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=approval_url or f"http://127.0.0.1:5474/requests/{request_id}",
    )


class TestHarnessBlockMessageCopyRule:
    """T732: harness block messages must never tell users to run 'hol-guard dashboard' as primary path."""

    @pytest.mark.parametrize("harness", _KNOWN_HARNESSES)
    def test_approval_center_hint_does_not_require_manual_dashboard_launch(self, tmp_path: Path, harness: str) -> None:
        """T732: approval_center_hint must not instruct users to run 'hol-guard dashboard'."""
        context = HarnessContext(
            home_dir=tmp_path,
            guard_home=tmp_path / ".hol-guard",
            workspace_dir=tmp_path / "workspace",
        )
        queued = [_make_queue_item(harness, "req-rule-01")]
        hint = approval_center_hint(
            context=context,
            harness=harness,
            approval_center_url="http://127.0.0.1:5474",
            queued=queued,
        )
        assert "hol-guard dashboard" not in hint, (
            f"Harness hint for '{harness}' must not tell users to run 'hol-guard dashboard' as primary path. "
            f"Got: {hint!r}"
        )


class TestBlockMessageNoDashboardLaunchRequired:
    """T733: CLI block message must not require manual dashboard launch."""

    def test_block_approval_center_hint_no_manual_dashboard_command(self, tmp_path: Path) -> None:
        """T733: block flow copy does not contain 'hol-guard dashboard' for any harness."""
        context = HarnessContext(
            home_dir=tmp_path,
            guard_home=tmp_path / ".hol-guard",
            workspace_dir=tmp_path / "workspace",
        )
        for harness in _KNOWN_HARNESSES:
            queued = [_make_queue_item(harness, f"req-t733-{harness}")]
            hint = approval_center_hint(
                context=context,
                harness=harness,
                approval_center_url="http://127.0.0.1:5474",
                queued=queued,
            )
            assert "hol-guard dashboard" not in hint, (
                f"CLI block message for '{harness}' must not say 'hol-guard dashboard'. Got: {hint!r}"
            )


def test_first_approval_url_ignores_malformed_queue_items() -> None:
    queued = [
        "not-a-request",
        {"approval_url": "  "},
        {"approval_url": "http://127.0.0.1:5474/requests/req-ok", "harness": "cursor"},
    ]

    assert (
        first_approval_url(
            queued,
            harness="cursor",
            approval_center_url="http://127.0.0.1:5474",
        )
        == "http://127.0.0.1:5474/requests/req-ok"
    )


def test_primary_approval_request_prefers_matching_harness() -> None:
    queued = [
        {
            "request_id": "codex-req",
            "harness": "codex",
            "approval_url": "http://127.0.0.1:5474/requests/codex-req",
        },
        {
            "request_id": "cursor-req",
            "harness": "cursor",
            "approval_url": "http://127.0.0.1:5474/requests/cursor-req",
        },
    ]

    selected = primary_approval_request(queued, harness="cursor")

    assert selected is not None
    assert selected["request_id"] == "cursor-req"
    assert (
        primary_approval_url(queued, harness="cursor", approval_center_url="http://127.0.0.1:5474")
        == "http://127.0.0.1:5474/requests/cursor-req"
    )


def test_primary_approval_request_prefers_request_id() -> None:
    queued = [
        {
            "request_id": "older-req",
            "harness": "cursor",
            "artifact_id": "cursor:project:shell-a",
        },
        {
            "request_id": "newer-req",
            "harness": "cursor",
            "artifact_id": "cursor:project:shell-b",
        },
    ]

    selected = primary_approval_request(queued, harness="cursor", request_id="older-req")

    assert selected is not None
    assert selected["request_id"] == "older-req"


def test_primary_approval_request_prefers_artifact_id_over_harness_latest() -> None:
    queued = [
        {
            "request_id": "req-a",
            "harness": "cursor",
            "artifact_id": "cursor:project:shell-a",
            "approval_url": "http://127.0.0.1:5474/requests/req-a",
        },
        {
            "request_id": "req-b",
            "harness": "cursor",
            "artifact_id": "cursor:project:shell-b",
            "approval_url": "http://127.0.0.1:5474/requests/req-b",
        },
    ]

    selected = primary_approval_request(
        queued,
        harness="cursor",
        artifact_id="cursor:project:shell-a",
    )

    assert selected is not None
    assert selected["request_id"] == "req-a"


def test_primary_approval_request_single_item_without_harness() -> None:
    queued = [
        {
            "request_id": "solo-req",
            "harness": "cursor",
            "approval_url": "http://127.0.0.1:5474/requests/solo-req",
        }
    ]

    selected = primary_approval_request(queued)

    assert selected is not None
    assert selected["request_id"] == "solo-req"


def test_primary_approval_request_returns_none_without_binding() -> None:
    queued = [
        {
            "request_id": "codex-req",
            "harness": "codex",
        },
        {
            "request_id": "cursor-req",
            "harness": "cursor",
        },
    ]

    assert primary_approval_request(queued) is None


def test_attach_primary_approval_link_uses_operation_request_id() -> None:
    payload: dict[str, object] = {
        "artifact_id": "cursor:project:shell-b",
        "approval_request_ids": ["bound-req"],
        "approval_requests": [
            {
                "request_id": "other-req",
                "harness": "cursor",
                "artifact_id": "cursor:project:shell-a",
                "approval_url": "http://127.0.0.1:5474/requests/other-req",
            },
            {
                "request_id": "bound-req",
                "harness": "cursor",
                "artifact_id": "cursor:project:shell-b",
                "approval_url": "http://127.0.0.1:5474/requests/bound-req",
            },
        ],
    }

    attach_primary_approval_link(
        payload,
        harness="cursor",
        approval_center_url="http://127.0.0.1:5474",
    )

    assert payload["primary_approval_request_id"] == "bound-req"
    assert payload["primary_approval_url"] == "http://127.0.0.1:5474/requests/bound-req"


def test_build_approval_request_url_uses_requests_route() -> None:
    assert build_approval_request_url("http://127.0.0.1:5474", "abc123") == "http://127.0.0.1:5474/requests/abc123"


class TestApprovalsOpenCommand:
    """T734-T735: 'hol-guard approvals open <request_id>' command."""

    def test_approvals_open_returns_approval_url_for_known_request(self, tmp_path: Path, capsys) -> None:
        """T734: approvals open prints the approval URL for an existing pending request."""
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-open-01"), "2026-01-01T00:00:00Z")

        rc = main(["guard", "approvals", "open", "req-open-01", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["request_id"] == "req-open-01"
        assert "approval_url" in output

    def test_approvals_open_returns_error_for_missing_request(self, tmp_path: Path, capsys) -> None:
        """T735: approvals open with daemon stopped returns a clear error, not a crash."""
        home_dir = tmp_path / "guard-home"

        rc = main(["guard", "approvals", "open", "req-missing", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc != 0
        assert "error" in output


class TestApprovalsAutoOpenCommand:
    def test_approvals_summary_auto_opens_first_pending_request(self, tmp_path: Path, monkeypatch, capsys) -> None:
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-auto-open"), "2026-01-01T00:00:00Z")
        opened_urls: list[str] = []
        monkeypatch.setattr(
            approval_commands_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            approval_commands_module.webbrowser,
            "open",
            lambda url: opened_urls.append(url) or True,
        )

        rc = main(["guard", "approvals", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert opened_urls == ["http://127.0.0.1:5474/requests/req-auto-open"]
        assert output["auto_open"]["opened"] is True
        assert output["auto_open"]["request_id"] == "req-auto-open"

    def test_approvals_summary_repairs_stale_auto_open_url(self, tmp_path: Path, monkeypatch, capsys) -> None:
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(
            _make_request(
                request_id="req-stale-open",
                approval_url="http://127.0.0.1:4000/requests/req-stale-open",
            ),
            "2026-01-01T00:00:00Z",
        )
        opened_urls: list[str] = []
        monkeypatch.setattr(
            approval_commands_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            approval_commands_module.webbrowser,
            "open",
            lambda url: opened_urls.append(url) or True,
        )

        rc = main(["guard", "approvals", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert opened_urls == ["http://127.0.0.1:5474/requests/req-stale-open"]
        assert output["auto_open"]["opened"] is True

    def test_approvals_summary_honors_native_only_auto_open_opt_out(self, tmp_path: Path, monkeypatch, capsys) -> None:
        home_dir = tmp_path / "guard-home"
        home_dir.mkdir(parents=True)
        (home_dir / "config.toml").write_text('approval_surface_policy = "native-only"\n', encoding="utf-8")
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-no-open"), "2026-01-01T00:00:00Z")
        opened_urls: list[str] = []
        monkeypatch.setattr(
            approval_commands_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            approval_commands_module.webbrowser,
            "open",
            lambda url: opened_urls.append(url) or True,
        )

        rc = main(["guard", "approvals", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert opened_urls == []
        assert output["auto_open"]["opened"] is False
        assert output["auto_open"]["reason"] == "policy-disabled"


class TestApprovalsRetryHintCommand:
    """T736-T737: 'hol-guard approvals retry-hint <request_id>' command."""

    def test_retry_hint_allow_resolution(self, tmp_path: Path, capsys) -> None:
        """T737: retry-hint returns allow copy after approval."""
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-hint-allow"), "2026-01-01T00:00:00Z")
        main(
            [
                "guard",
                "approvals",
                "approve",
                "req-hint-allow",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--json",
            ]
        )
        capsys.readouterr()

        rc = main(["guard", "approvals", "retry-hint", "req-hint-allow", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["title"] == "Approved. Retry in chat."

    def test_retry_hint_block_resolution(self, tmp_path: Path, capsys) -> None:
        """T737: retry-hint returns block copy after block decision."""
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-hint-block"), "2026-01-01T00:00:00Z")
        main(
            [
                "guard",
                "approvals",
                "deny",
                "req-hint-block",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--json",
            ]
        )
        capsys.readouterr()

        rc = main(["guard", "approvals", "retry-hint", "req-hint-block", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["title"] == "Blocked. Guard will remember this decision."

    def test_retry_hint_missing_request(self, tmp_path: Path, capsys) -> None:
        """T737: retry-hint with unknown request_id returns error."""
        home_dir = tmp_path / "guard-home"

        rc = main(["guard", "approvals", "retry-hint", "req-hint-missing", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc != 0
        assert "error" in output

    def test_retry_hint_pending_request(self, tmp_path: Path, capsys) -> None:
        """T737: retry-hint with still-pending request returns not_resolved status."""
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-hint-pending"), "2026-01-01T00:00:00Z")

        rc = main(["guard", "approvals", "retry-hint", "req-hint-pending", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc != 0
        assert output.get("status") == "pending" or "error" in output
