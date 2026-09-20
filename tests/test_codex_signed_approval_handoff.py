"""Focused regression tests for signed Codex approval handoffs."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approval_hook_copy as approval_hook_copy_module
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from codex_plugin_scanner.guard.approval_hook_copy import (
    _SIGNED_APPROVAL_LINK_UNAVAILABLE,
    live_hook_approval_context,
)
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_pre_tool_review
from tests.guard_signed_approval_fixtures import write_synthetic_daemon_auth_token


def test_live_hook_copy_loads_auth_once_and_builds_signed_link_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as runtime_policy_module

    guard_home = tmp_path / "guard-home"
    review_url = "http://127.0.0.1:5474/requests/req-codex-single-load"
    payload = {"primary_approval_url": review_url}
    loads: list[Path] = []
    builds: list[tuple[str, str | None]] = []

    def load_token(home: Path) -> str:
        loads.append(home)
        return "synthetic-daemon-token"

    def build_url(url: str, *, auth_token: str | None) -> str:
        builds.append((url, auth_token))
        return f"{url}#guard-token=fixture"

    monkeypatch.setattr(approval_hook_copy_module, "load_guard_daemon_auth_token", load_token)
    monkeypatch.setattr(approval_hook_copy_module, "build_approval_browser_url", build_url)
    monkeypatch.setattr(
        runtime_policy_module,
        "_native_approval_center_context",
        lambda _payload, *, harness: f"{review_url} then {review_url} ({harness})",
    )

    live = live_hook_approval_context(payload, harness="codex", guard_home=guard_home)

    assert live is not None
    signed_url = f"{review_url}#guard-token=fixture"
    assert live.count(signed_url) == 2
    assert loads == [guard_home]
    assert builds == [(review_url, "synthetic-daemon-token")]


def test_live_hook_copy_does_not_advertise_raw_loopback_without_auth(tmp_path: Path) -> None:
    review_url = "http://127.0.0.1:5474/requests/req-codex-no-auth"

    live = live_hook_approval_context(
        {"primary_approval_url": review_url},
        harness="codex",
        guard_home=tmp_path / "missing-guard-home",
    )

    assert live is not None
    assert live.endswith(_SIGNED_APPROVAL_LINK_UNAVAILABLE)
    assert "Open HOL Guard" in live
    assert ": ." not in live
    assert review_url not in live
    assert "guard-token=" not in live


def test_live_hook_copy_does_not_advertise_raw_loopback_when_signing_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_url = "http://127.0.0.1:5474/requests/req-codex-signing-error"
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)

    def raise_signing_error(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("synthetic signing failure")

    monkeypatch.setattr(approval_hook_copy_module, "build_approval_browser_url", raise_signing_error)
    live = live_hook_approval_context(
        {"primary_approval_url": review_url},
        harness="codex",
        guard_home=guard_home,
    )

    assert live is not None
    assert live.endswith(_SIGNED_APPROVAL_LINK_UNAVAILABLE)
    assert "Open HOL Guard" in live
    assert ": ." not in live
    assert review_url not in live
    assert "synthetic signing failure" not in live


def test_pending_approval_prints_the_authenticated_browser_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []
    monkeypatch.setattr(resume, "open_browser_url", lambda url: opened_urls.append(url) or True)

    resume._open_pending_approval(approval_url, state_path=guard_home / "daemon-state.json")

    captured = capsys.readouterr()
    assert len(opened_urls) == 1
    assert opened_urls[0].startswith(f"{approval_url}#guard-token=")
    assert captured.err == f"HOL Guard is waiting for approval in your browser: {opened_urls[0]}\n"


def test_pending_approval_does_not_open_unsigned_url_when_auth_token_load_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []

    def raise_auth_error(_guard_home: Path) -> str:
        raise OSError("synthetic auth loader failure")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approval_hook_copy.load_guard_daemon_auth_token",
        raise_auth_error,
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda url: opened_urls.append(url) or True)

    resume._open_pending_approval(approval_url, state_path=tmp_path / "daemon-state.json")

    captured = capsys.readouterr()
    assert opened_urls == []
    assert "could not create a signed approval link" in captured.err.lower()
    assert approval_url not in captured.err


def test_codex_live_approval_prints_the_authenticated_browser_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []
    monkeypatch.setattr(interaction, "open_browser_url", lambda url: opened_urls.append(url) or True)

    interaction._open_codex_live_approval(
        {"approval_requests": [{"request_id": "req-1", "approval_url": approval_url}]},
        guard_home=guard_home,
    )

    captured = capsys.readouterr()
    assert len(opened_urls) == 1
    assert opened_urls[0].startswith(f"{approval_url}#guard-token=")
    assert captured.err == f"HOL Guard is waiting for approval in your browser: {opened_urls[0]}\n"


def test_codex_live_approval_keeps_external_url_unsigned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    approval_url = "https://example.invalid/requests/req-1"
    opened_urls: list[str] = []
    monkeypatch.setattr(interaction, "open_browser_url", lambda url: opened_urls.append(url) or True)

    interaction._open_codex_live_approval(
        {"approval_requests": [{"request_id": "req-1", "approval_url": approval_url}]},
        guard_home=tmp_path / "guard-home",
    )

    captured = capsys.readouterr()
    assert opened_urls == [approval_url]
    assert captured.err == f"HOL Guard is waiting for approval in your browser: {approval_url}\n"


def test_codex_live_approval_does_not_open_unsigned_local_url_without_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []
    monkeypatch.setattr(interaction, "open_browser_url", lambda url: opened_urls.append(url) or True)

    interaction._open_codex_live_approval(
        {"approval_requests": [{"request_id": "req-1", "approval_url": approval_url}]},
        guard_home=tmp_path / "missing-guard-home",
    )

    captured = capsys.readouterr()
    assert opened_urls == []
    assert "could not create a signed approval link" in captured.err.lower()
    assert approval_url not in captured.err


def test_codex_bridge_stdout_excludes_native_approval_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_url = "http://127.0.0.1:5474/requests/req-native-codex-bridge"
    signed_url = f"{review_url}#guard-token=fixture"
    response = {
        "policy_action": "review",
        "reason_code": "native_pre_tool_review",
        "reason": f"Open HOL Guard: {signed_url}.",
        "approval_url": review_url,
        "approval_request_id": "req-native-codex-bridge",
        "primary_approval_url": review_url,
        "guardApprovalUrl": review_url,
        "approval_requests": [{"request_id": "req-native-codex-bridge", "approval_url": review_url}],
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Open HOL Guard: {signed_url}.",
        },
    }
    monkeypatch.setattr(bridge, "apply_browser_approval_wait", lambda payload, **_kwargs: payload)

    stdout = bridge._bridge_output(
        response,
        event_name="PreToolUse",
        hook_input="{}",
        state_path=tmp_path / "daemon-state.json",
        deadline=time.monotonic() + 1,
    )
    filtered = json.loads(stdout)

    assert set(filtered) == {"hookSpecificOutput"}
    assert filtered["hookSpecificOutput"]["permissionDecisionReason"] == f"Open HOL Guard: {signed_url}."
    for alias in (
        "approval_url",
        "approval_request_id",
        "primary_approval_url",
        "guardApprovalUrl",
        "approval_requests",
    ):
        assert alias not in filtered


def test_codex_native_review_reason_signs_loopback_without_changing_aliases(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)
    review_url = "http://127.0.0.1:5474/requests/req-native-codex"

    rendered = harness_json_from_native_pre_tool_review(
        "codex",
        {"reason": "HOL Guard paused this action.", "reason_code": "native_pre_tool_review"},
        approval={"request_id": "req-native-codex", "approval_url": review_url},
        guard_home=guard_home,
    )

    assert "guard-token=gld1." in str(rendered["reason"])
    assert rendered["approval_url"] == review_url
    assert rendered["primary_approval_url"] == review_url
    assert rendered["guardApprovalUrl"] == review_url


def test_codex_native_review_reason_hides_loopback_when_auth_is_missing(tmp_path: Path) -> None:
    review_url = "http://127.0.0.1:5474/requests/req-native-codex-no-auth"
    rendered = harness_json_from_native_pre_tool_review(
        "codex",
        {"reason": f"Review this action: {review_url}", "reason_code": "native_pre_tool_review"},
        approval={"request_id": "req-native-codex-no-auth", "approval_url": review_url},
        guard_home=tmp_path / "missing-guard-home",
    )

    reason = str(rendered["reason"])
    assert review_url not in reason
    assert "could not create a signed approval link" in reason.lower()
    assert rendered["approval_url"] == review_url


def test_codex_native_review_reason_hides_loopback_when_signing_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)
    review_url = "http://127.0.0.1:5474/requests/req-native-codex-error"

    def raise_signing_error(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("synthetic signing failure")

    monkeypatch.setattr(approval_hook_copy_module, "build_approval_browser_url", raise_signing_error)
    rendered = harness_json_from_native_pre_tool_review(
        "codex",
        {"reason": f"Review this action: {review_url}", "reason_code": "native_pre_tool_review"},
        approval={"request_id": "req-native-codex-error", "approval_url": review_url},
        guard_home=guard_home,
    )

    reason = str(rendered["reason"])
    assert review_url not in reason
    assert "could not create a signed approval link" in reason.lower()
    assert "synthetic signing failure" not in reason


def test_codex_native_review_reason_leaves_external_url_unchanged(tmp_path: Path) -> None:
    review_url = "https://example.invalid/requests/req-native-codex-external"
    rendered = harness_json_from_native_pre_tool_review(
        "codex",
        {"reason": "HOL Guard paused this action.", "reason_code": "native_pre_tool_review"},
        approval={"request_id": "req-native-codex-external", "approval_url": review_url},
        guard_home=tmp_path / "missing-guard-home",
    )

    assert review_url in str(rendered["reason"])
    assert rendered["approval_url"] == review_url
