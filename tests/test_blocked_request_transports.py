"""Default denial keeps transport execution and approval surfaces closed."""

from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.protect_approvals import _queue_local_protect_approvals
from codex_plugin_scanner.guard.cli.protect_output import _protect_payload_for_human_output
from codex_plugin_scanner.guard.native_daemon_lifecycle import NativeDaemonLifecycleError
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_signed_approval_fixtures import short_signed_link
from tests.mcp_stdio_fixture_support import harness_context as _context
from tests.silent_review_assertions import assert_silent_review_recorded
from tests.test_guard_protect_approval_guidance import _pending_package_payload


@pytest.fixture(autouse=True)
def _native_package_context(package_intent_native, native_mcp_probe, monkeypatch) -> None:
    original = _context

    def enrolled_context(tmp_path: Path):
        context = original(tmp_path)
        native_mcp_probe(context.guard_home)
        return context

    monkeypatch.setitem(globals(), "_context", enrolled_context)


def _unexpected_prompt(*args, **kwargs):
    pytest.fail("default denial must not open an approval prompt")


def test_local_package_denial_preserves_receipt_and_exposes_decision_wait(tmp_path):
    context = _context(tmp_path)
    payload = _pending_package_payload()
    original_receipt = deepcopy(payload["receipt"])
    store = GuardStore(context.guard_home)
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    assert payload["executed"] is False
    assert payload["policy_action"] == "block"
    assert payload["receipt"] == original_receipt
    assert "Current package policy" in payload["review_hint"]
    request_id = store.list_approval_requests(status="pending")[0]["request_id"]
    assert f"hol-guard approvals wait {request_id} --json" in payload["review_hint"]
    assert payload["approval_resume"]["request_id"] == request_id
    assert payload["approval_requests"] == []
    assert_silent_review_recorded(store)


_LIVE_DAEMON_URL = "http://127.0.0.1:61234"


def _held_package_install_output(tmp_path, capsys, monkeypatch, *, token: bool, daemon_url: str | None):
    from codex_plugin_scanner.guard import native_daemon_manage as manager

    def live_daemon_url(_home):
        if isinstance(daemon_url, Exception):
            raise daemon_url
        return daemon_url

    monkeypatch.setattr(manager, "load_guard_daemon_url", live_daemon_url)
    context = _context(tmp_path)
    context.guard_home.chmod(0o700)
    if token:
        token_path = context.guard_home / "daemon-auth-token"
        token_path.write_text("synthetic-daemon-token", encoding="utf-8")
        token_path.chmod(0o600)
    payload = _pending_package_payload()
    store = GuardStore(context.guard_home)
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    request = store.list_approval_requests(status="pending")[0]
    human_payload = _protect_payload_for_human_output(payload, guard_home=context.guard_home)
    render.emit_guard_payload("protect", human_payload, False)
    return human_payload, request, capsys.readouterr().out


def test_local_package_denial_prints_signed_link_to_the_running_daemon(tmp_path, capsys, monkeypatch):
    payload, request, output = _held_package_install_output(
        tmp_path, capsys, monkeypatch, token=True, daemon_url=_LIVE_DAEMON_URL
    )

    review_url = f"{_LIVE_DAEMON_URL}/requests/{request['request_id']}"
    assert short_signed_link(review_url).fullmatch(payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"])
    assert short_signed_link(review_url).search(output)
    assert request["request_id"] in output
    assert "synthetic-daemon-token" not in output


@pytest.mark.parametrize(
    ("token", "daemon_url"),
    [
        (False, _LIVE_DAEMON_URL),
        (True, None),
        (True, NativeDaemonLifecycleError("native_daemon_lifecycle_fact_unknown")),
    ],
    ids=["no-daemon-token", "no-running-daemon", "daemon-lookup-fails"],
)
def test_local_package_denial_without_an_openable_link_keeps_wait_guidance(
    tmp_path, capsys, monkeypatch, token, daemon_url
):
    payload, request, output = _held_package_install_output(
        tmp_path, capsys, monkeypatch, token=token, daemon_url=daemon_url
    )

    user_copy = payload["supply_chain_evaluation"]["user_copy"]
    assert user_copy["dashboard_url"] is None
    assert f"hol-guard approvals wait {request['request_id']}" in user_copy["harness_message"]
    assert "could not create a signed approval link" not in user_copy["harness_message"]
    assert request["request_id"] in output
    assert "#guard-token=" not in output
    assert "could not create a signed approval link" not in output


def test_local_package_malformed_config_stays_blocked(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    (context.guard_home / "config.toml").write_text("[invalid\n", encoding="utf-8")
    payload = _pending_package_payload()
    original_receipt = deepcopy(payload["receipt"])
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    assert payload["policy_action"] == "block"
    assert payload["receipt"] == original_receipt
    assert "hol-guard approvals wait" in payload["review_hint"]
    assert payload["approval_requests"] == []
    assert_silent_review_recorded(store)
