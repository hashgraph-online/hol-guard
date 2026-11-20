"""A decision wait observes one row and leaves approval reuse to the retry."""

import argparse
import json
from threading import Thread
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.blocked_request_mode import approval_wait_hint
from codex_plugin_scanner.guard.cli.approval_wait import run_approval_wait_command
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.native_approval_scope import ApprovalScopeUnavailableError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_codex_resume_commands import _request


@pytest.mark.parametrize("action, expected_code", [("allow", 0), ("block", 1)])
def test_wait_observes_external_decision_without_consuming_it(tmp_path, action, expected_code):
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    store.add_approval_request(_request("unrelated"), "2026-10-22T11:00:00Z")

    def decide():
        # Simulate a separately authenticated UI decision at the store boundary.
        store.resolve_approval_request(
            "req-1",
            resolution_action=action,
            resolution_scope="artifact",
            reason="test",
            resolved_at="2026-10-22T12:00:00Z",
        )

    thread = Thread(target=decide)
    thread.start()
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=2), store=store)
    thread.join()
    assert code == expected_code
    assert payload["resolution_action"] == action
    assert store.get_approval_request("unrelated")["status"] == "pending"
    assert store.get_approval_request("req-1")["status"] == "resolved"
    # Observing a decision repeatedly neither consumes nor changes it.
    assert run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store) == (payload, code)


def test_wait_timeout_and_missing_id_are_not_approval(tmp_path, capsys):
    home = tmp_path / "guard"
    store = GuardStore(home)
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    assert main(["guard", "approvals", "wait", "req-1", "--timeout", "0", "--home", str(home), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "approval_wait_timeout"
    assert store.get_approval_request("req-1")["status"] == "pending"
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="missing", timeout=0), store=store)
    assert (payload["error"], code) == ("not_found", 1)


@pytest.mark.parametrize("timeout", ["-1", "601", "abc"])
def test_wait_rejects_unbounded_timeout(timeout):
    with pytest.raises(SystemExit):
        main(["guard", "approvals", "wait", "req-1", "--timeout", timeout])


@pytest.mark.parametrize("request_id", ["", "-x", "req;id", "$(id)", "req/1", "réq"])
def test_wait_hint_never_interpolates_shell_syntax(request_id, tmp_path, native_mcp_probe):
    native_mcp_probe(tmp_path)
    assert approval_wait_hint(request_id, guard_home=tmp_path) == ""


def test_a_request_deleted_during_wait_is_missing_immediately():
    rows = iter([{"status": "pending"}, None])
    store = SimpleNamespace(get_approval_request=lambda _id: next(rows))
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=2), store=store)
    assert (payload["error"], code) == ("not_found", 1)


@pytest.mark.parametrize("pending_reads", [0, 1])
def test_store_outage_is_machine_readable_and_never_approval(pending_reads):
    def read(_id):
        nonlocal pending_reads
        if pending_reads:
            pending_reads -= 1
            return {"status": "pending"}
        raise ApprovalScopeUnavailableError

    payload, code = run_approval_wait_command(
        argparse.Namespace(request_id="req-1", timeout=2), store=SimpleNamespace(get_approval_request=read)
    )
    assert (payload["error"], payload["status"], code) == ("approval_store_unavailable", "unknown", 3)


def test_custom_home_hint_reaches_the_queued_store(tmp_path, native_mcp_probe):
    native_mcp_probe(tmp_path / "guard home")
    hint = approval_wait_hint("req-1", guard_home=tmp_path / "guard home", home_dir=tmp_path)
    assert "--json --home" in hint
    assert str(tmp_path / "guard home") in hint


def test_human_block_output_names_the_denial(capsys):
    emit_guard_payload(
        "approvals",
        {"title": "Approval decision received", "body": "Keep this action blocked.", "resolution_action": "block"},
        False,
    )
    assert "Approval blocked" in capsys.readouterr().out


def _paired(store):
    store.get_review_event_oauth_binding = lambda: {"oauth_subject_hash": "subject"}
    return store


def test_an_unanswered_cloud_review_request_says_it_expired(tmp_path):
    store = _paired(GuardStore(tmp_path / "guard"))
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store)
    assert code == 2
    assert (payload["error"], payload["status"]) == ("approval_expired", "expired")
    assert "expired" in payload["body"] and "stays blocked" in payload["body"]
    assert store.get_approval_request("req-1")["status"] == "pending"


def test_a_cloud_review_request_inside_its_window_is_still_waiting(tmp_path):
    from datetime import datetime, timezone

    store = _paired(GuardStore(tmp_path / "guard"))
    store.add_approval_request(_request("req-1"), datetime.now(timezone.utc).isoformat())
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store)
    assert (payload["error"], code) == ("approval_wait_timeout", 2)


def test_an_answer_after_the_window_is_still_reported(tmp_path):
    store = _paired(GuardStore(tmp_path / "guard"))
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    store.resolve_approval_request(
        "req-1",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="test",
        resolved_at="2026-10-22T12:00:00Z",
    )
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store)
    assert (payload["resolution_action"], code) == ("allow", 0)


def _raise_store_error():
    import sqlite3

    raise sqlite3.OperationalError("locked")


@pytest.mark.parametrize(
    "binding, row",
    [
        (_raise_store_error, {"status": "pending", "created_at": "2026-10-22T11:00:00Z"}),
        (lambda: {"oauth_subject_hash": "subject"}, {"status": "pending", "created_at": "not-a-time"}),
    ],
)
def test_an_unreadable_deadline_keeps_the_plain_timeout(binding, row):
    store = SimpleNamespace(get_approval_request=lambda _id: dict(row), get_review_event_oauth_binding=binding)
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store)
    assert (payload["error"], payload["status"], code) == ("approval_wait_timeout", "pending", 2)
