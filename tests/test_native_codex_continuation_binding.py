"""Exact Rust request commitments and final continuation deadline regressions."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.codex_live_decision import resolve_codex_live_allow_authority
from codex_plugin_scanner.guard.daemon import codex_native_live_decision as completion

from .test_native_codex_live_continuation import _complete, _fixture, _now, _resolve, _Worker
from .test_native_review_policy_binding import _bind_receipt


@pytest.fixture(autouse=True)
def _native_mode(monkeypatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")


@pytest.mark.parametrize("change", ["none", "missing", "relative", "retargeted"])
def test_fresh_native_call_retains_original_ingress_source_home(tmp_path, monkeypatch, change):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    operation = store.get_guard_operation_for_approval_request(row["request_id"])
    assert operation["metadata"]["native_hook_home_dir"] == str(tmp_path)
    real_operation = store.get_guard_operation_for_approval_request

    def changed_operation(request_id):
        original = real_operation(request_id)
        if change == "missing":
            original["metadata"].pop("native_hook_home_dir")
        elif change == "relative":
            original["metadata"]["native_hook_home_dir"] = "different-home"
        elif change == "retargeted":
            original["metadata"]["native_hook_home_dir"] = str(tmp_path / "different-home")
        return original

    monkeypatch.setattr(store, "get_guard_operation_for_approval_request", changed_operation)
    worker = _Worker(store, edge)
    native_call = worker._review_raw_hook_native
    witnessed_homes = []

    def source_bound_result(**kwargs):
        witnessed_homes.append(kwargs["home_dir"])
        if kwargs["home_dir"] != tmp_path:
            # Actual Rust request identity commits source.home_dir. The fake
            # edge models that exact commitment instead of ignoring this input.
            edge["receipt"]["request_digest"] = "e" * 64
            _bind_receipt(edge)
        return native_call(**kwargs)

    monkeypatch.setattr(worker, "_review_raw_hook_native", source_bound_result)
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is (change == "none")
    assert witnessed_homes == (
        [tmp_path] if change == "none" else [tmp_path / "different-home"] if change == "retargeted" else []
    )


@pytest.mark.parametrize("change", ["ancillary_argument", "generation"])
def test_exact_native_request_commitment_rejects_projection_equal_change(tmp_path, change):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    worker = _Worker(store, edge)
    if change == "ancillary_argument":
        hook["tool_input"]["timeout"] = 2
        # The Python display projection omits this field; it is not exact
        # native authority. Rust v3 request identity commits nested arguments.
        from codex_plugin_scanner.guard.runtime.actions import (
            GuardActionEnvelope,
            normalize_harness_payload,
            stable_action_hash,
        )

        projection = normalize_harness_payload("codex", "PreToolUse", hook, home_dir=tmp_path, workspace=workspace)
        assert stable_action_hash(projection) == stable_action_hash(
            GuardActionEnvelope.from_dict(row["action_envelope_json"])
        )
    else:
        edge["receipt"]["policy_generation"] += 1
        worker.snapshot["generation"] += 1
    edge["receipt"]["request_digest"] = "e" * 64
    _bind_receipt(edge)
    assert _complete(store, workspace, edge, hook, row, worker=worker)["completed"] is False
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is not None
    )


def test_final_liveness_work_cannot_cross_owned_deadline_then_consume(tmp_path, monkeypatch):
    store, _workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    clock = [time.monotonic()]
    deadline = clock[0] + 3
    real = completion._original_hook_is_live
    calls = []

    def liveness(*args, **kwargs):
        valid = real(*args, **kwargs)
        calls.append(valid)
        if len(calls) == 2:
            clock[0] = deadline + 1
        return valid

    monkeypatch.setattr(completion, "_original_hook_is_live", liveness)
    monkeypatch.setattr(completion, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    result = completion.complete_native_codex_live_decision(
        store,
        worker=_Worker(store, edge),
        request_id=row["request_id"],
        payload={"hook_input": json.dumps(hook)},
        deadline=deadline,
    )
    assert calls == [True, True] and result["completed"] is False
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is not None
    )


def test_slow_atomic_finalize_retains_consumption_but_never_delivers_late_allow(tmp_path, monkeypatch):
    store, _workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    clock = [time.monotonic()]
    deadline = clock[0] + 3
    real = store.finalize_continuation_attempt

    def finalize(**kwargs):
        persisted = real(**kwargs)
        clock[0] = deadline + 1
        return persisted

    monkeypatch.setattr(store, "finalize_continuation_attempt", finalize)
    monkeypatch.setattr(completion, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    result = completion.complete_native_codex_live_decision(
        store,
        worker=_Worker(store, edge),
        request_id=row["request_id"],
        payload={"hook_input": json.dumps(hook)},
        deadline=deadline,
    )
    assert result["completed"] is False
    assert store.get_request_resume(row["request_id"])["status"] == "sent"
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is None
    )


def test_original_browser_deadline_is_rechecked_after_atomic_finalize(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    operation = store.get_guard_operation_for_approval_request(row["request_id"])
    waiter_deadline = datetime.fromisoformat(operation["metadata"]["codex_browser_wait_deadline_at"])
    clock = [datetime.now(timezone.utc)]

    class ClockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz)

    real = store.finalize_continuation_attempt

    def finalize(**kwargs):
        committed = real(**kwargs)
        clock[0] = waiter_deadline + timedelta(microseconds=1)
        return committed

    monkeypatch.setattr(completion, "datetime", ClockDateTime)
    monkeypatch.setattr(store, "finalize_continuation_attempt", finalize)
    result = _complete(store, workspace, edge, hook, row)
    assert result == {"completed": False, "error": "fresh_policy_revalidation_failed"}
    assert store.get_request_resume(row["request_id"])["status"] == "sent"
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is None
    )


@pytest.mark.parametrize("previously_consumed", [False, True])
def test_store_reopen_retains_exact_live_authority_and_replay(tmp_path, previously_consumed):
    from codex_plugin_scanner.guard.store import GuardStore

    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    if previously_consumed:
        assert _complete(store, workspace, edge, hook, row)["completed"] is True
    reopened = GuardStore(store.guard_home)
    worker = _Worker(reopened, edge)
    result = _complete(reopened, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is True and result["action"] == "allow"
    assert result["replayed"] is previously_consumed
    assert worker.calls == 1 and worker.routes == ["native_resident"]
    assert reopened.get_request_resume(row["request_id"])["status"] == "sent"
    assert (
        resolve_codex_live_allow_authority(
            reopened,
            request=reopened.get_approval_request(row["request_id"]),
            request_id=row["request_id"],
            now=_now(),
        )
        is None
    )


@pytest.mark.parametrize("corruption", ["missing", "changed", "retargeted"])
def test_signed_once_artifact_prevents_mutable_envelope_retarget(tmp_path, monkeypatch, corruption):
    from codex_plugin_scanner.guard.daemon.hook_native_review_binding import NATIVE_REVIEW_REQUEST_DIGEST_FIELD

    store, workspace, edge, hook, row = _fixture(tmp_path)
    assert (
        row["artifact_hash"]
        == row["action_envelope_json"][NATIVE_REVIEW_REQUEST_DIGEST_FIELD]
        == edge["receipt"]["request_digest"]
    )
    _resolve(store, row)
    real = store.get_approval_request

    def altered(request_id):
        current = real(request_id)
        if corruption == "missing":
            current["action_envelope_json"].pop(NATIVE_REVIEW_REQUEST_DIGEST_FIELD)
        else:
            current["action_envelope_json"][NATIVE_REVIEW_REQUEST_DIGEST_FIELD] = "e" * 64
            if corruption == "retargeted":
                current["artifact_hash"] = "e" * 64
        return current

    monkeypatch.setattr(store, "get_approval_request", altered)
    if corruption == "retargeted":
        edge["receipt"]["request_digest"] = "e" * 64
        _bind_receipt(edge)
    assert _complete(store, workspace, edge, hook, row)["completed"] is False


@pytest.mark.parametrize("persist_policy", [None, False])
def test_native_codex_allow_once_does_not_mutate_the_acknowledged_policy(tmp_path, persist_policy):
    from codex_plugin_scanner.guard.approvals import apply_approval_resolution

    store, workspace, edge, hook, row = _fixture(tmp_path)
    apply_approval_resolution(
        store=store,
        request_id=row["request_id"],
        action="allow",
        scope="artifact",
        workspace=None,
        reason="Synthetic exact native once",
        persist_policy=persist_policy,
        resolve_scope_matches=False,
    )
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
    assert _complete(store, workspace, edge, hook, row)["completed"] is True


@pytest.mark.parametrize("with_unconsumed_authority", [False, True])
def test_unsigned_terminal_resume_cannot_authorize_native_review(tmp_path, monkeypatch, with_unconsumed_authority):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    if with_unconsumed_authority:
        _resolve(store, row)
    else:
        store.resolve_one_request_only(
            row["request_id"],
            resolution_action="allow",
            resolution_scope="artifact",
            reason="Unsigned fixture status",
            resolved_at=_now(),
        )
    monkeypatch.setattr(
        store,
        "get_request_resume",
        lambda request_id: {"request_id": request_id, "resolution_action": "allow", "status": "sent"},
    )
    assert _complete(store, workspace, edge, hook, row)["completed"] is False


def test_terminal_row_forged_after_precheck_cannot_skip_atomic_consume(tmp_path, monkeypatch):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    real = store.get_request_resume
    calls = []

    def resume(request_id):
        calls.append(request_id)
        if len(calls) > 1:
            return {"request_id": request_id, "resolution_action": "allow", "status": "sent"}
        return real(request_id)

    monkeypatch.setattr(store, "get_request_resume", resume)
    assert _complete(store, workspace, edge, hook, row)["completed"] is False
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is not None
    )


def test_registered_waiter_cannot_reuse_a_legacy_resolved_row(tmp_path):
    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )

    store, workspace, edge, hook, row = _fixture(tmp_path, proof=False)
    _resolve(store, row)
    hook[CODEX_BROWSER_WAIT_PROCESS_KEY] = current_process_identity()
    hook[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = 120
    response = pause_native_pre_tool_for_approval(
        store,
        harness="codex",
        payload=hook,
        native_result=edge["result"],
        native_receipt=None,
        workspace=workspace,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        verified_receipt=edge["receipt"],
    )
    assert response["policy_action"] == "review"
    assert response["approval_request_id"] != row["request_id"]
    assert "approval_reuse_status" not in response
