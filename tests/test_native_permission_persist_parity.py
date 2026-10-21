"""A Claude-native approval saves exactly what the resident's plan names.

``scripts/ci/record_native_permission_persist_vectors.py`` recorded the retired
Python decision logic against a recording store. The Rust suite replays the
plan field of each vector; this suite hands each recorded plan back through the
transport and checks the executors write the same operations, in the same
order, as the Python that decided them. The stored hash is what a later lookup
matches a saved approval by, so the literal bytes are pinned as well.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_hook_route as route_module
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateError
from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.cli import commands_hook_native_route as route_run
from codex_plugin_scanner.guard.cli import commands_hook_native_route_handlers as handlers
from codex_plugin_scanner.guard.cli import commands_support_permission_store as permission_store

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/native_permission_persist_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_native_permission_persist_vectors.py"
FEATURE = decision.HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE
HOME = Path("/tmp/hook-decision-home")

# The bytes a saved approval is matched by; each is also pinned in the Rust replay suite.
# A v1 approval-context token is stored exactly as given.
WELL_FORMED_TOKEN = (
    "guard-approval-context:v1:eyJjYXBhYmlsaXRpZXMiOiIwOTcxNjBmMzZjNWY1ZTEwNDE4NzU4YzBkOGQ1Zjhj"
    "MWUzZTc2YTMwMmU5YTdkMWZmNWFmMjljYThiM2JhYzg1IiwiY29udGVudCI6ImQ5OTQ2NTU5NzQ1MGIxODQ4MzU4Zj"
    "NlNjY3MjBjNjQ2ZjdhMzFkODQ4MTVmNjk4NDU3NDVmOTY2YzY0MDhjODAiLCJpZGVudGl0eSI6ImM5ZWEzN2I4NGJh"
    "MTBjMzlhYTg5MDg3ODE4NjMyNTE5MzNmNjBhYjY1ZTEzMjVjNTZiYTk4YzY5NzY1ZWJkYjIiLCJwb2xpY3kiOiI3Yz"
    "A5NGM1YTRkMjgyODVlYzg3NTI3MTI1NWY2NzIzZWVlZWY3YjhmNjgzZjA2NmU4OGZjOTQyOTEwYzUwMGIyIiwic2Fu"
    "ZGJveCI6IjRlNWU0ZWYwY2Y4YTIwZDk2MThkNzY2MzRkMzdlYmU0NGNkODk1NzA3MGEyZjAyYzcwYTkyMTExODQzYjAzZjMiLCJ2ZXJzaW9uIjoxfQ"
)
TOOL_ACTION_ID = "claude-code:runtime:tool-action:abc123"
LEGACY_HASH = "hash-native"
# A legacy hash is replaced by sha256 of the identity (and of its context, when it has one).
LEGACY_EXACT_KEY = "runtime-exact:44869672e5a90ec571e6ba62a2aec9cded44bdf7a09b4d477a679f972b70a534"
LEGACY_EXACT_KEY_WITH_CONTEXT = "runtime-exact:7ee804454b012f82e91b2fbd4b5471f53c41c1fb9d6ad108a3625a22f01e79bc"
PLAN_NOW = "2026-10-20T00:00:00+00:00"


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_native_permission_persist_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict[str, Any]]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def _store_class(recorder: Any) -> type:
    class Store(recorder.RecordingStore):
        guard_home = HOME

    return Store


class _Resident:
    """The stubbed resident: records what it was asked and answers with ``answer``."""

    def __init__(self) -> None:
        self.asked: list[dict[str, Any]] = []
        self.features: set[str] = {"resident-protocol-v2", FEATURE}
        self.available = True
        self.answer: Any = None

    def status(self) -> SimpleNamespace:
        return SimpleNamespace(
            available=self.available,
            compatible=True,
            identity=object(),
            capabilities=SimpleNamespace(features=set(self.features)),
        )

    def transport(self, *, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any] | None:
        assert required_feature == FEATURE
        if not self.available or required_feature not in self.features:
            return None
        self.asked.append(request["query"])
        payload = self.answer(request["query"]) if callable(self.answer) else self.answer
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }


@pytest.fixture
def resident(monkeypatch: pytest.MonkeyPatch) -> _Resident:
    stub = _Resident()
    monkeypatch.setattr(shared, "native_runtime_status", stub.status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: HOME)
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(decision, "_resident_request", stub.transport)
    return stub


@pytest.fixture
def recorder() -> Any:
    return _recorder()


def _plan(**changes: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "kind": "native_permission_persist_plan",
        "stored_artifact_hash": "stored-hash",
        "policy_action": "allow",
        "events": [
            {
                "name": "claude/native_permission_saved",
                "payload": {
                    "artifact_id": "claude-code:runtime:bash:demo",
                    "artifact_hash": "stored-hash",
                    "action": "allow",
                    "reason": "native approval",
                },
                "before_policy": False,
            }
        ],
        "inventory_approved": True,
    }
    plan.update(changes)
    return plan


def _policy(store: Any, **changes: Any) -> bool:
    arguments: dict[str, Any] = {
        "store": store,
        "artifact_id": "claude-code:runtime:bash:demo",
        "artifact_hash": LEGACY_HASH,
        "artifact_type": "tool_action_request",
        "action": "allow",
        "reason": "native approval",
        "now": PLAN_NOW,
    }
    arguments.update(changes)
    return permission_store._persist_claude_native_permission_policy(**arguments)


def _artifact(inputs: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_id=inputs["artifact_id"],
        artifact_type=inputs["artifact_type"],
        config_path=inputs["config_path"],
        source_scope=inputs["source_scope"],
        metadata={"raw_command_text": inputs["raw_command_text"], "wrapper_chain": inputs["wrapper_chain"]},
    )


def _stub_pending(monkeypatch: pytest.MonkeyPatch, now: str) -> None:
    monkeypatch.setattr(permission_store, "_now", lambda: now)
    monkeypatch.setattr(
        permission_store, "_load_claude_pending_permission", lambda *_a, **_k: {"permission_prompt_seen": True}
    )
    monkeypatch.setattr(
        permission_store,
        "_remove_claude_pending_permission",
        lambda store, *, session_id, artifact_id: store.remove_pending(session_id, artifact_id),
    )


def _execute(vector: dict[str, Any], store: Any) -> Any:
    inputs = vector["inputs"]
    if vector["entry"] == "policy":
        return _policy(
            store,
            artifact_id=inputs["artifact_id"],
            artifact_hash=inputs["artifact_hash"],
            artifact_type=inputs["artifact_type"],
            config_path=inputs["config_path"],
            source_scope=inputs["source_scope"],
            raw_command_text=inputs["raw_command_text"],
            wrapper_chain=inputs["wrapper_chain"],
            action=inputs["action"],
            reason=inputs["reason"],
            source=inputs["source"],
        )
    return list(
        permission_store._persist_claude_native_permission_for_runtime_artifact(
            store=store,
            payload={"session_id": "recorded-session"},
            artifact=_artifact(inputs),
            artifact_hash=inputs["artifact_hash"],
            action=inputs["action"],
            authoritative_action=inputs["authoritative_action"],
            reason=inputs["reason"],
        )
    )


def test_executors_write_what_the_recorded_python_wrote(
    monkeypatch: pytest.MonkeyPatch, resident: _Resident, recorder: Any
) -> None:
    store_class = _store_class(recorder)
    _stub_pending(monkeypatch, recorder.NOW)
    vectors = _vectors()
    assert len(vectors) > 2700
    current: list[dict[str, Any]] = []

    def answer(query: dict[str, Any]) -> dict[str, Any]:
        assert query == {"kind": "native_permission_persist_plan", "inputs": current[0]["inputs"]}
        return {"kind": "native_permission_persist_plan", **current[0]["plan"]}

    resident.answer = answer
    failures: list[str] = []
    replayed = 0
    eligible = [v for v in vectors if not (v["flavor"] == "posix" and sys.platform == "win32")]
    for vector in eligible:
        home = vector["inputs"]["tilde_home"]
        monkeypatch.setattr(os.path, "expanduser", lambda _path, home=home: home if home is not None else "~")
        current[:] = [vector]
        store = store_class()
        replayed += 1
        returns = _execute(vector, store)
        if store.ops != vector["ops"] or returns != vector["returns"]:
            failures.append(f"{vector['inputs']}: wrote {store.ops} returned {returns!r}")
        if len(failures) > 5:
            break
    assert failures == []
    # Windows skips the POSIX path vectors; every other vector still has to replay.
    assert replayed == len(eligible)
    assert replayed > (900 if sys.platform == "win32" else 2500)


def test_a_well_formed_token_is_stored_as_given(resident: _Resident, recorder: Any) -> None:
    resident.answer = _plan(stored_artifact_hash=WELL_FORMED_TOKEN)
    store = _store_class(recorder)()
    assert _policy(store, artifact_hash=WELL_FORMED_TOKEN) is True
    upsert = next(op for op in store.ops if op["op"] == "upsert_policy")
    assert upsert["artifact_hash"] == WELL_FORMED_TOKEN
    assert resident.asked[0]["inputs"]["artifact_hash"] == WELL_FORMED_TOKEN


def _stored_by(**inputs: Any) -> set[str | None]:
    return {
        vector["plan"]["stored_artifact_hash"]
        for vector in _vectors()
        if vector["entry"] == "policy" and all(vector["inputs"][key] == value for key, value in inputs.items())
    }


def test_recorded_vectors_pin_the_stored_hashes() -> None:
    # A well-formed token is stored as given, whatever the identity and context around it.
    assert _stored_by(artifact_hash=WELL_FORMED_TOKEN) == {WELL_FORMED_TOKEN}
    # The legacy hash of a command with no recorded location or text becomes its exact-match key.
    bare = {
        "artifact_id": TOOL_ACTION_ID,
        "artifact_hash": LEGACY_HASH,
        "artifact_type": "tool_action_request",
        "config_path": None,
        "source_scope": None,
        "raw_command_text": None,
        "wrapper_chain": None,
    }
    assert _stored_by(**bare) == {LEGACY_EXACT_KEY}
    # The same command bound to its config path, scope, text and wrapper chain keys differently.
    bound = {
        **bare,
        "config_path": "/repo/.claude/settings.json",
        "source_scope": "project",
        "raw_command_text": "git status",
        "wrapper_chain": ["bash", "-lc"],
        "tilde_home": "/home/recorder",
    }
    assert _stored_by(**bound) == {LEGACY_EXACT_KEY_WITH_CONTEXT}
    # Across every hash shape recorded for that bare command, a token is kept only when well formed.
    pairs = {
        (vector["inputs"]["artifact_hash"], vector["plan"]["stored_artifact_hash"])
        for vector in _vectors()
        if vector["entry"] == "policy"
        and all(
            vector["inputs"][key] == value
            for key, value in {**bare, "artifact_hash": None}.items()
            if key != "artifact_hash"
        )
    }
    assert all(kept in {LEGACY_EXACT_KEY, given} for given, kept in pairs)
    prefixed = {(given, kept) for given, kept in pairs if given.startswith("guard-approval-context:v1:")}
    assert any(given == kept for given, kept in prefixed)
    assert any(kept == LEGACY_EXACT_KEY for _, kept in prefixed)


@pytest.mark.parametrize(
    "failure",
    [sqlite3.OperationalError("locked"), OSError("disk"), ApprovalGateError("approval_gate_required", "gate")],
)
def test_a_refused_write_reports_unsaved(resident: _Resident, recorder: Any, failure: Exception) -> None:
    resident.answer = _plan()
    store = _store_class(recorder)()

    def refuse(_decision: object, _now: str) -> None:
        raise failure

    store.upsert_policy = refuse  # type: ignore[method-assign]
    assert _policy(store) is False
    assert [op["op"] for op in store.ops] == []


def test_a_refused_leading_event_writes_no_policy_row(resident: _Resident, recorder: Any) -> None:
    resident.answer = _plan(
        events=[
            {
                "name": "claude/native_permission_exact_key_missing",
                "payload": {"artifact_id": "x"},
                "before_policy": True,
            },
            {"name": "claude/native_permission_saved", "payload": {"artifact_id": "x"}, "before_policy": False},
        ]
    )
    store = _store_class(recorder)()

    def refuse(_name: str, _payload: object, _now: str) -> None:
        raise sqlite3.OperationalError("locked")

    store.add_event = refuse  # type: ignore[method-assign]
    assert _policy(store) is False
    assert store.ops == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"extra": True},
        {"policy_action": None},
        {"stored_artifact_hash": None},
        {"policy_action": "warn"},
        {"inventory_approved": "yes"},
        {"events": []},
        {"events": "none"},
        {"events": [{"name": "claude/native_permission_saved", "payload": {}, "before_policy": True}]},
        {"events": [{"name": "claude/native_permission_other", "payload": {}, "before_policy": False}]},
        {"events": [{"name": "claude/native_permission_saved", "payload": [], "before_policy": False}]},
        {"events": [{"name": "claude/native_permission_saved", "payload": {}, "before_policy": False, "extra": 1}]},
        {
            "events": [
                {"name": "claude/native_permission_saved", "payload": {}, "before_policy": False},
                {"name": "claude/native_permission_exact_key_missing", "payload": {}, "before_policy": True},
            ]
        },
        {
            "stored_artifact_hash": None,
            "policy_action": None,
            "events": [{"name": "claude/native_permission_saved", "payload": {}, "before_policy": False}],
        },
    ],
)
def test_a_malformed_plan_fails_closed_before_any_write(
    resident: _Resident, recorder: Any, overrides: dict[str, Any]
) -> None:
    resident.answer = _plan(**overrides)
    store = _store_class(recorder)()
    with pytest.raises(decision.NativeHookDecisionError):
        _policy(store)
    assert store.ops == []


def test_a_plan_without_a_kind_fails_closed(resident: _Resident, recorder: Any) -> None:
    plan = _plan()
    del plan["kind"]
    resident.answer = plan
    store = _store_class(recorder)()
    with pytest.raises(decision.NativeHookDecisionError):
        _policy(store)
    assert store.ops == []


def test_an_unavailable_resident_fails_closed_before_any_write(
    resident: _Resident, recorder: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident.available = False
    store = _store_class(recorder)()
    with pytest.raises(decision.NativeHookDecisionError) as error:
        _policy(store)
    assert error.value.code == "native_hook_decision_unavailable"
    assert store.ops == []
    assert resident.asked == []


def test_a_resident_without_the_capability_fails_closed(resident: _Resident, recorder: Any) -> None:
    resident.features = {"resident-protocol-v2"}
    store = _store_class(recorder)()
    with pytest.raises(decision.NativeHookDecisionError) as error:
        _policy(store)
    assert error.value.code == "native_hook_decision_unavailable"
    assert store.ops == []


def test_an_unavailable_resident_leaves_a_native_answer_unrecorded(
    resident: _Resident, recorder: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident.available = False
    _stub_pending(monkeypatch, PLAN_NOW)
    store = _store_class(recorder)()
    inputs = {
        "artifact_id": "claude-code:runtime:bash:demo",
        "artifact_type": "tool_action_request",
        "config_path": None,
        "source_scope": "project",
        "raw_command_text": "echo hi",
        "wrapper_chain": None,
    }
    with pytest.raises(decision.NativeHookDecisionError):
        permission_store._persist_claude_native_permission_for_runtime_artifact(
            store=store,
            payload={"session_id": "session"},
            artifact=_artifact(inputs),
            artifact_hash=LEGACY_HASH,
            action="allow",
            authoritative_action="allow",
            reason="native approval",
        )
    assert store.ops == []


def test_a_retained_plan_records_its_event_and_the_inventory_disposition(
    resident: _Resident, recorder: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_pending(monkeypatch, PLAN_NOW)
    event = {
        "name": "claude/native_permission_current_policy_retained",
        "payload": {"artifact_id": "x", "authoritative_action": "block"},
        "before_policy": False,
    }
    resident.answer = _plan(stored_artifact_hash=None, policy_action=None, events=[event], inventory_approved=False)
    store = _store_class(recorder)()
    inputs = {
        "artifact_id": "claude-code:runtime:bash:demo",
        "artifact_type": "tool_action_request",
        "config_path": None,
        "source_scope": "project",
        "raw_command_text": "echo hi",
        "wrapper_chain": None,
    }
    observed, saved = permission_store._persist_claude_native_permission_for_runtime_artifact(
        store=store,
        payload={"session_id": "session"},
        artifact=_artifact(inputs),
        artifact_hash=LEGACY_HASH,
        action="allow",
        authoritative_action="block",
        reason="native approval",
    )
    assert (observed, saved) == (True, False)
    assert [op["op"] for op in store.ops] == ["add_event", "record_inventory", "remove_pending"]
    assert store.ops[1]["approved"] is False


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(resident: _Resident) -> None:
    resident.answer = _plan()
    inputs = {
        "artifact_id": "a",
        "artifact_hash": "h",
        "artifact_type": None,
        "config_path": None,
        "source_scope": None,
        "raw_command_text": None,
        "wrapper_chain": None,
        "action": "allow",
        "reason": "r",
        "source": "s",
        "authoritative_action": None,
    }
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_permission_persist_plan({key: value for key, value in inputs.items() if key != "reason"})
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_permission_persist_plan({**inputs, "tilde_home": "/home/x"})
    assert resident.asked == []


def test_the_home_directory_follows_the_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/home/recorder")
    monkeypatch.setenv("USERPROFILE", "/home/recorder")
    assert decision._tilde_home() == os.path.expanduser("~")
    monkeypatch.setattr(os.path, "expanduser", lambda _path: "~")
    assert decision._tilde_home() is None


def test_an_outage_while_saving_an_ask_user_question_answer_emits_the_unavailable_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"session_id": "session", "hook_event_name": "PostToolUse", "tool_name": "AskUserQuestion"}
    emitted: list[dict[str, Any]] = []

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

    def emit(args: object, **kwargs: Any) -> int:
        emitted.append(kwargs)
        return 7

    state = (payload, None, False, None, None, None, None, None)
    monkeypatch.setattr(pipeline, "_normalize_hook_payload", lambda value, **_kwargs: value)
    monkeypatch.setattr(pipeline, "prepare_native_hook_state", lambda *_args, **_kwargs: state)
    monkeypatch.setattr(
        pipeline,
        "native_hook_route",
        lambda _inputs, **_kwargs: route_module.NativeHookRoute(("claude_guard_question",), "PostToolUse"),
    )
    monkeypatch.setattr(handlers, "_load_single_claude_pending_permission", lambda *_a, **_k: ("key", {}))
    monkeypatch.setattr(handlers, "_claude_guard_question_verdict", lambda *_a, **_k: SimpleNamespace(is_question=True))
    monkeypatch.setattr(handlers, "_persist_claude_guard_question_decision", unavailable)
    monkeypatch.setattr(route_run, "_emit_native_unavailable", emit)
    context = SimpleNamespace(guard_home=HOME, home_dir=HOME)

    rc = pipeline.run_native_hook_pipeline(
        SimpleNamespace(harness="claude-code"),  # type: ignore[arg-type]
        config=object(),  # type: ignore[arg-type]
        context=context,  # type: ignore[arg-type]
        payload=payload,
        runtime_workspace=None,
        store=SimpleNamespace(),  # type: ignore[arg-type]
        worker=SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert rc == 7
    assert len(emitted) == 1
    assert emitted[0]["reason_code"] == "native_hook_decision_unavailable"
    assert emitted[0]["event_name"] == "PostToolUse"
