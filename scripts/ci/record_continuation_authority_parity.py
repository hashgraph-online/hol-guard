"""Freeze continuation outcomes from a pinned source revision."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import itertools
import json
import sqlite3
import subprocess
import sys
import types
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = "c339d9db720c85664f6bbdc08167e5b750a713bc"
ROOT = Path(__file__).resolve().parents[2]
for name in ("oracle", "oracle.guard"):
    module = types.ModuleType(name)
    module.__path__ = []
    sys.modules[name] = module
hashes = {}
for leaf in ("review_correlation", "continuation_contract", "continuation_payload", "continuation_snapshot"):
    path = f"src/codex_plugin_scanner/guard/{leaf}.py"
    source = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT).decode()
    hashes[path] = hashlib.sha256(source.encode()).hexdigest()
    name = f"oracle.guard.{leaf}"
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, path, "exec"), module.__dict__)
c = sys.modules["oracle.guard.continuation_contract"]
p = sys.modules["oracle.guard.continuation_payload"]
s = sys.modules["oracle.guard.continuation_snapshot"]
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CORRELATION = "gcr_12345678-1234-1234-1234-123456789abc"


def wire(value):
    if dataclasses.is_dataclass(value):
        return {k: wire(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [wire(v) for v in value]
    if isinstance(value, dict):
        return {k: wire(v) for k, v in value.items()}
    return value


cases = []
runtime_path = "src/codex_plugin_scanner/guard/continuation_runtime.py"
runtime_source = subprocess.check_output(["git", "show", f"{BASE}:{runtime_path}"], cwd=ROOT).decode()
hashes[runtime_path] = hashlib.sha256(runtime_source.encode()).hexdigest()
selected = ast.Module(
    body=[
        node
        for node in ast.parse(runtime_source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_finalize_persist_attempt", "_operation_session_id", "_first_text"}
    ],
    type_ignores=[],
)
bindings = {
    **c.__dict__,
    "Mapping": __import__("collections.abc", fromlist=["Mapping"]).Mapping,
    "_SESSION_KEYS": (
        "codex_thread_id",
        "thread_id",
        "threadId",
        "conversation_id",
        "conversationId",
        "session_id",
        "sessionId",
    ),
}
for old, new in [
    ("attempt_count", "_attempt_count"),
    ("continuation_events", "_continuation_events"),
    ("operation_update_payload", "_operation_update_payload"),
    ("text_value", "_text"),
    ("mapping_value", "_mapping"),
    ("offer_hash", "_offer_hash"),
    ("continuation_strategy", "_strategy"),
    ("persisted_resume_status", "_persisted_resume_status"),
]:
    bindings[new] = getattr(p, old)
exec(compile(selected, runtime_path, "exec"), bindings)


class CapturedStore:
    def __init__(self, operation, prior):
        self.operation, self.prior, self.captured = operation, prior, None

    def get_guard_operation_for_approval_request(self, request_id):
        return self.operation

    def get_request_resume(self, request_id):
        return self.prior

    def finalize_continuation_attempt(self, **kwargs):
        self.captured = kwargs
        return True


for capability, action, cancelled in itertools.product(
    ("suspended-response", "session-resume", "retry-only", "unsupported"), ("allow_once", "block"), (True, False)
):
    offer = c.ContinuationOffer(
        CORRELATION,
        "codex",
        capability,
        capability == "suspended-response",
        NOW if capability == "suspended-response" else None,
        "target-12345678" if capability == "session-resume" else None,
    )
    coordinator = c.ContinuationCoordinator(
        record_attempt=lambda *a: None, notify_manual_retry=lambda *a: None, now=lambda: NOW
    )
    outcome = coordinator._terminal_result(offer, action=action, cancelled=lambda value=cancelled: value)
    if outcome is not None:
        outcome = dataclasses.replace(outcome, evidence_id="evidence-12345678")
    cases.append(
        {
            "args": {
                "call": "coordinate",
                "offer": wire(offer),
                "action": action,
                "cancelled": cancelled,
                "now": NOW.isoformat(),
                "evidence_id": "evidence-12345678",
            },
            "expected": {"identity_hash": c._offer_identity(offer), "result": wire(outcome)},
        }
    )
for harness, capability, status, action in itertools.product(
    ("codex", "pi", "hermes", "unknown"),
    ("suspended-response", "session-resume", "retry-only", "unsupported"),
    ("resumed", "already_resumed", "manual_retry_required", "blocked_not_resumed", "unsupported", "failed", "waiting"),
    ("allow_once", "block"),
):
    offer = c.ContinuationOffer(
        CORRELATION,
        harness,
        capability,
        capability == "suspended-response",
        NOW if capability == "suspended-response" else None,
        "target-12345678" if capability == "session-resume" else None,
    )
    result = c.ContinuationResult(CORRELATION, capability, status, "fixture_reason", NOW, "evidence-12345678")
    operation = {
        "operation_id": "operation-1",
        "session_id": "session-1",
        "operation_type": "tool",
        "harness": harness,
        "metadata": {"marker": "snowman \u2603"},
        "approval_request_ids": ["request-1", 1],
        "resume_token": " token ",
    }
    args = {
        "call": "project",
        "offer": wire(offer),
        "result": wire(result),
        "operation": operation,
        "request_id": "request-1",
        "action": action,
        "now": NOW.isoformat(),
    }
    expected = {
        "offer_hash": p.offer_hash(offer),
        "identity_hash": c._offer_identity(offer),
        "payload": p.continuation_payload(offer, result, replayed=False),
        "replayed_payload": p.continuation_payload(offer, result, replayed=True),
        "strategy": p.continuation_strategy(offer, result),
        "persisted_status": p.persisted_resume_status(offer, result),
        "operation_update": p.operation_update_payload(operation, result=result, action=action, now=NOW.isoformat()),
        "events": wire(
            p.continuation_events(
                request_id="request-1", operation_id="operation-1", action=action, offer=offer, result=result
            )
        ),
    }
    cases.append({"args": args, "expected": expected})
    for prior in ({}, {"attempt_count": True}, {"attempt_count": -1}, {"attempt_count": 3}):
        store = CapturedStore(operation, prior)
        bindings["_finalize_persist_attempt"](
            store, request_id="request-1", action=action, offer=offer, result=result, now=NOW.isoformat()
        )
        cases.append(
            {"args": {**args, "call": "finalize", "prior": prior}, "expected": {"finalization": wire(store.captured)}}
        )
for value in [None, [], {}, 1, "bad"] + [
    {
        "correlationId": CORRELATION,
        "capability": capability,
        "hookAttached": attached,
        "opaqueTargetId": target,
        "waitDeadline": deadline,
    }
    for capability, attached, target, deadline in itertools.product(
        ("suspended-response", "session-resume", "retry-only", "unsupported", "bad"),
        (True, False, "yes"),
        (None, "target-12345678", ""),
        (None, "2026-01-01", ""),
    )
]:
    cases.append(
        {
            "args": {"call": "snapshot", "value": value},
            "expected": {"snapshot": s.validated_continuation_snapshot(value)},
        }
    )
store_path = "src/codex_plugin_scanner/guard/store_continuation.py"
store_source = subprocess.check_output(["git", "show", f"{BASE}:{store_path}"], cwd=ROOT).decode()
hashes[store_path] = hashlib.sha256(store_source.encode()).hexdigest()
selected = ast.Module(
    body=[
        node
        for node in ast.parse(store_source).body
        if isinstance(node, ast.FunctionDef) and node.name == "_continuation_claim_allows_finalization"
    ],
    type_ignores=[],
)
store_bindings = {}
exec(compile(selected, store_path, "exec"), store_bindings)
for state, stored_claim, stored_evidence, claim_id in itertools.product(
    (None, "claimed", "waiting", "completed"),
    (None, "claim-original", "claim-foreign"),
    (None, "evidence-original", "evidence-foreign"),
    (None, "claim-original", "claim-foreign"),
):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "create table guard_continuation_claims (request_id,offer_hash,action,state,claim_id,evidence_id)"
    )
    row = None
    if state is not None:
        connection.execute(
            "insert into guard_continuation_claims values ('request','offer','allow_once',?,?,?)",
            (state, stored_claim, stored_evidence),
        )
        row = {"state": state, "claim_id": stored_claim, "evidence_id": stored_evidence}
    try:
        allowed = store_bindings["_continuation_claim_allows_finalization"](
            connection,
            request_id="request",
            offer_hash="offer",
            action="allow_once",
            claim_id=claim_id,
            evidence_id="evidence-original",
        )
        expected = {"allowed": allowed}
    except RuntimeError as error:
        expected = {"error": str(error)}
    cases.append(
        {
            "args": {"call": "claim_check", "row": row, "claim_id": claim_id, "evidence_id": "evidence-original"},
            "expected": expected,
        }
    )
    connection.close()
TARGET = "target-12345678"
for harness, attached, deadline, verified, headless in itertools.product(
    ("codex", " Codex ", "", "  ", "pi", "OMP", "hermes", "other"),
    (False, True),
    (None, NOW + timedelta(hours=1), NOW - timedelta(hours=1), NOW),
    (False, True),
    (False, True),
):
    offer = c.capability_offer(
        correlation_id=CORRELATION,
        harness=harness,
        original_hook_attached=attached,
        wait_deadline=deadline,
        opaque_target_id=TARGET,
        session_target_verified=verified,
        headless=headless,
        now=lambda: NOW,
    )
    cases.append(
        {
            "args": {
                "call": "offer",
                "correlation_id": CORRELATION,
                "harness": harness,
                "original_hook_attached": attached,
                "wait_deadline": wire(deadline),
                "opaque_target_id": TARGET,
                "session_target_verified": verified,
                "headless": headless,
                "now": NOW.isoformat(),
            },
            "expected": {"offer": wire(offer)},
        }
    )

REPLAY_OFFERS = (
    c.capability_offer(
        correlation_id=CORRELATION,
        harness="codex",
        original_hook_attached=True,
        wait_deadline=NOW + timedelta(hours=1),
        now=lambda: NOW,
    ),
    c.capability_offer(
        correlation_id=CORRELATION,
        harness="codex",
        original_hook_attached=False,
        wait_deadline=None,
        opaque_target_id=TARGET,
        session_target_verified=True,
        now=lambda: NOW,
    ),
    c.capability_offer(correlation_id=CORRELATION, harness="pi", original_hook_attached=False, wait_deadline=None),
)


def replay_case(prior, offer, action):
    expected = {"result": wire(p.previous_result(prior, offer=offer, action=action))}
    cases.append(
        {"args": {"call": "replay", "prior": prior, "offer": wire(offer), "action": action}, "expected": expected}
    )


def replay_prior(offer, action, **overrides):
    prior = {
        "continuation_offer_hash": p.offer_hash(offer),
        "continuation_action": action,
        "continuation_status": "resumed",
        "continuation_completed_at": "2026-01-01T00:00:00+00:00",
        "continuation_evidence": [{"evidenceId": "evidence-1"}],
        "continuation_reason": "decision_allowed",
    }
    prior.update(overrides)
    return prior


for offer in REPLAY_OFFERS:
    for action in ("allow_once", "block"):
        replay_case(None, offer, action)
        replay_case([], offer, action)
        replay_case({}, offer, action)
        replay_case(replay_prior(offer, action), offer, action)
        replay_case(replay_prior(offer, "block" if action == "allow_once" else "allow_once"), offer, action)
        replay_case(replay_prior(offer, action, continuation_offer_hash="0" * 64), offer, action)
        replay_case(replay_prior(offer, action, continuation_offer_hash=None), offer, action)
offer = REPLAY_OFFERS[0]
for status, completed in itertools.product(
    (
        "resumed",
        "already_resumed",
        "manual_retry_required",
        "blocked_not_resumed",
        "unsupported",
        "failed",
        "waiting",
        " resumed ",
        "sent",
        "",
        None,
        7,
    ),
    (
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00Z",
        " 2026-01-01T05:30:00+05:30 ",
        "2025-12-31T16:00:00-08:00",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00.123456Z",
        "2026-01-01T00:00:00.120000+00:00",
        "2026-01-01 00:00:00+00:00",
        "2026-01-01",
        "bad",
        "",
        None,
        1767225600,
    ),
):
    replay_case(
        replay_prior(offer, "allow_once", continuation_status=status, continuation_completed_at=completed),
        offer,
        "allow_once",
    )
for evidence, reason in itertools.product(
    (
        [],
        [{"evidenceId": "evidence-1"}],
        ["x", {"evidenceId": " evidence-2 "}],
        [{"evidenceId": ""}, {"evidenceId": "evidence-3"}],
        [{"evidenceId": 5}],
        {"evidenceId": "evidence-4"},
        None,
    ),
    (None, "", "  ", " spaced reason ", "r" * 200, 12),
):
    replay_case(
        replay_prior(offer, "allow_once", continuation_evidence=evidence, continuation_reason=reason),
        offer,
        "allow_once",
    )
for prior in (
    None,
    {},
    [],
    {"attempt_count": None},
    {"attempt_count": True},
    {"attempt_count": False},
    {"attempt_count": -1},
    {"attempt_count": 0},
    {"attempt_count": 3},
    {"attempt_count": 3.0},
    {"attempt_count": "3"},
):
    cases.append({"args": {"call": "attempt", "prior": prior}, "expected": {"attempt_count": p.attempt_count(prior)}})
for value in (
    "waiting",
    "resumed",
    "already_resumed",
    "blocked_not_resumed",
    "manual_retry_required",
    "unsupported",
    "failed",
    "other",
    "",
):
    cases.append({"args": {"call": "status", "value": value}, "expected": {"status": p.public_status(value)}})
document = {"schema": "guard.continuation-parity.v1", "source_revision": BASE, "source_sha256": hashes, "cases": cases}
target = ROOT / "rust/crates/guard-runtime/tests/fixtures/continuation_authority_vectors.json"
target.write_text(json.dumps(document, indent=2, ensure_ascii=True) + "\n")
print(f"froze {len(cases)} original outcomes")


def record_lease_traces():
    method = next(
        item
        for node in ast.parse(store_source).body
        if isinstance(node, ast.ClassDef) and node.name == "StoreContinuationMixin"
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "claim_continuation_attempt"
    )
    fixed = types.ModuleType("fixture")
    fixed.hex = "00112233445566778899aabbccddeeff"
    lease_bindings = {"datetime": datetime, "timedelta": timedelta, "uuid4": lambda: fixed}
    exec(compile(ast.Module(body=[method], type_ignores=[]), store_path, "exec"), lease_bindings)
    schema = (
        "create table guard_continuation_claims (request_id text,offer_hash text,action text,state text,"
        "claimed_at text,lease_expires_at text,claim_id text,evidence_id text,"
        "primary key(request_id,offer_hash,action))"
    )

    class LeaseOwner:
        def __init__(self, connection):
            self.connection = connection

        @contextmanager
        def _connect(self):
            with self.connection:
                yield self.connection

    traces = []
    clocks = (
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00Z",
        "2026-01-01T05:30:00+05:30",
        "2026-01-01T00:00:00",
        "bad",
    )
    existing = (
        (None, None),
        ("claimed", None),
        ("claimed", "2025-12-31T23:59:59Z"),
        ("claimed", "2026-01-01T00:01:00Z"),
        ("claimed", "2026-01-01T00:01:00"),
        ("claimed", "bad"),
        ("waiting", None),
        ("completed", None),
    )
    for clock, seconds, (state, expiry) in itertools.product(clocks, (-1, 0, 0.0000005, 0.0000015, 0.25, 30), existing):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(schema)
        seed = []
        if state is not None:
            seed = [
                ["request", "offer", "allow_once", state, "2025-01-01T00:00:00Z", expiry, "old-claim", "old-evidence"]
            ]
            connection.execute("insert into guard_continuation_claims values (?,?,?,?,?,?,?,?)", seed[0])
            connection.commit()
        args = {
            "request_id": "request",
            "offer_hash": "offer",
            "action": "allow_once",
            "now": clock,
            "lease_seconds": seconds,
        }
        try:
            result = lease_bindings["claim_continuation_attempt"](LeaseOwner(connection), **args)
            outcome = {"claim_id": result}
        except (ValueError, OverflowError) as error:
            outcome = {"error": str(error), "exception": type(error).__name__}
        rows = [list(row) for row in connection.execute("select * from guard_continuation_claims order by request_id")]
        traces.append(
            {"seed": seed, "args": {**args, "new_claim_id": "claim-" + fixed.hex}, "expected": outcome, "rows": rows}
        )
        connection.close()
    output = ROOT / "rust/crates/guard-runtime/tests/fixtures/continuation_lease_traces.json"
    output.write_text(json.dumps({"source_revision": BASE, "schema_sql": schema, "cases": traces}, indent=2) + "\n")


record_lease_traces()
