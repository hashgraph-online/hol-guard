"""Replay recorded workflow-capability scenarios through the real GuardStore."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard import store_workflow_capabilities
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import WorkflowCapabilityError
from tests.workflow_capability_transitions_support import (
    authority_transition_sha256,
    decode_signed_authority_transition,
)

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

DATA_DIR = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/guard_store"
sys.path.insert(0, str(DATA_DIR))
import workflow_capability_scenarios  # noqa: E402
import workflow_capability_tamper_scenarios  # noqa: E402
from workflow_capability_factories import KEY, KEY_ID, OTHER_KEY, OTHER_KEY_ID  # noqa: E402

LAST = workflow_capability_scenarios.LAST
SCENARIOS = {
    scenario["name"]: scenario
    for scenario in [*workflow_capability_scenarios.SCENARIOS, *workflow_capability_tamper_scenarios.SCENARIOS]
}
TABLES = {
    "guard_workflow_capabilities": "capability_id",
    "guard_workflow_capability_authority_state": "capability_id",
    "guard_workflow_capability_revocations": "revocation_id",
    "guard_workflow_capability_receipts": "receipt_id",
    "guard_workflow_capability_authority_transitions": "sequence",
    "guard_events": "event_id",
    "schema_migrations": "version",
}


def canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class FakeBlobStore:
    """The external control blob: in-memory, with per-step store faults."""

    def __init__(self) -> None:
        self.blob: str | None = None
        self.writes: list[dict[str, object]] = []
        self.fail_at: int | None = None

    def load(self) -> str | None:
        return self.blob

    def store(self, encoded: str) -> bool:
        accepted = self.fail_at != len(self.writes) + 1
        self.writes.append({"value": encoded, "ok": accepted})
        if accepted:
            self.blob = encoded
        return accepted


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        existing = {row[0] for row in connection.execute("select name from sqlite_master where type = 'table'")}
        return {
            table: [dict(row) for row in connection.execute(f"select * from {table} order by {key}")]
            for table, key in TABLES.items()
            if table in existing
        }
    finally:
        connection.close()


def _transition_hash(path: Path, sequence: int) -> str:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "select signed_transition_json from guard_workflow_capability_authority_transitions where sequence = ?",
            (sequence,),
        ).fetchone()
    finally:
        connection.close()
    return authority_transition_sha256(decode_signed_authority_transition(row[0]))


def _invoke(store: GuardStore, step: Mapping[str, Any]) -> Any:
    op = step["op"]
    if op == "issue":
        # The recorded vectors carry pre-signed envelopes, including ones signed
        # with the wrong key that the resident must reject, so they travel the
        # resident's recorded `signed_json` route rather than the live claim
        # route, which would have the resident sign them validly.
        return store._run_workflow_capability(
            "issue",
            WORKFLOW_CAPABILITY_STORE_CLOCK.now(),
            {
                "signed_json": store_workflow_capabilities._canonical_json(step["signed"].to_dict()),
                "approval_provenance_id": step["approval_provenance_id"],
            },
        )
    if op == "claim":
        return store.claim_workflow_capability(
            step["capability_id"],
            invocation_id=step["invocation_id"],
            expected_binding=step["expected_binding"],
            expected_subject_id=step["expected_subject_id"],
            expected_task_id=step["expected_task_id"],
            expected_issuer_id=step["expected_issuer_id"],
            expected_approval_provenance_id=step["expected_approval_provenance_id"],
        )
    if op == "revoke":
        return store.revoke_workflow_capability(step["capability_id"], reason_code=step["reason_code"])
    if op == "lookup":
        return store.lookup_workflow_capability(step["capability_id"])
    return store.lookup_workflow_capability_receipt(receipt_id=step["receipt_id"], invocation_id=step["invocation_id"])


def _encode(op: str, result: object) -> object:
    if op == "revoke":
        return result
    if result is None:
        return None
    # `issue` travels the resident's recorded route, which answers with the
    # envelope itself; the other ops answer with a typed value.
    payload = result if isinstance(result, Mapping) else result.to_dict()  # type: ignore[attr-defined]
    return canonical(payload)


@contextmanager
def patched_store(blob: FakeBlobStore, clock: dict[str, str]) -> Iterator[Callable[[Path], GuardStore]]:
    saved = (store_workflow_capabilities.uuid4, WORKFLOW_CAPABILITY_STORE_CLOCK.now)
    store_workflow_capabilities.uuid4 = lambda: SimpleNamespace(hex=clock["uuid"])  # type: ignore[assignment]
    WORKFLOW_CAPABILITY_STORE_CLOCK.now = lambda: clock["now"]  # type: ignore[method-assign]
    try:
        yield lambda root: GuardStore(root / "guard-home", prime_policy_integrity=False)
    finally:
        store_workflow_capabilities.uuid4, WORKFLOW_CAPABILITY_STORE_CLOCK.now = saved  # type: ignore[assignment,method-assign]


def replay(name: str, recorded: Mapping[str, Any]) -> list[tuple[dict[str, object], dict[str, object]]]:
    """Return (expected, actual) pairs for every recorded step of one scenario."""

    blob = FakeBlobStore()
    clock = {"now": "", "uuid": ""}
    pairs: list[tuple[dict[str, object], dict[str, object]]] = []
    marks: dict[str, str | None] = {}
    with patched_store(blob, clock) as make_store, tempfile.TemporaryDirectory(prefix="guard-wfcap-") as root:
        store = make_store(Path(root))
        material: dict[str, tuple[bytes | None, str | None]] = {"key": (KEY, KEY_ID)}
        store._policy_integrity_secret_material = lambda *, create: material["key"]  # type: ignore[method-assign]
        store._load_workflow_capability_control = blob.load  # type: ignore[method-assign]
        store._store_workflow_capability_control = blob.store  # type: ignore[method-assign]
        path = Path(store.path)
        previous = dump(path)
        last_receipt = ""

        class Ctx:
            blob = property(lambda self: blob.blob)
            marks = property(lambda self: marks)
            transition_hash = staticmethod(lambda sequence: _transition_hash(path, sequence))

        for step, expected in zip(SCENARIOS[name]["steps"], recorded["steps"], strict=True):
            if step["op"] == "sql":
                connection = sqlite3.connect(path)
                if "fn" in step:
                    step["fn"](_Recording(connection))
                else:
                    for statement, params in step["statements"]:
                        connection.execute(statement, params)
                connection.commit()
                connection.close()
                actual: dict[str, object] = {}
            elif step["op"] == "blob":
                blob.blob = step["fn"](Ctx())
                actual = {"value": blob.blob}
            else:
                recorded_wire = expected["wire"]
                new_id = (
                    recorded_wire.get("receipt_id") if step["op"] == "claim" else recorded_wire.get("revocation_id")
                )
                clock["uuid"] = str(new_id or "-").split("-", 1)[1]
                actual = _run_step(store, blob, clock, material, step, last_receipt)
                if step["op"] == "claim" and actual["result"] is not None:
                    last_receipt = json.loads(str(actual["result"]))["receipt"]["receipt_id"]
            if "mark" in step:
                marks[step["mark"]] = blob.blob
            current = dump(path)
            actual["post_changed"] = {t: rows for t, rows in current.items() if rows != previous.get(t)}
            previous = current
            keys = {"post_changed", *actual.keys()} - {"statements"}
            pairs.append(({key: expected[key] for key in keys if key in expected}, actual))
    return pairs


class _Recording:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def execute(self, statement: str, params: tuple = ()) -> None:
        self.connection.execute(statement, params)

    def query(self, statement: str, params: tuple = ()) -> list[tuple]:
        return [tuple(row) for row in self.connection.execute(statement, params)]


def _run_step(
    store: GuardStore,
    blob: FakeBlobStore,
    clock: dict[str, str],
    material: dict[str, tuple[bytes | None, str | None]],
    step: Mapping[str, Any],
    last_receipt: str,
) -> dict[str, object]:
    fault = step.get("fault")
    blob.writes = []
    blob.fail_at = int(fault.rsplit("_", 1)[1]) if fault and fault.startswith("fail_store_") else None
    other = step.get("key") == "other"
    keyed = (OTHER_KEY, OTHER_KEY_ID) if other else (KEY, KEY_ID)
    material["key"] = (None, None) if fault == "no_key" else keyed
    if step.get("receipt_id") == LAST:
        step = {**step, "receipt_id": last_receipt}
    clock["now"] = step["now"]
    outcome: dict[str, object]
    try:
        outcome = {"result": _encode(step["op"], _invoke(store, step)), "error": None}
    except WorkflowCapabilityError as error:
        outcome = {"result": None, "error": {"kind": "capability", "code": str(error)}}
    except RuntimeError as error:
        outcome = {"result": None, "error": {"kind": "runtime", "message": str(error)}}
    return {**outcome, "blob_writes": blob.writes, "blob_after": blob.blob}
