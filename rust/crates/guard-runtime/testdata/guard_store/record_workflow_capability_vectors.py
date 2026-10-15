#!/usr/bin/env python3
"""Record workflow-capability store vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of the workflow-capability mixins, never against the branch under test and
never from Rust output:

    cd <worktree-with-old-python>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario replays `workflow_capability_scenarios` and
`workflow_capability_tamper_scenarios` through the real `GuardStore` on a real
`guard.db`, with the key, clock, ids and the external control blob replaced by
deterministic fakes. Per step the vectors hold the request the native
transport sends (`wire`), the Python-visible outcome, every control blob write
in order (with whether the store accepted it), the blob afterwards, and the
post-step rows of every workflow table plus `guard_events`.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import (
    store_workflow_capabilities,
    store_workflow_capability_common,
    store_workflow_capability_revocation,
)

if not hasattr(store_workflow_capability_common, "WORKFLOW_CAPABILITY_STORE_CLOCK"):
    sys.exit("refusing to record: the original Python workflow-capability implementation is gone")

import workflow_capability_scenarios
import workflow_capability_tamper_scenarios
from vector_support import schema_sql_for_tables
from workflow_capability_factories import KEY, KEY_ID, OTHER_KEY, OTHER_KEY_ID

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workflow_capabilities import WorkflowCapabilityError
from codex_plugin_scanner.guard.workflow_capability_transitions import (
    authority_transition_sha256,
    decode_signed_authority_transition,
)

WORKFLOW_TABLES = {
    "guard_workflow_capabilities": "capability_id",
    "guard_workflow_capability_authority_state": "capability_id",
    "guard_workflow_capability_revocations": "revocation_id",
    "guard_workflow_capability_receipts": "receipt_id",
    "guard_workflow_capability_authority_transitions": "sequence",
    "guard_events": "event_id",
    "schema_migrations": "version",
}
LAST = workflow_capability_scenarios.LAST
SHARED_TABLES = ("guard_events", "schema_migrations")


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
        index = len(self.writes) + 1
        accepted = self.fail_at != index
        self.writes.append({"value": encoded, "ok": accepted})
        if accepted:
            self.blob = encoded
        return accepted


class Clock:
    def __init__(self) -> None:
        self.value = ""

    def now(self) -> str:
        return self.value


class Ctx:
    def __init__(self, path: Path, blob: FakeBlobStore) -> None:
        self.path = path
        self._blob = blob
        self.marks: dict[str, str | None] = {}

    @property
    def blob(self) -> str | None:
        return self._blob.blob

    def transition_hash(self, sequence: int) -> str:
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute(
                "select signed_transition_json from guard_workflow_capability_authority_transitions where sequence = ?",
                (sequence,),
            ).fetchone()
        finally:
            connection.close()
        return authority_transition_sha256(decode_signed_authority_transition(row[0]))


class RecordingConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.statements: list[list[object]] = []

    def execute(self, statement: str, params: tuple = ()) -> None:
        self.connection.execute(statement, params)
        self.statements.append([statement, list(params)])

    def query(self, statement: str, params: tuple = ()) -> list[tuple]:
        return [tuple(row) for row in self.connection.execute(statement, params)]


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        existing = {row[0] for row in connection.execute("select name from sqlite_master where type = 'table'")}
        return {
            table: [dict(row) for row in connection.execute(f"select * from {table} order by {key}")]
            for table, key in WORKFLOW_TABLES.items()
            if table in existing
        }
    finally:
        connection.close()


def wire_for(step: dict[str, object], *, blob: str | None, receipt_id: str, revocation_id: str) -> dict[str, object]:
    wire: dict[str, object] = {"op": step["op"], "now": step["now"], "control_blob": blob}
    op = step["op"]
    if op == "issue":
        wire["signed_json"] = canonical(step["signed"].to_dict())  # type: ignore[attr-defined]
        wire["approval_provenance_id"] = step["approval_provenance_id"]
    elif op == "claim":
        for key in (
            "capability_id",
            "invocation_id",
            "expected_subject_id",
            "expected_task_id",
            "expected_issuer_id",
            "expected_approval_provenance_id",
        ):
            wire[key] = step[key]
        wire["expected_binding"] = asdict(step["expected_binding"])  # type: ignore[arg-type]
        wire["receipt_id"] = receipt_id
    elif op == "revoke":
        wire.update(capability_id=step["capability_id"], reason_code=step["reason_code"], revocation_id=revocation_id)
    elif op == "lookup":
        wire["capability_id"] = step["capability_id"]
    elif op == "receipt_lookup":
        wire.update(receipt_id=step["receipt_id"], invocation_id=step["invocation_id"])
    return wire


def invoke(store: GuardStore, step: dict[str, object]) -> object:
    op = step["op"]
    if op == "issue":
        return store.issue_workflow_capability(
            step["signed"],  # type: ignore[arg-type]
            approval_provenance_id=step["approval_provenance_id"],  # type: ignore[arg-type]
        )
    if op == "claim":
        return store.claim_workflow_capability(
            step["capability_id"],  # type: ignore[arg-type]
            invocation_id=step["invocation_id"],  # type: ignore[arg-type]
            expected_binding=step["expected_binding"],  # type: ignore[arg-type]
            expected_subject_id=step["expected_subject_id"],  # type: ignore[arg-type]
            expected_task_id=step["expected_task_id"],  # type: ignore[arg-type]
            expected_issuer_id=step["expected_issuer_id"],  # type: ignore[arg-type]
            expected_approval_provenance_id=step["expected_approval_provenance_id"],  # type: ignore[arg-type]
        )
    if op == "revoke":
        return store.revoke_workflow_capability(
            step["capability_id"],  # type: ignore[arg-type]
            reason_code=step["reason_code"],  # type: ignore[arg-type]
        )
    if op == "lookup":
        return store.lookup_workflow_capability(step["capability_id"])  # type: ignore[arg-type]
    if op == "receipt_lookup":
        return store.lookup_workflow_capability_receipt(
            receipt_id=step["receipt_id"],  # type: ignore[arg-type]
            invocation_id=step["invocation_id"],  # type: ignore[arg-type]
        )
    raise AssertionError(op)


def encode_result(op: str, result: object) -> object:
    if op in ("issue", "lookup", "receipt_lookup", "claim"):
        return None if result is None else canonical(result.to_dict())  # type: ignore[attr-defined]
    return result


def run_scenario(scenario: dict[str, object]) -> dict[str, object]:
    counter = iter(range(1, 10_000))
    peek = {"next": 1}

    def fake_uuid() -> SimpleNamespace:
        value = next(counter)
        peek["next"] = value + 1
        return SimpleNamespace(hex=f"{value:032x}")

    store_workflow_capabilities.uuid4 = fake_uuid
    store_workflow_capability_revocation.uuid4 = fake_uuid
    blob = FakeBlobStore()
    clock = Clock()
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("codex_plugin_scanner.guard.store_workflow_capabilit") and hasattr(
            module, "WORKFLOW_CAPABILITY_STORE_CLOCK"
        ):
            module.WORKFLOW_CAPABILITY_STORE_CLOCK = clock
    with tempfile.TemporaryDirectory(prefix="guard-wfcap-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        keyed: dict[str, tuple[bytes | None, str | None]] = {"material": (KEY, KEY_ID)}
        store._policy_integrity_secret_material = lambda *, create: keyed["material"]  # type: ignore[method-assign]
        last_receipt: dict[str, str] = {}
        store._load_workflow_capability_control = blob.load  # type: ignore[method-assign]
        store._store_workflow_capability_control = blob.store  # type: ignore[method-assign]
        path = Path(store.path)
        ctx = Ctx(path, blob)
        previous = dump(path)
        seed = previous
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:  # type: ignore[attr-defined]
            record: dict[str, object] = {"label": step.get("label", ""), "op": step["op"]}
            if step["op"] == "sql":
                connection = sqlite3.connect(path)
                recording = RecordingConnection(connection)
                if "fn" in step:
                    step["fn"](recording)
                else:
                    for statement, params in step["statements"]:
                        recording.execute(statement, params)
                connection.commit()
                connection.close()
                record["statements"] = recording.statements
            elif step["op"] == "blob":
                blob.blob = step["fn"](ctx)
                record["value"] = blob.blob
            else:
                fault = step.get("fault")
                blob.writes = []
                blob.fail_at = int(fault.rsplit("_", 1)[1]) if fault and fault.startswith("fail_store_") else None
                other = step.get("key") == "other"
                material: tuple[bytes | None, str | None] = (OTHER_KEY, OTHER_KEY_ID) if other else (KEY, KEY_ID)
                keyed["material"] = (None, None) if fault == "no_key" else material
                if step.get("receipt_id") == LAST:
                    step = {**step, "receipt_id": last_receipt["id"]}
                clock.value = step["now"]
                record["fault"] = fault
                record["wire"] = wire_for(
                    step,
                    blob=blob.blob,
                    receipt_id=f"wcr-{peek['next']:032x}",
                    revocation_id=f"wcv-{peek['next']:032x}",
                )
                key, key_id = keyed["material"]
                record["wire"]["key_b64"] = None if key is None else base64.b64encode(key).decode("ascii")  # type: ignore[index]
                record["wire"]["key_id"] = key_id  # type: ignore[index]
                try:
                    result = invoke(store, step)
                    record.update(result=encode_result(step["op"], result), error=None)
                except WorkflowCapabilityError as error:
                    record.update(result=None, error={"kind": "capability", "code": str(error)})
                except RuntimeError as error:
                    record.update(result=None, error={"kind": "runtime", "message": str(error)})
                record["blob_writes"] = blob.writes
                record["blob_after"] = blob.blob
                if step["op"] == "claim" and record["result"] is not None:
                    last_receipt["id"] = json.loads(record["result"])["receipt"]["receipt_id"]  # type: ignore[arg-type]
            if "mark" in step:
                ctx.marks[step["mark"]] = blob.blob
            current = dump(path)
            record["post_changed"] = {t: rows for t, rows in current.items() if rows != previous.get(t)}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-wfcap-schema-") as root:
        base = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        schema = schema_sql_for_tables(Path(base.path), SHARED_TABLES)
    scenarios = [*workflow_capability_scenarios.SCENARIOS, *workflow_capability_tamper_scenarios.SCENARIOS]
    document = {
        "schema": "guard-store-workflow-capability-vectors.v1",
        "source": "guard",
        "shared_schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in scenarios],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
