#!/usr/bin/env python3
"""Record startup generation vectors from the ORIGINAL Python state machine.

The Python decision code has since been removed; the resident's
``policy_integrity_rows`` op answers the ``generation`` section instead.
Re-recording needs a checkout from before that removal (the commit that added
this file), never Rust output:

    PYTHONPATH=$PWD/src:$PWD/tests python3 <this-file> <output vectors.json>

Each case plants local policy rows in an in-memory store and runs the original
``_prepared_startup_policy_integrity_state`` and
``_prefetched_startup_state_still_matches_local_rows`` against them. Only the
per-row verification is supplied here, through the frozen v1/v2 envelope in
``tests/policy_integrity_fixture.py``; the Rust test verifies the same rows
with the resident's own verifier, so a mismatch in either fails the test.

The key is synthetic: bytes 0..31. Only its id is written to the vectors.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import sqlite3
import sys
from pathlib import Path

from policy_integrity_fixture import canonical_policy_payload

from codex_plugin_scanner.guard.policy_integrity import PolicyIntegrityVerificationResult
from codex_plugin_scanner.guard.store_policy_integrity_runtime import StorePolicyIntegrityAdminMixin
from codex_plugin_scanner.guard.store_secret_policy_integrity import StoreSecretPolicyIntegrityMixin

KEY = bytes(range(32))
KEY_ID = "guard-policy-integrity-key:00000000feedface:1f2e3d4c5b6a7988"
OTHER_KEY_ID = "guard-policy-integrity-key:00000000feedface:0000000000000000"
COLUMNS = (
    "decision_id",
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "action",
    "reason",
    "owner",
    "source",
    "expires_at",
    "updated_at",
    "integrity_version",
    "integrity_generation",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
)
INTEGRITY_COLUMNS = (
    "integrity_version",
    "integrity_generation",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
)


def _text(row, name):
    value = row.get(name)
    return value if isinstance(value, str) and value else None


def _int(row, name):
    value = row.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _verify(row, trusted_generation):
    """The resident verifier's statuses, from the frozen envelope."""

    version = _int(row, "integrity_version")
    stored = {name: _text(row, name) for name in ("payload_hash", "payload_mac", "integrity_key_id", "signed_at")}
    if version is None or any(value is None for value in stored.values()):
        return "missing_integrity"
    if version not in (1, 2):
        return "tampered"
    if stored["integrity_key_id"] != KEY_ID:
        return "unknown_key"
    payload = canonical_policy_payload(row, integrity_version=version)
    if stored["payload_hash"] != hashlib.sha256(payload).hexdigest():
        return "tampered"
    if stored["payload_mac"] != hmac.new(KEY, payload, hashlib.sha256).hexdigest():
        return "tampered"
    if version == 2 and trusted_generation is not None and _int(row, "integrity_generation") != trusted_generation:
        return "rollback_detected"
    return "valid"


class _Store(StoreSecretPolicyIntegrityMixin, StorePolicyIntegrityAdminMixin):
    def _verify_policy_rows(self, items, *, key, key_id):
        assert key == KEY and key_id == KEY_ID
        return [
            PolicyIntegrityVerificationResult(status=_verify(dict(item.row), item.trusted_generation)) for item in items
        ]


def _row(decision_id, *, source="local", reason="approved"):
    return {
        "decision_id": decision_id,
        "harness": "codex",
        "scope": "artifact",
        "artifact_id": f"codex:project:tool-{decision_id}",
        "artifact_hash": f"sha256:{decision_id:064x}",
        "workspace": None,
        "publisher": None,
        "action": "allow",
        "reason": reason,
        "owner": "local-user",
        "source": source,
        "expires_at": None,
        "updated_at": f"2026-10-15T12:00:{decision_id:02d}Z",
        **dict.fromkeys(INTEGRITY_COLUMNS),
    }


def v2(decision_id, generation, **kwargs):
    row = _row(decision_id, **kwargs)
    row["integrity_version"] = 2
    row["integrity_generation"] = generation
    payload = canonical_policy_payload(row, integrity_version=2)
    row["payload_hash"] = hashlib.sha256(payload).hexdigest()
    row["payload_mac"] = hmac.new(KEY, payload, hashlib.sha256).hexdigest()
    row["integrity_key_id"] = KEY_ID
    row["signed_at"] = "2026-10-15T12:00:00Z"
    return row


def v1(decision_id):
    row = _row(decision_id)
    row["integrity_version"] = 1
    payload = canonical_policy_payload(row, integrity_version=1)
    row["payload_hash"] = hashlib.sha256(payload).hexdigest()
    row["payload_mac"] = hmac.new(KEY, payload, hashlib.sha256).hexdigest()
    row["integrity_key_id"] = KEY_ID
    row["signed_at"] = "2026-10-15T12:00:00Z"
    return row


def unsigned(decision_id):
    return _row(decision_id)


def tampered(row):
    changed = copy.deepcopy(row)
    changed["reason"] = "changed after signing"
    return changed


def with_fields(row, **fields):
    changed = copy.deepcopy(row)
    changed.update(fields)
    return changed


def state(generation, pending=None, cutover=False):
    return {"cutover_complete": cutover, "generation": generation, "pending_generation": pending, "version": 1}


CASES = [
    ("steady_current", [v2(1, 3), v2(2, 3)], state(3)),
    ("steady_current_cutover_done", [v2(1, 3)], state(3, cutover=True)),
    ("newer_single_generation", [v2(1, 5), v2(2, 5)], state(3)),
    ("newer_two_generations", [v2(1, 4), v2(2, 5)], state(3)),
    ("older_generation", [v2(1, 2)], state(3)),
    ("current_and_newer", [v2(1, 3), v2(2, 5)], state(3)),
    ("newer_tampered", [tampered(v2(1, 5))], state(3)),
    ("newer_other_key", [with_fields(v2(1, 5), integrity_key_id=OTHER_KEY_ID)], state(3)),
    ("newer_null_generation", [with_fields(v2(1, 5), integrity_generation=None)], state(3)),
    ("legacy_unsigned_no_pending", [unsigned(1), v2(2, 3)], state(3)),
    ("legacy_v1_no_pending", [v1(1), v2(2, 5)], state(3)),
    ("v2_missing_signed_at", [v2(1, 3), with_fields(v2(2, 3), signed_at=None)], state(3)),
    ("pending_all_at_pending", [v2(1, 4), v2(2, 4)], state(3, pending=4)),
    ("pending_all_at_current", [v2(1, 3), v2(2, 3)], state(3, pending=4)),
    ("pending_mixed", [v2(1, 3), v2(2, 4)], state(3, pending=4)),
    ("pending_tampered", [v2(1, 4), tampered(v2(2, 4))], state(3, pending=4)),
    ("pending_legacy_unsigned", [unsigned(1), v2(2, 3)], state(3, pending=4)),
    ("pending_legacy_v1_current_valid", [v1(1), v2(2, 3)], state(3, pending=4)),
    ("pending_legacy_v1_only", [v1(1)], state(3, pending=4)),
    ("pending_legacy_v1_pending_signed", [v1(1), v2(2, 4)], state(3, pending=4)),
    ("pending_cutover_done", [v2(1, 4)], state(3, pending=4, cutover=True)),
    (
        "remote_rows_ignored",
        [v2(1, 3), tampered(v2(2, 9, source="cloud-sync")), unsigned(3) | {"source": "team-policy"}],
        state(3),
    ),
    ("null_source_ignored", [v2(1, 3), unsigned(2) | {"source": None}], state(3)),
    ("real_integrity_version", [with_fields(v2(1, 3), integrity_version=2.0)], state(3)),
    ("no_local_rows", [], state(3)),
    ("no_local_rows_pending", [], state(3, pending=4)),
    ("only_remote_rows_pending", [unsigned(1) | {"source": "policy-bundle"}], state(3, pending=4)),
]


def _connection(rows):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(f"create table policy_decisions ({', '.join(COLUMNS)})")
    for row in rows:
        connection.execute(
            f"insert into policy_decisions ({', '.join(COLUMNS)}) values ({', '.join('?' for _ in COLUMNS)})",
            tuple(row[name] for name in COLUMNS),
        )
    return connection


def main(output: Path) -> None:
    store = _Store.__new__(_Store)
    cases = []
    for name, rows, trusted in CASES:
        connection = _connection(rows)
        prepared = store._prepared_startup_policy_integrity_state(
            connection, key=KEY, key_id=KEY_ID, trusted_state=copy.deepcopy(trusted)
        )
        still_matches = store._prefetched_startup_state_still_matches_local_rows(
            connection, key=KEY, key_id=KEY_ID, trusted_state=copy.deepcopy(trusted)
        )
        cases.append(
            {
                "name": name,
                "rows": rows,
                "trusted_state": trusted,
                "expected": {"prepared_state": prepared, "still_matches": still_matches},
            }
        )
    document = {
        "integrity_key_id": KEY_ID,
        "cases": cases,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
