"""Exact-build compatibility for stopped artifact receipt preservation.

The audited baseline writes complete receipts but has no public getter. Its
readback validates current receipts with that installed build's validator.
After a candidate schema migration, prior candidate bindings are compared as
complete previously validated objects; baseline program interpretation is not
claimed. Candidate getter errors and missing fields never use this path.
"""

from __future__ import annotations

import json
import re
from typing import Any

from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt

AUDITED_BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
_BASELINE_FIELDS = frozenset(
    {
        "decision_id",
        "schema",
        "version",
        "authority",
        "request_id",
        "request_digest",
        "harness",
        "event_name",
        "payload_kind",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "decision",
        "model_output_action",
        "policy_action",
        "observed_policy_action",
        "reason_code",
        "workspace_bound",
        "source_ref_external_allowed",
        "reviewed_output_sha256",
        "observe_mode",
        "deadline_budget_ms",
    }
)
_BASELINE_COLUMNS = _BASELINE_FIELDS | {"recorded_at"}
_MIGRATED_COLUMNS = _BASELINE_COLUMNS | {"command_extensions_json"}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate binding field")
        result[key] = value
    return result


def same_receipt(left: object, right: dict) -> bool:
    """Compare every field and JSON scalar type, not Python's bool/int equality."""
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
            right, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError):
        return False


class TransitionReceiptReader:
    def __init__(self, store: Any, *, build_sha: str) -> None:
        self.store = store
        self.getter = getattr(store, "get_native_decision_receipt", None)
        self.legacy = not callable(self.getter)
        if not self.legacy:
            return
        if build_sha != AUDITED_BASELINE_SHA:
            raise RuntimeError("qualification_transition_candidate_receipt_getter_missing")
        with store._connect() as connection:
            rows = connection.execute("pragma table_info(native_hook_decision_receipts)").fetchmany(65)
        columns = {row["name"] for row in rows}
        if len(rows) >= 65 or columns not in (_BASELINE_COLUMNS, _MIGRATED_COLUMNS):
            raise RuntimeError("qualification_transition_baseline_receipt_schema_changed")

    def _legacy_read(self, identity: str) -> dict | None:
        if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            return None
        with self.store._connect() as connection:
            row = connection.execute(
                "select * from native_hook_decision_receipts where decision_id = ?", (identity,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        # Recheck each row so schema drift during a phase cannot drop a field.
        if set(result) not in (_BASELINE_COLUMNS, _MIGRATED_COLUMNS):
            return None
        result.pop("recorded_at")
        binding = result.pop("command_extensions_json", None)
        if binding is not None:
            if not isinstance(binding, str) or not 2 <= len(binding) <= 2048:
                return None
            try:
                result["command_extensions"] = json.loads(binding, object_pairs_hook=_unique_object)
            except (ValueError, RecursionError):
                return None
        for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
            if type(result[field]) is not int or result[field] not in (0, 1):
                return None
            result[field] = bool(result[field])
        return result

    def read_current(self, identity: str) -> dict | None:
        if self.legacy:
            receipt = self._legacy_read(identity)
            # An old build must never validate a binding by discarding it.
            if receipt is None or set(receipt) != _BASELINE_FIELDS:
                return None
        else:
            receipt = self.getter(identity)
        return validate_native_decision_receipt(receipt)

    def preserves_prior(self, expected: dict) -> bool:
        if self.legacy:
            # ``expected`` was captured and validated under the prior installed
            # artifact. Equality preserves every supported field, including a
            # candidate binding the baseline cannot semantically interpret.
            return same_receipt(self._legacy_read(expected["decision_id"]), expected)
        return same_receipt(self.read_current(expected["decision_id"]), expected)
