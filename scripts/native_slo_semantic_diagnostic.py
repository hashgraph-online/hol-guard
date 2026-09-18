"""Bounded verdict diagnostics for a failed synthetic qualification case.

Never copy reasons, response text or arbitrary values out of the private run.
Only closed verdict vocabularies and reason codes frozen in the corpus may be
exported; a digest records every other value without disclosing its content.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from scripts.native_slo_workloads import QualificationCase

_ACTIONS = frozenset({"allow", "deny", "block", "review", "ask", "warn", "allow_original", "replace"})
_FIELDS = ("decision", "minimum_action", "policy_action", "model_output_action", "reason_code", "error")


def semantic_diagnostic(
    response: Mapping[str, object], native: object, cases: Sequence[QualificationCase]
) -> dict[str, object]:
    allowed_codes = {
        value
        for case in cases
        for expected in (case.expected, case.native_expected)
        if expected is not None
        for key, value in expected.fields.items()
        if key in {"reason_code", "error"} and isinstance(value, str)
    }
    result: dict[str, object] = {}
    for label, source in (("delivered", response), ("native", native)):
        if not isinstance(source, Mapping):
            result[label] = {"available": False}
            continue
        observed: dict[str, object] = {"available": True}
        for key in _FIELDS:
            if key not in source:
                continue
            value = source[key]
            allowed = allowed_codes if key in {"reason_code", "error"} else _ACTIONS
            if isinstance(value, str) and value in allowed:
                observed[key] = value
                if key in {"reason_code", "error"}:
                    # Some frozen codes contain sensitive vocabulary and the
                    # generic export sanitizer redacts their string. Retain an
                    # exact identifier without exposing arbitrary error text.
                    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
                    observed[key + "_digest"] = hashlib.sha256(encoded).hexdigest()
            else:
                encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
                observed[key + "_digest"] = hashlib.sha256(encoded).hexdigest()
        result[label] = observed
    return result
