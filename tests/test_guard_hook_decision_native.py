"""Hook decisions are answered by the native runtime.

The language-neutral vectors under ``rust/crates/guard-runtime/tests/fixtures``
are the contract; the Rust suite runs them against the op directly and this
suite runs them through the real resident and the Python transport.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures/hook_decision_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


def _subset(expected: object, actual: object, path: str = "payload") -> list[str]:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected object"]
        problems: list[str] = []
        for key, value in expected.items():
            if key not in actual:
                problems.append(f"{path}.{key}: missing")
            else:
                problems.extend(_subset(value, actual[key], f"{path}.{key}"))
        return problems
    return [] if expected == actual else [f"{path}: expected {expected!r}, got {actual!r}"]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_matches_language_neutral_vectors() -> None:
    failures: list[str] = []
    for vector in _VECTORS:
        try:
            payload = decision._decide(vector["query"], None, lambda _payload: None)
        except decision.NativeHookDecisionError as error:
            # A resident-side rejection never yields a decision; the transport
            # reports it as a failure (the exact code is asserted in Rust).
            if "error" not in vector:
                failures.append(f"{vector['name']}: unexpected {error.code}")
            continue
        if "error" in vector:
            failures.append(f"{vector['name']}: expected error {vector['error']}")
            continue
        failures.extend(f"{vector['name']}: {problem}" for problem in _subset(vector["expect"], payload))
    assert failures == []
