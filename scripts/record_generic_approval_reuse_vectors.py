"""Record generic-hook approval-reuse vectors from the Python owner before it retires.

Run with ``PYTHONPATH`` pointing at a source tree that still composes the
generic hook's approval-reuse verdict in Python. Each vector freezes the saved
``{decision, ignored_local_integrity}``, the current action and token, the
miss diagnosis the store answered, and what the composition then handed to the
reuse verdict: its arguments, the saved-evidence flag and the stored hash used
for provenance. No resident runs: the token check and the miss diagnosis are
answered from the vector, and the verdict itself is the shared Rust evaluator.
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.cli import commands_hook_native_generic

ACTIONS = ["allow", "warn", "review", "ask", "require-reapproval", "sandbox-required", "block", "frobnicate", None]
CURRENT = ["allow", "warn", "review", "ask", "require-reapproval", "sandbox-required", "block"]
REASONS = [
    "approval_reuse_content_changed",
    "approval_reuse_integrity_failure",
    "approval_reuse_expired",
    "approval_reuse_scope_mismatch",
]
# Saved hashes are never context tokens here, so the token check fails closed
# as changed content without a resident.
TOKEN_REASON = "approval_reuse_content_changed"
FLAGS = [True, False, "true", 1, None, "absent"]


class _Store:
    def __init__(self, diagnosis: tuple[str | None, str | None]) -> None:
        self.diagnosis = diagnosis
        self.diagnosed = False

    def approval_reuse_diagnostic(self, *_args: Any) -> tuple[str | None, str | None]:
        self.diagnosed = True
        return self.diagnosis


def _decision(rng: random.Random, index: int) -> dict[str, Any] | None:
    if rng.random() < 0.35:
        return None
    decision: dict[str, Any] = {"action": rng.choice(ACTIONS), "scope": "workspace"}
    saved_hash = rng.choice(["absent", None, f"hash-{index}", f"runtime-exact:{index}", ""])
    if saved_hash != "absent":
        decision["artifact_hash"] = saved_hash
    for key in ("fresh_local_approval", "durable_exact_approval"):
        flag = rng.choice(FLAGS)
        if flag != "absent":
            decision[key] = flag
    return decision


def _vector(rng: random.Random, index: int) -> dict[str, Any]:
    decision = _decision(rng, index)
    ignored = {"reason": f"integrity-{index}"} if rng.random() < 0.25 else None
    current_action = rng.choice(CURRENT)
    current_token = f"current-{index}"
    store = _Store(
        (
            rng.choice([None, None, *REASONS]),
            rng.choice([None, f"stored-{index}", f"runtime-exact:stored-{index}"]),
        )
    )
    captured: dict[str, Any] = {}
    verdict = object()

    def evaluate(current: object, saved: object = None, **kwargs: Any) -> object:
        captured["evaluate"] = {
            "current_action": current,
            "saved_action": saved,
            "saved_decision_present": kwargs["saved_decision_present"],
            "validation_reason": kwargs["validation_reason"],
            "fresh_local_approval": kwargs["fresh_local_approval"],
            "durable_exact_approval": kwargs["durable_exact_approval"],
        }
        return verdict

    def provenance(reuse: object, stored_hash: object) -> object:
        assert reuse is verdict
        captured["saved_artifact_hash"] = stored_hash
        return reuse

    def validate(saved: object, current: object) -> str:
        assert current == current_token
        assert not (isinstance(saved, str) and saved.startswith("guard-approval-context:"))
        return TOKEN_REASON

    commands_hook_native_generic.evaluate_approval_reuse = evaluate  # type: ignore[assignment]
    commands_hook_native_generic.with_saved_artifact_hash_provenance = provenance  # type: ignore[assignment]
    commands_hook_native_generic.approval_context_tokens_validation_reason = validate  # type: ignore[assignment]
    compose = getattr(commands_hook_native_generic, "_generic_hook_approval_reuse")  # noqa: B009
    _reuse, saved_present = compose(
        artifact_hash=current_token,
        artifact_id=f"claude-code:tool:Bash:{index}",
        current_action=current_action,  # type: ignore[arg-type]
        decision=decision,
        harness="claude-code",
        ignored_integrity=ignored,
        publisher=None,
        runtime_workspace=Path("/work/repo"),
        store=store,  # type: ignore[arg-type]
    )
    return {
        "name": f"reuse-{index}",
        "saved": {"decision": decision, "ignored_local_integrity": ignored},
        "current_action": current_action,
        "current_token": current_token,
        "diagnosis": list(store.diagnosis),
        "expected": {
            "diagnosed": store.diagnosed,
            "evaluate": captured["evaluate"],
            "saved_present": saved_present,
            "saved_artifact_hash": captured["saved_artifact_hash"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=400)
    args = parser.parse_args()
    rng = random.Random(4364)
    vectors = [_vector(rng, index) for index in range(args.count)]
    document = {"schema": "guard-generic-approval-reuse-vectors.v1", "vectors": vectors}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(payload, mtime=0))


if __name__ == "__main__":
    main()
