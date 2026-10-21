"""Record runtime-hook saved-reuse inputs from the Python owner before it retires.

Run with ``PYTHONPATH`` pointing at a source tree whose
``evaluate_native_artifact_hook`` still builds the ``saved_reuse`` fields in
Python (``commands_hook_native_eval.py``, the non-package branch). The block
below is that branch transcribed verbatim; the stored-allow check runs the real
``_runtime_saved_allow_validation_reason`` and ``_optional_string`` source,
loaded without importing the CLI (which needs the generated command catalog).
No resident runs: the
token check answers from a deterministic fake whose calls each vector records,
and the miss diagnosis answers from the vector.

Each vector freezes the runtime lookup (``{lookup, decision}``), the current
action and token, the Cursor native allowance token, the store's miss
diagnosis, every token check and its answer, whether the diagnosis ran, and the
exact ``saved_fields`` Python handed to ``native_hook_compose("saved_reuse")``.
"""

from __future__ import annotations

import argparse
import ast
import itertools
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard import cli as _cli_package

_CLI = Path(_cli_package.__file__).parent


def _owner_function(module: str, name: str, namespace: dict[str, Any]) -> Any:
    """Execute one function's source from the owner module into ``namespace``."""

    path = _CLI / f"{module}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    (node,) = [item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name]
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]


_OWNER: dict[str, Any] = {"Mapping": Mapping}
_optional_string = _owner_function("commands_support_runtime_artifacts", "_optional_string", _OWNER)
_runtime_saved_allow_validation_reason = _owner_function(
    "commands_support_runtime_policy", "_runtime_saved_allow_validation_reason", _OWNER
)

CURRENT_TOKEN = "token-current"
CURRENT_ACTIONS = ["allow", "review", "require-reapproval", "block"]
DECISIONS: list[dict[str, Any] | None] = [
    None,
    {"action": "allow", "scope": "artifact", "artifact_hash": CURRENT_TOKEN},
    {"action": "allow", "scope": "workspace", "artifact_hash": "token-policy-changed"},
    {"action": " allow ", "scope": "artifact", "artifact_hash": f"  {CURRENT_TOKEN} "},
    {"action": "allow", "scope": "artifact", "artifact_hash": "runtime-exact:abc"},
    {"action": "allow", "scope": "artifact", "artifact_hash": None},
    {"action": "allow", "scope": "artifact"},
    {"action": "block", "scope": "artifact", "artifact_hash": "legacy-hash"},
    {"action": "review", "scope": "harness", "artifact_hash": CURRENT_TOKEN},
    {"action": "warn", "scope": "artifact", "artifact_hash": "token-stale"},
]
IGNORED = [None, {"reason": "approval_reuse_integrity_failure", "artifact_id": "codex:x"}]
CURSOR = [None, CURRENT_TOKEN, "token-stale"]
DIAGNOSES: list[tuple[str | None, str | None]] = [
    (None, None),
    ("approval_reuse_content_changed", "token-stored"),
    (None, "legacy-stored"),
    ("approval_reuse_integrity_failure", None),
]


def _fake_validation(saved: object, current: object) -> str | None:
    """Deterministic stand-in for the resident token comparison."""

    if not isinstance(saved, str) or not isinstance(current, str):
        return "approval_reuse_content_changed"
    if saved == current:
        return None
    if saved.startswith("token-policy"):
        return "approval_reuse_policy_changed"
    return "approval_reuse_content_changed"


class _Store:
    def __init__(self, diagnosis: tuple[str | None, str | None]) -> None:
        self.diagnosis = diagnosis
        self.diagnosed = False

    def approval_reuse_diagnostic(self, *_args: object) -> tuple[str | None, str | None]:
        self.diagnosed = True
        return self.diagnosis


def _old_saved_fields(
    *,
    store: _Store,
    validate: Any,
    current_policy_action: str,
    policy_lookup: Mapping[str, object],
    stored_policy_decision: Mapping[str, object] | None,
    cursor_native_approval_hash: str | None,
    runtime_artifact: Any,
    runtime_artifact_hash: str,
) -> dict[str, object]:
    # Transcribed from the pre-port non-package branch.
    approval_context_tokens_validation_reason = validate
    stored_policy_action = (
        _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
    )
    stored_validation_reason = (
        _runtime_saved_allow_validation_reason(
            stored_policy_decision,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
        )
        if stored_policy_decision is not None and policy_lookup.get("ignored_local_integrity") is None
        else None
    )
    cursor_validation_reason = (
        approval_context_tokens_validation_reason(cursor_native_approval_hash, runtime_artifact_hash)
        if cursor_native_approval_hash is not None
        else None
    )
    diagnostic_reason: str | None = None
    diagnostic_stored_hash: object | None = None
    if (
        stored_policy_decision is None
        and cursor_native_approval_hash is None
        and policy_lookup.get("ignored_local_integrity") is None
    ):
        diagnostic_reason, diagnostic_stored_hash = store.approval_reuse_diagnostic(
            "codex",
            runtime_artifact.artifact_id,
            runtime_artifact_hash,
            "/workspace",
            runtime_artifact.publisher,
            "2026-10-15T00:00:00Z",
        )
    return {
        "current_action": current_policy_action,
        "stored_present": stored_policy_decision is not None,
        "stored_action": stored_policy_action,
        "stored_artifact_hash": (
            stored_policy_decision.get("artifact_hash") if stored_policy_decision is not None else None
        ),
        "integrity_failure": policy_lookup.get("ignored_local_integrity") is not None,
        "stored_validation_reason": stored_validation_reason,
        "cursor_native_present": cursor_native_approval_hash is not None,
        "cursor_validation_reason": cursor_validation_reason,
        "diagnostic_reason": diagnostic_reason,
        "diagnostic_stored_hash": diagnostic_stored_hash,
    }


def _cases() -> list[tuple[str, Any, Any, Any, Any]]:
    cases = []
    for index, (decision, ignored, cursor) in enumerate(itertools.product(DECISIONS, IGNORED, CURSOR)):
        current_action = CURRENT_ACTIONS[index % len(CURRENT_ACTIONS)]
        diagnosis = DIAGNOSES[index % len(DIAGNOSES)]
        cases.append((current_action, decision, ignored, cursor, diagnosis))
    # Every diagnosis on the plain miss, where it is consulted.
    for current_action, diagnosis in itertools.product(CURRENT_ACTIONS, DIAGNOSES):
        cases.append((current_action, None, None, None, diagnosis))
    return cases


def _vector(index: int, case: tuple[str, Any, Any, Any, Any]) -> dict[str, Any]:
    current_action, decision, ignored, cursor, diagnosis = case
    calls: list[list[object]] = []

    def validate(saved: object, current: object) -> str | None:
        reason = _fake_validation(saved, current)
        calls.append([saved, current, reason])
        return reason

    store = _Store(diagnosis)
    lookup = {"decision": decision, "ignored_local_integrity": ignored, "trust_status": {"trusted": True}}
    artifact = SimpleNamespace(artifact_id="codex:project:tool-action:npm-test", publisher=None)
    _OWNER["approval_context_tokens_validation_reason"] = validate
    expected = _old_saved_fields(
        store=store,
        validate=validate,
        current_policy_action=current_action,
        policy_lookup=lookup,
        stored_policy_decision=decision,
        cursor_native_approval_hash=cursor,
        runtime_artifact=artifact,
        runtime_artifact_hash=CURRENT_TOKEN,
    )
    reuse: dict[str, object] = {"current_action": current_action}
    if cursor is not None:
        reuse["cursor_native_token"] = cursor
    return {
        "name": f"case-{index:03d}",
        "reuse": reuse,
        "current_hash": CURRENT_TOKEN,
        "composed": {"lookup": lookup, "decision": decision},
        "diagnosis": list(diagnosis),
        "validations": calls,
        "diagnosed": store.diagnosed,
        "expected": expected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("vectors.json"))
    args = parser.parse_args()
    vectors = [_vector(index, case) for index, case in enumerate(_cases())]
    document = {"schema": "guard-runtime-saved-reuse-vectors.v1", "vectors": vectors}
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
