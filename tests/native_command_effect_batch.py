"""Batched ``command_effect_decide_batch`` client for offline command corpora.

Hooks never batch; only the corpus tests and the installed-corpus script do,
so this client lives with them. Every item keeps its own request id and
request hash and is judged by the resident's single-op rules; the client only
binds the batch to its answers. Resident calls go through the
``native_command_effect`` module attributes so tests can forge or observe them.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard import native_command_effect as effect
from codex_plugin_scanner.guard.native_command_effect import (
    CommandEffectItem,
    NativeCommandEffectMalformedError,
    NativeCommandEffectRejectedError,
)
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_runtime import _isolated_environment, _native_error
from codex_plugin_scanner.guard.native_runtime_values import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime import command_evaluation
from codex_plugin_scanner.guard.runtime.command_evaluation import (
    CommandEvaluationInput,
    CompositeCommandEvaluation,
    NativeCommandExtensionEvidenceError,
)

COMMAND_EFFECT_BATCH_FEATURE = "command-effect-batch-v1"
COMMAND_EFFECT_BATCH_MAX_ITEMS = 64
COMMAND_EFFECT_BATCH_MAX_BYTES = 4 * 1024 * 1024
_MAX_REQUEST_BYTES = 1024 * 1024
_BATCH_REQUEST_SCHEMA = "guard-command-effect-batch-request.v1"
_BATCH_RESULT_SCHEMA = "guard-command-effect-batch-result.v1"
_RESULT_SCHEMA = "guard-command-effect-result.v1"
_UNAVAILABLE = "native_command_effect_unavailable"
# A batch the resident refuses only for size is re-sent as two halves, never
# relaxed: the same bounds apply to every half.
_BATCH_SPLITTABLE_CODES = frozenset(
    {
        "native_command_effect_batch_too_large",
        "native_command_effect_batch_response_too_large",
        "native_command_effect_batch_too_many_items",
    }
)

_batch_counter = 0

_Outcome = dict[str, object] | NativeCommandEffectRejectedError


def command_effect_decide_batch_native(
    items: Sequence[CommandEffectItem],
    *,
    guard_home: Path,
    timeout_seconds: float = 30.0,
    deadline_monotonic: float | None = None,
) -> list[_Outcome] | None:
    """Evaluate many commands in few resident round trips.

    One result per item, in order: the evaluation payload, or the bound
    ``NativeCommandEffectRejectedError`` the resident gave that item. ``None``
    means the resident could not service the call and nothing was decided.
    A result that is not bound to its request (schema, id, hash, count or
    order) raises ``NativeCommandEffectMalformedError``.
    """
    ready = effect._resident_ready(guard_home, COMMAND_EFFECT_BATCH_FEATURE, timeout_seconds, deadline_monotonic)
    if ready is None:
        return None
    identity, effective_deadline = ready
    requests = [
        effect._build_request(
            command_text=item.command_text,
            canonical_command=item.canonical_command,
            native_extension_evidence=item.native_extension_evidence,
            control_snapshot=item.control_snapshot,
            compatibility_action_class=item.compatibility_action_class,
            compatibility_reason=item.compatibility_reason,
            workflow_authorization=item.workflow_authorization,
            cwd=item.cwd,
            home_dir=item.home_dir,
        )
        for item in items
    ]
    try:
        hashes = ["sha256:" + _canonical_request_sha256(request) for request in requests]
    except (TypeError, ValueError) as exc:
        raise NativeCommandEffectMalformedError("command_effect request is not JSON data") from exc
    results: list[_Outcome] = []
    for start in range(0, len(requests), COMMAND_EFFECT_BATCH_MAX_ITEMS):
        chunk = _batch_chunk(
            identity,
            guard_home,
            requests[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS],
            hashes[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS],
            effective_deadline,
        )
        if chunk is None:
            return None
        results.extend(chunk)
    return results


def _batch_chunk(
    identity: NativeRuntimeIdentity,
    guard_home: Path,
    requests: list[dict[str, object]],
    hashes: list[str],
    deadline: float,
) -> list[_Outcome] | None:
    global _batch_counter
    remaining_seconds = deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    batch_id = f"ceb-{_batch_counter}"
    _batch_counter += 1
    try:
        resident = json.dumps(
            {
                "operation": "command_effect_decide_batch",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": {"schema": _BATCH_REQUEST_SCHEMA, "request_id": batch_id, "items": requests},
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeCommandEffectMalformedError("command_effect request is not JSON data") from exc
    if len(resident) > COMMAND_EFFECT_BATCH_MAX_BYTES + _MAX_REQUEST_BYTES // 8:
        return _split_batch(identity, guard_home, requests, hashes, deadline, "native_command_effect_batch_too_large")
    output = effect.native_resident_client_request(
        executable=identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=deadline,
    )
    del resident
    if output is None:
        effect.native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_unavailable")
        return None
    try:
        # Transfer bytes to text before parsing, so the request, response bytes
        # and parsed response do not remain live together for a large batch.
        text = output.decode(json.detect_encoding(output), "surrogatepass")
        del output
        envelope = json.loads(text)
        del text
    except (UnicodeDecodeError, json.JSONDecodeError):
        effect.native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_decode_failed")
        raise NativeCommandEffectMalformedError("command_effect batch result is not valid JSON") from None
    if _native_error(envelope) == "native_overloaded":
        effect.native_record_overload(identity.sha256, guard_home)
        return None
    if isinstance(envelope, dict) and isinstance(envelope.get("error"), str) and "schema" not in envelope:
        effect.native_record_resident_failure(
            identity.sha256, guard_home, reason="native_command_effect_resident_error"
        )
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _BATCH_RESULT_SCHEMA
        or envelope.get("request_id") != batch_id
    ):
        effect.native_record_resident_failure(
            identity.sha256, guard_home, reason="native_command_effect_schema_mismatch"
        )
        raise NativeCommandEffectMalformedError("command_effect batch result does not match the request")
    code = envelope.get("code")
    if envelope.get("status") == "error":
        effect.native_record_resident_success(identity.sha256, guard_home)
        refusal = code if isinstance(code, str) else "native_command_effect_rejected"
        if refusal in _BATCH_SPLITTABLE_CODES and len(requests) > 1:
            return _split_batch(identity, guard_home, requests, hashes, deadline, refusal)
        raise NativeCommandEffectRejectedError(refusal)
    answers = envelope.get("items")
    if envelope.get("status") != "ok" or code != "ok" or not isinstance(answers, list) or len(answers) != len(requests):
        effect.native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_bad_status")
        raise NativeCommandEffectMalformedError("command_effect batch result has the wrong item count")
    outcomes: list[_Outcome] = []
    for request, expected_hash, answer in zip(requests, hashes, answers, strict=True):
        if (
            not isinstance(answer, dict)
            or answer.get("schema") != _RESULT_SCHEMA
            or answer.get("request_id") != request["request_id"]
            or answer.get("request_sha256") != expected_hash
        ):
            effect.native_record_resident_failure(
                identity.sha256, guard_home, reason="native_command_effect_schema_mismatch"
            )
            raise NativeCommandEffectMalformedError("command_effect batch item does not match its request")
        item_code = answer.get("code")
        if answer.get("status") == "error":
            outcomes.append(
                NativeCommandEffectRejectedError(
                    item_code if isinstance(item_code, str) else "native_command_effect_rejected"
                )
            )
            continue
        payload = answer.get("payload")
        if answer.get("status") != "ok" or item_code != "ok" or not isinstance(payload, dict):
            effect.native_record_resident_failure(
                identity.sha256, guard_home, reason="native_command_effect_bad_status"
            )
            raise NativeCommandEffectMalformedError("command_effect batch item has no evaluation payload")
        outcomes.append(payload)
    effect.native_record_resident_success(identity.sha256, guard_home)
    return outcomes


def _split_batch(
    identity: NativeRuntimeIdentity,
    guard_home: Path,
    requests: list[dict[str, object]],
    hashes: list[str],
    deadline: float,
    refusal: str,
) -> list[_Outcome] | None:
    if len(requests) <= 1:
        raise NativeCommandEffectRejectedError(refusal)
    middle = len(requests) // 2
    outcomes: list[_Outcome] = []
    for part_requests, part_hashes in ((requests[:middle], hashes[:middle]), (requests[middle:], hashes[middle:])):
        part = _batch_chunk(identity, guard_home, part_requests, part_hashes, deadline)
        if part is None:
            return None
        outcomes.extend(part)
    return outcomes


def evaluate_commands_batch(
    entries: Sequence[CommandEvaluationInput],
    *,
    guard_home: Path | None = None,
) -> tuple[CompositeCommandEvaluation, ...]:
    """Evaluate many commands in few resident round trips.

    Each command is judged by the single-op rules and projected exactly as
    ``evaluate_command`` projects it; any refusal or unavailable resident
    raises the same error the single path raises.
    """

    if not entries:
        return ()
    home = command_evaluation._resolve_home(guard_home)
    results: list[CompositeCommandEvaluation] = []
    # One wire group at a time: request bytes and parsed payloads are released
    # as each group is projected, so peak memory tracks the group, not the list.
    for start in range(0, len(entries), COMMAND_EFFECT_BATCH_MAX_ITEMS):
        group = entries[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS]
        outcomes = command_effect_decide_batch_native(
            [command_evaluation._wire_item(entry)[0] for entry in group], guard_home=home
        )
        if outcomes is None:
            raise NativeCommandExtensionEvidenceError(_UNAVAILABLE)
        for entry, outcome in zip(group, outcomes, strict=True):
            if isinstance(outcome, NativeCommandEffectRejectedError):
                raise NativeCommandExtensionEvidenceError(outcome.code) from outcome
            results.append(
                command_evaluation._project_payload(outcome, entry.canonical_command, entry.extension_control_snapshot)
            )
        del outcomes
    return tuple(results)
