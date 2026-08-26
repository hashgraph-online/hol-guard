# pyright: reportPrivateUsage=false

from __future__ import annotations

import copy
import random
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.contracts.guard_cloud_review import (
    load_fixtures,
    validate_exact_command_result,
    validate_review_result,
)
from codex_plugin_scanner.guard.review_contracts import (
    normalize_remote_approval_decision,
    validated_remote_approval_envelope,
)
from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewContractError
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import (
    CloudReviewEventProtocolError,
    _normalize_response,
)
from tests.guard_cloud_review_hardening_support import exact_job_store

_FUZZ_SEED = 0xC10D5EED


def _json_value(randomizer: random.Random, depth: int = 0) -> object:
    scalar: tuple[object, ...] = (None, True, False, -1, 0, 1, 2.5, "", " ", "allow", "block", "\x00")
    if depth >= 2 or randomizer.randrange(3) == 0:
        return randomizer.choice(scalar)
    if randomizer.randrange(2) == 0:
        return [_json_value(randomizer, depth + 1) for _ in range(randomizer.randrange(4))]
    return {f"key-{index}": _json_value(randomizer, depth + 1) for index in range(randomizer.randrange(4))}


def _mutations(seed: Mapping[str, object], *, count: int) -> list[dict[str, object]]:
    randomizer = random.Random(_FUZZ_SEED)
    keys = tuple(seed)
    candidates: list[dict[str, object]] = []
    for _ in range(count):
        candidate = copy.deepcopy(dict(seed))
        key = randomizer.choice(keys)
        if randomizer.randrange(4) == 0:
            candidate.pop(key, None)
        else:
            candidate[key] = _json_value(randomizer)
        if randomizer.randrange(5) == 0:
            candidate[f"unknown-{randomizer.randrange(20)}"] = _json_value(randomizer)
        candidates.append(candidate)
    return candidates


def _assert_parser_is_total(
    candidates: list[dict[str, object]],
    parser: Callable[[dict[str, object]], object],
    expected_errors: tuple[type[BaseException], ...],
) -> None:
    for candidate in candidates:
        try:
            parser(candidate)
        except expected_errors:
            continue


def test_event_ack_parser_is_total_over_deterministic_json_mutations() -> None:
    events: list[dict[str, object]] = [{"eventId": "event-41", "localStreamSequence": 41}]
    valid: dict[str, object] = {
        "protocolVersion": 2,
        "acknowledgedThrough": 41,
        "accepted": 1,
        "rejected": 0,
        "results": [{"eventId": "event-41", "status": "accepted"}],
    }
    _assert_parser_is_total(
        _mutations(valid, count=400),
        lambda candidate: _normalize_response(candidate, events=events, sequences=[41]),
        (CloudReviewEventProtocolError,),
    )


def test_decision_parser_is_total_and_never_expands_its_vocabulary() -> None:
    randomizer = random.Random(_FUZZ_SEED)
    values = [_json_value(randomizer) for _ in range(1_000)]
    values.extend(["allow", "allow_once", "allowOnce", "block", "deny", "denied", "blocked"])
    for value in values:
        assert normalize_remote_approval_decision(value) in {"allow", "block", None}


def test_signed_envelope_parser_is_total_over_deterministic_json_mutations(tmp_path: Path) -> None:
    store, job = exact_job_store(tmp_path, request_id="parser-envelope")
    payload = job["payload"]
    assert isinstance(payload, dict)
    envelope = cast(dict[str, object], payload["remoteApproval"])
    admitted_at = envelope["issuedAt"]
    _assert_parser_is_total(
        _mutations(envelope, count=400),
        lambda candidate: validated_remote_approval_envelope(candidate, store=store, admitted_at=admitted_at),
        (GuardReviewContractError,),
    )


def test_result_parsers_are_total_over_deterministic_json_mutations() -> None:
    fixtures = load_fixtures()
    valid_results = fixtures["validResults"]
    assert isinstance(valid_results, list)
    aggregate = cast(dict[str, object], valid_results[0])
    aggregate_result = cast(dict[str, object], aggregate["result"])
    exact: dict[str, object] = {
        "applicationReason": None,
        "applicationStatus": "applied",
        "applicationUpdatedAt": "2026-08-24T00:03:00+00:00",
        "continuationReason": None,
        "continuationStatus": "resumed",
        "continuationUpdatedAt": "2026-08-24T00:03:00+00:00",
        "contractVersion": "guard-cloud-review-command-result-v2",
        "correlationId": "command-123",
        "localRequestId": "request-123",
        "protocolVersion": 2,
        "receiptId": "receipt-123",
    }
    _assert_parser_is_total(
        _mutations(aggregate_result, count=400),
        validate_review_result,
        (ValueError, ValidationError),
    )
    _assert_parser_is_total(
        _mutations(exact, count=400),
        validate_exact_command_result,
        (ValueError, ValidationError),
    )
