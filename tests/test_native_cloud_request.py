"""Recorded parity and fail-closed behaviour for the native Cloud request owner.

``fixtures/cloud_request_authority/vectors.json`` was recorded from the retired
Python helpers in ``guard/runtime/local_request_snapshots.py`` and
``receipt_sync_privacy.py`` before they were deleted; the same file is replayed
by the Rust unit tests, so a divergence here means the resident changed.
Large byte-cap scenarios are stored as ``$repeat`` specs and compared as
summaries (see ``cloud_request_vectors_tests.rs``), so only the typed vectors
are replayed byte for byte here.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime import cloud_request_native as cloud

_VECTORS = Path(__file__).parent / "fixtures" / "cloud_request_authority" / "vectors.json.gz"
_KINDS = (
    "cloud_scrub_texts",
    "cloud_sync_texts",
    "cloud_sync_scrub_envelope",
    "cloud_review_event_display",
    "cloud_request_payload",
    "local_request_snapshot",
    "local_request_snapshot_items",
)


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(gzip.decompress(_VECTORS.read_bytes()))
    assert document["version"] == 1
    return document["vectors"]


def _has_spec(value: object) -> bool:
    if isinstance(value, dict):
        return "$repeat" in value or any(_has_spec(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_spec(item) for item in value)
    return False


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_recorded_python_vectors_match_the_resident() -> None:
    vectors = [vector for vector in _vectors() if not _has_spec(vector["args"]) and not vector.get("summary")]
    assert len(vectors) > 500
    mismatches: list[str] = []
    for vector in vectors:
        if "expected_error" in vector:
            with pytest.raises(NativeRunnerAuthorityError):
                native_runner_authority(vector["kind"], vector["args"])
        elif native_runner_authority(vector["kind"], vector["args"]) != vector["expected"]:
            mismatches.append(f"{vector['kind']} / {vector['name']}")
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_typed_adapters_return_the_owner_answer() -> None:
    assert cloud.cloud_scrub_texts(["curl --token abc123 https://x", "plain"]) == [
        "curl --token [redacted] https://x",
        "plain",
    ]
    assert cloud.cloud_scrub_texts([]) == []
    assert cloud.cloud_sync_command_display_part("  ls   -la \n") == "ls -la"
    assert cloud.cloud_sync_sanitize_text("def run(): pass", fallback="withheld") == "withheld"
    envelope = {"command": "rm -rf x", "redacted_command": "rm --token abc", "kind": "shell"}
    assert cloud.cloud_sync_scrub_envelope_commands(envelope, redaction_level="full") == {"kind": "shell"}
    row = {"request_id": "r1", "harness": "codex", "policy_action": "allow", "command_text": "echo hi"}
    payload = cloud.cloud_safe_local_request_payload(row, redaction_level="none")
    assert payload["command_text"] == "echo hi"
    display = cloud.cloud_review_event_display(row, redaction_level="full")
    assert display["display_provenance"] == "redacted"
    assert display["payload"]["request_id"] == "r1"


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_unknown_policy_action_keeps_the_historical_value_error() -> None:
    with pytest.raises(ValueError, match="authoritative_decision_inconsistent"):
        cloud.cloud_safe_local_request_payload(
            {"request_id": "r1", "policy_action": "require-approval"}, redaction_level="full"
        )


@pytest.mark.usefixtures("native_approval_reuse_runtime")
@pytest.mark.parametrize("kind", _KINDS)
def test_malformed_arguments_fail_closed(kind: str) -> None:
    with pytest.raises(NativeRunnerAuthorityError):
        native_runner_authority(kind, {"unexpected": 1})


def test_native_unavailable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    cloud._SCRUB_MEMO.clear()
    cloud._synced_text.cache_clear()
    monkeypatch.setattr(cloud, "native_runner_authority", refuse)
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_scrub_text("token abc")
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_sync_command_display_part("ls")
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_safe_local_request_payload({"request_id": "r"}, redaction_level="full")


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_scrub_is_reused_for_the_same_text(monkeypatch: pytest.MonkeyPatch) -> None:
    cloud._SCRUB_MEMO.clear()
    first = cloud.cloud_scrub_text("password hunter2")

    def refuse(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(cloud, "native_runner_authority", refuse)
    assert cloud.cloud_scrub_text("password hunter2") == first


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_oversized_snapshot_is_built_in_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {
            "row": {"request_id": f"r{index}", "harness": "codex", "policy_action": "allow", "risk_summary": "x" * 400},
            "claim": None,
        }
        for index in range(30)
    ]
    args: dict[str, Any] = {
        "redaction_level": "full",
        "routing_inputs": {"workspace_id": "w"},
        "now": "2026-01-01T00:00:00Z",
        "pending": {"rows": rows, "complete": True},
        "resolved": {"rows": [], "complete": True},
    }
    whole = cloud.local_request_snapshot(**args)
    calls: list[str] = []
    original = cloud.native_runner_authority

    def spy(kind: str, call_args: Any, guard_home: object = None) -> dict[str, Any]:
        calls.append(kind)
        return original(kind, call_args, guard_home)

    monkeypatch.setattr(cloud, "native_runner_authority", spy)
    monkeypatch.setattr(cloud, "_ONE_SHOT_BYTES", 1)
    monkeypatch.setattr(cloud, "_CHUNK_BYTES", 5_000)
    assert cloud.local_request_snapshot(**args) == whole
    assert calls.count("local_request_snapshot_items") > 2
    assert calls[-1] == "local_request_snapshot"


def test_request_row_text_is_cut_to_fit_one_resident_request() -> None:
    row = {
        "request_id": "r1",
        "raw_command_text": "a" * 200_000 + "b" * 200_000,
        "action_envelope_json": "{" + " " * 900_000,
    }
    projected = cloud.project_request_row(row)
    assert projected["raw_command_text"] == "a" * 70_000 + "b" * 70_000
    assert len(projected["action_envelope_json"]) == 400_000
    assert projected["request_id"] == "r1"


def test_error_text_is_withheld_not_raised_or_leaked_when_scrub_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_values: object) -> list[str]:
        raise NativeRunnerAuthorityError("native_runner_authority_resident_unavailable")

    monkeypatch.setattr(cloud, "cloud_scrub_texts", refuse)
    secret = "token=hunter2-secret"
    assert cloud.cloud_error_text(secret) == cloud.WITHHELD_ERROR_TEXT
    assert cloud.cloud_error_texts([secret, "b"]) == [cloud.WITHHELD_ERROR_TEXT] * 2


def test_scrub_memo_keys_by_digest_and_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def scrub(values: list[str]) -> list[str]:
        calls.append(list(values))
        return [f"scrubbed:{len(value)}" for value in values]

    monkeypatch.setattr(cloud, "cloud_scrub_texts", scrub)
    memo = cloud._ScrubMemo(2)
    assert memo.get("password=a") == memo.get("password=a")
    assert len(calls) == 1
    memo.get("b")
    memo.get("c")
    assert len(memo._entries) == 2
    assert all(isinstance(key, bytes) and len(key) == 32 for key in memo._entries)
