"""Recorded parity and fail-closed behaviour for the native receipt payload owner.

``fixtures/cloud_receipt_payload/vectors.json`` was recorded from the retired
Python ``_cloud_sync_receipt_payload`` builder in ``guard/runtime/runner.py``;
the same file is replayed by the Rust unit tests.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime import cloud_request_native as cloud

_VECTORS = Path(__file__).parent / "fixtures" / "cloud_receipt_payload" / "vectors.json.gz"
_NOW = "2026-01-02T03:04:05+00:00"


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_recorded_python_receipts_match_the_resident() -> None:
    document = json.loads(gzip.decompress(_VECTORS.read_bytes()))
    assert document["version"] == 1
    mismatches: list[str] = []
    for vector in document["vectors"]:
        if "expected_error" in vector:
            with pytest.raises(NativeRunnerAuthorityError):
                native_runner_authority(vector["kind"], vector["args"])
        elif native_runner_authority(vector["kind"], vector["args"]) != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_adapter_returns_one_payload_per_receipt() -> None:
    receipts = [{"receipt_id": "a", "artifact_id": "skill:x"}, {"receipt_id": "b"}]
    payloads = cloud.cloud_sync_receipt_payloads(
        receipts, device_id="d", device_name="n", redaction_level="full", now=_NOW
    )
    assert [payload["receiptId"] for payload in payloads] == ["a", "b"]
    assert payloads[0]["artifactType"] == "skill"
    assert payloads[1]["capturedAt"] == _NOW
    assert cloud.cloud_sync_receipt_payloads([], device_id="d", device_name="n", redaction_level="full", now=_NOW) == []


def test_oversized_batches_are_halved(monkeypatch: pytest.MonkeyPatch) -> None:
    sizes: list[int] = []

    def fake(kind: str, args: dict[str, Any], guard_home: object = None) -> dict[str, Any]:
        receipts = args["receipts"]
        sizes.append(len(receipts))
        if len(receipts) > 2:
            raise NativeRunnerAuthorityError("native_runner_authority_request_too_large")
        return {"payloads": [{"receiptId": receipt["receipt_id"]} for receipt in receipts]}

    monkeypatch.setattr(cloud, "native_runner_authority", fake)
    receipts = [{"receipt_id": str(index)} for index in range(5)]
    payloads = cloud.cloud_sync_receipt_payloads(
        receipts, device_id="d", device_name="n", redaction_level="full", now=_NOW
    )
    assert [payload["receiptId"] for payload in payloads] == ["0", "1", "2", "3", "4"]
    assert sizes[0] == 5


def test_single_oversized_receipt_and_unavailable_native_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def too_large(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_request_too_large")

    monkeypatch.setattr(cloud, "native_runner_authority", too_large)
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_sync_receipt_payloads(
            [{"receipt_id": "x"}], device_id="d", device_name="n", redaction_level="full", now=_NOW
        )

    def unavailable(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(cloud, "native_runner_authority", unavailable)
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_sync_receipt_payloads(
            [{"receipt_id": "x"}, {"receipt_id": "y"}], device_id="d", device_name="n", redaction_level="full", now=_NOW
        )


def test_malformed_result_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloud, "native_runner_authority", lambda *a, **k: {"payloads": []})
    with pytest.raises(NativeRunnerAuthorityError):
        cloud.cloud_sync_receipt_payloads(
            [{"receipt_id": "x"}], device_id="d", device_name="n", redaction_level="full", now=_NOW
        )
