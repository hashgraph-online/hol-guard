from __future__ import annotations

import hashlib
from typing import cast

from codex_plugin_scanner.guard.mdm.observer_conformance import (
    JsonValue,
    ObserverAdapter,
    run_observer_adapter_conformance,
    sign_observer_assertion,
)


def conforming_adapter(fixture: dict[str, JsonValue]) -> dict[str, JsonValue]:
    case_id = fixture["caseId"]
    if case_id == "provider-outage":
        return {"status": "outage", "assertion": None, "errorCode": "provider_unavailable"}
    if case_id == "mapping-collision":
        return {"status": "collision", "assertion": None, "mappingStatus": "ambiguous"}
    source_event_id = str(fixture["sourceEventId"])
    assertion = sign_observer_assertion(
        {
            "schemaVersion": "observer-assertion.v1",
            "assertionId": f"assertion-{hashlib.sha256(source_event_id.encode()).hexdigest()[:16]}",
            "workspaceId": fixture["workspaceId"],
            "observerId": fixture["observerId"],
            "adapterId": fixture["adapterId"],
            "externalDeviceId": fixture["externalDeviceId"],
            "observedAt": fixture["observedAt"],
            "expiresAt": fixture["expiresAt"],
            "detection": fixture["detection"],
            "remediation": {"state": "none", "jobId": None},
        }
    )
    return {"status": "observed", "assertion": assertion}


def test_conforming_adapter_passes_all_signed_cases() -> None:
    report = run_observer_adapter_conformance("reference-adapter", conforming_adapter)

    assert report.passed
    assert report.adapter_id == "reference-adapter"
    assert {result.case_id for result in report.results} >= {
        "clock-skew",
        "duplicate-idempotency",
        "mapping-collision",
        "partial-data",
        "provider-outage",
        "replay-digest",
        "valid-current",
    }
    assert next(result for result in report.results if result.case_id == "replay-digest").detail.startswith("sha256:")


def test_harness_rejects_fabricated_outage_evidence() -> None:
    def unsafe_adapter(fixture: dict[str, JsonValue]) -> dict[str, JsonValue]:
        result = dict(conforming_adapter(fixture))
        if fixture["caseId"] == "provider-outage":
            result["assertion"] = conforming_adapter({**fixture, "caseId": "valid-current"})["assertion"]
        return result

    report = run_observer_adapter_conformance("unsafe-adapter", unsafe_adapter)

    assert not report.passed
    assert next(result for result in report.results if result.case_id == "provider-outage").detail == (
        "outage_contract_invalid"
    )


def test_harness_rejects_non_idempotent_duplicate_outputs() -> None:
    counter = 0

    def unstable_adapter(fixture: dict[str, JsonValue]) -> dict[str, JsonValue]:
        nonlocal counter
        counter += 1
        if fixture["caseId"] not in {"duplicate-a", "duplicate-b"}:
            return conforming_adapter(fixture)
        changed = dict(fixture)
        changed["sourceEventId"] = f"unstable-{counter}"
        return conforming_adapter(changed)

    report = run_observer_adapter_conformance("unstable-adapter", unstable_adapter)

    assert not report.passed
    assert next(result for result in report.results if result.case_id == "duplicate-idempotency").detail == (
        "duplicate_output_changed"
    )


def test_harness_reports_invalid_adapter_return_without_crashing() -> None:
    def invalid_adapter(_fixture: dict[str, JsonValue]) -> object:
        return None

    report = run_observer_adapter_conformance("invalid-adapter", cast(ObserverAdapter, invalid_adapter))

    assert not report.passed
    assert report.results[0].detail == "adapter_invalid_return_type:NoneType"
