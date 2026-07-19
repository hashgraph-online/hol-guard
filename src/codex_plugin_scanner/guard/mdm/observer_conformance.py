"""Vendor-neutral observer adapter conformance kit.

Adapters receive bounded fixtures and return contract-shaped observations. The
kit never executes vendor commands and therefore remains safe to embed in an
MDM, EDR, RMM, or partner test runner.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
AdapterResult: TypeAlias = dict[str, JsonValue]
ObserverAdapter: TypeAlias = Callable[[dict[str, JsonValue]], AdapterResult]

_PRIVATE_KEY_BYTES: Final = bytes(range(32))
_PRIVATE_KEY: Final = Ed25519PrivateKey.from_private_bytes(_PRIVATE_KEY_BYTES)
_PUBLIC_KEY: Final = _PRIVATE_KEY.public_key()
_SIGNATURE_KEYS: Final = frozenset({"algorithm", "keyId", "value"})
_SAFE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ASSERTION_KEYS: Final = frozenset(
    {
        "schemaVersion",
        "assertionId",
        "workspaceId",
        "observerId",
        "adapterId",
        "externalDeviceId",
        "observedAt",
        "expiresAt",
        "detection",
        "remediation",
        "signature",
    }
)


@dataclass(frozen=True)
class ObserverConformanceCase:
    case_id: str
    fixture: dict[str, JsonValue]
    expected: Literal["assertion", "collision", "outage"]


@dataclass(frozen=True)
class ObserverConformanceResult:
    case_id: str
    detail: str
    passed: bool


@dataclass(frozen=True)
class ObserverConformanceReport:
    adapter_id: str
    results: tuple[ObserverConformanceResult, ...]
    schema_version: Literal["guard-observer-adapter-conformance.v1"] = "guard-observer-adapter-conformance.v1"

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)


def _canonical(value: dict[str, JsonValue]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_observer_assertion(assertion: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Return a deterministic Ed25519-signed copy for fixture authors."""

    unsigned = {key: value for key, value in assertion.items() if key != "signature"}
    signature = base64.b64encode(_PRIVATE_KEY.sign(_canonical(unsigned))).decode("ascii")
    return {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "keyId": "conformance-observer-key-v1",
            "value": signature,
        },
    }


def observer_conformance_public_key_base64() -> str:
    """Return the raw deterministic fixture public key, never the private key."""

    return base64.b64encode(_PUBLIC_KEY.public_bytes_raw()).decode("ascii")


def observer_conformance_cases(adapter_id: str = "adapter-under-test") -> tuple[ObserverConformanceCase, ...]:
    if not _SAFE_ID.fullmatch(adapter_id):
        raise ValueError("adapter_id must be a safe identifier")
    base: dict[str, JsonValue] = {
        "workspaceId": "workspace-conformance",
        "observerId": "observer-conformance",
        "adapterId": adapter_id,
        "externalDeviceId": "vendor-device-1",
        "sourceEventId": "source-event-1",
        "observedAt": "2026-07-19T06:00:00Z",
        "expiresAt": "2026-07-19T06:10:00Z",
        "detection": {
            "state": "present",
            "endpointOnline": True,
            "version": "3.1.0a9",
            "packageIdentity": "org.hol.guard",
            "reasonCodes": ["observer_current_present"],
        },
    }
    return (
        ObserverConformanceCase("valid-current", {**base, "caseId": "valid-current"}, "assertion"),
        ObserverConformanceCase(
            "clock-skew",
            {
                **base,
                "caseId": "clock-skew",
                "sourceEventId": "source-event-skew",
                "observedAt": "2026-07-19T06:04:00Z",
            },
            "assertion",
        ),
        ObserverConformanceCase("duplicate-a", {**base, "caseId": "duplicate-a"}, "assertion"),
        ObserverConformanceCase("duplicate-b", {**base, "caseId": "duplicate-b"}, "assertion"),
        ObserverConformanceCase(
            "partial-data",
            {
                **base,
                "caseId": "partial-data",
                "sourceEventId": "source-event-partial",
                "detection": {
                    "state": "partial",
                    "endpointOnline": True,
                    "version": None,
                    "packageIdentity": None,
                    "reasonCodes": ["observer_current_partial"],
                },
            },
            "assertion",
        ),
        ObserverConformanceCase(
            "mapping-collision",
            {**base, "caseId": "mapping-collision", "candidateDeviceIds": ["device-a", "device-b"]},
            "collision",
        ),
        ObserverConformanceCase(
            "provider-outage",
            {**base, "caseId": "provider-outage", "providerAvailable": False},
            "outage",
        ),
    )


def _assertion_error(result: AdapterResult, fixture: dict[str, JsonValue]) -> str | None:
    assertion_value = result.get("assertion")
    if not isinstance(assertion_value, dict) or set(assertion_value) != set(_ASSERTION_KEYS):
        return "assertion_shape_invalid"
    assertion = cast(dict[str, JsonValue], assertion_value)
    signature_value = assertion.get("signature")
    if not isinstance(signature_value, dict) or set(signature_value) != set(_SIGNATURE_KEYS):
        return "signature_shape_invalid"
    signature = cast(dict[str, JsonValue], signature_value)
    if signature.get("algorithm") != "ed25519" or signature.get("keyId") != "conformance-observer-key-v1":
        return "signature_authority_invalid"
    if assertion.get("schemaVersion") != "observer-assertion.v1":
        return "schema_version_invalid"
    assertion_id = assertion.get("assertionId")
    if not isinstance(assertion_id, str) or not _SAFE_ID.fullmatch(assertion_id):
        return "assertion_id_invalid"
    for field in ("workspaceId", "observerId", "adapterId", "externalDeviceId", "observedAt", "expiresAt"):
        if assertion.get(field) != fixture.get(field):
            return f"{field}_binding_invalid"
    if assertion.get("detection") != fixture.get("detection"):
        return "detection_fidelity_invalid"
    remediation = assertion.get("remediation")
    if remediation != {"state": "none", "jobId": None}:
        return "remediation_fabricated"
    encoded_signature = signature.get("value")
    if not isinstance(encoded_signature, str):
        return "signature_value_invalid"
    try:
        unsigned = {key: value for key, value in assertion.items() if key != "signature"}
        _PUBLIC_KEY.verify(base64.b64decode(encoded_signature, validate=True), _canonical(unsigned))
    except (binascii.Error, InvalidSignature, ValueError, TypeError):
        return "signature_invalid"
    return None


def _invoke_untrusted_adapter(adapter: ObserverAdapter, fixture: dict[str, JsonValue]) -> object:
    return adapter(fixture)


def _run_case(
    adapter: ObserverAdapter,
    case: ObserverConformanceCase,
) -> tuple[ObserverConformanceResult, AdapterResult]:
    try:
        raw_result = _invoke_untrusted_adapter(adapter, case.fixture)
        if not isinstance(raw_result, dict):
            return (
                ObserverConformanceResult(
                    case.case_id,
                    f"adapter_invalid_return_type:{type(raw_result).__name__}",
                    False,
                ),
                {},
            )
        result = cast(AdapterResult, raw_result)
    except Exception as exc:
        return ObserverConformanceResult(case.case_id, f"adapter_exception:{type(exc).__name__}", False), {}
    if case.expected == "outage":
        valid = (
            result.get("status") == "outage"
            and result.get("assertion") is None
            and result.get("errorCode") == "provider_unavailable"
        )
        return ObserverConformanceResult(case.case_id, "ok" if valid else "outage_contract_invalid", valid), result
    if case.expected == "collision":
        valid = (
            result.get("status") == "collision"
            and result.get("mappingStatus") == "ambiguous"
            and result.get("assertion") is None
        )
        return ObserverConformanceResult(case.case_id, "ok" if valid else "collision_contract_invalid", valid), result
    if result.get("status") != "observed":
        return ObserverConformanceResult(case.case_id, "observation_status_invalid", False), result
    error = _assertion_error(result, case.fixture)
    return ObserverConformanceResult(case.case_id, error or "ok", error is None), result


def run_observer_adapter_conformance(adapter_id: str, adapter: ObserverAdapter) -> ObserverConformanceReport:
    """Run replay, skew, partial-data, collision, and outage conformance cases."""

    results: list[ObserverConformanceResult] = []
    outputs: dict[str, AdapterResult] = {}
    for case in observer_conformance_cases(adapter_id):
        result, output = _run_case(adapter, case)
        results.append(result)
        outputs[case.case_id] = output
    duplicate_a = outputs["duplicate-a"].get("assertion")
    duplicate_b = outputs["duplicate-b"].get("assertion")
    duplicate_valid = duplicate_a == duplicate_b and isinstance(duplicate_a, dict)
    results.append(
        ObserverConformanceResult(
            "duplicate-idempotency",
            "ok" if duplicate_valid else "duplicate_output_changed",
            duplicate_valid,
        )
    )
    replay_digest = (
        hashlib.sha256(_canonical(cast(dict[str, JsonValue], duplicate_a))).hexdigest() if duplicate_valid else None
    )
    results.append(
        ObserverConformanceResult(
            "replay-digest",
            f"sha256:{replay_digest}" if replay_digest else "replay_digest_unavailable",
            replay_digest is not None,
        )
    )
    return ObserverConformanceReport(adapter_id=adapter_id, results=tuple(results))
