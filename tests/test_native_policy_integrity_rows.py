"""The policy-row integrity bridge batches rows, binds replies and never computes locally."""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_integrity_rows as bridge
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_policy_integrity_rows import (
    NativePolicyIntegrityUnavailableError,
    PolicyRowSignItem,
    PolicyRowVerifyItem,
    discard_row_signing_verifier_key,
    native_prepare_policy_integrity_generation,
    native_sign_policy_rows,
    native_verify_policy_rows,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _RUST_GENERATION_FLOOR_NAME,
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
)
from codex_plugin_scanner.guard.policy_integrity import PolicyIntegrityVerificationResult

_KEY = bytes(range(32))
_KEY_ID = "guard-policy-integrity-key:test"


def _digest(request: dict[str, object], *, include_key: bool = False) -> str:
    bound = {name: value for name, value in request.items() if include_key or name != "integrity_key_b64"}
    return "sha256:" + _canonical_request_sha256(bound)


class _Resident:
    """Answers like the resident op: one outcome per item, reply bound to the request."""

    def __init__(self, *, include_key_in_digest: bool = False) -> None:
        self.requests: list[dict[str, object]] = []
        self.include_key_in_digest = include_key_in_digest

    def __call__(self, **kwargs: object) -> dict[str, object] | None:
        assert kwargs["operation"] == "policy_integrity_rows"
        request = kwargs["request"]
        assert isinstance(request, dict)
        expected_feature = "policy-integrity-generation-v1" if "generation" in request else "policy-integrity-rows-v1"
        assert kwargs["required_feature"] == expected_feature
        self.requests.append(request)
        verify = request["verify"]
        sign = request["sign"]
        assert isinstance(verify, list)
        assert isinstance(sign, list)
        return {
            "schema": "guard-policy-integrity-rows-result.v1",
            "request_id": request["request_id"],
            "request_sha256": _digest(request, include_key=self.include_key_in_digest),
            "status": "ok",
            "code": "ok",
            "payload": {
                "verify": [{"status": "valid", "payload_hash": str(item["row"]["decision_id"])} for item in verify],
                "sign": [
                    {
                        "integrity_version": 2,
                        "integrity_generation": item["generation"],
                        "payload_hash": "h",
                        "payload_mac": "m",
                        "integrity_key_id": request["integrity_key_id"],
                        "signed_at": item["signed_at"],
                    }
                    for item in sign
                ],
            },
        }


@pytest.fixture
def resident(monkeypatch: pytest.MonkeyPatch) -> _Resident:
    fake = _Resident()
    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))
    return fake


def _verify(rows: int) -> list[PolicyRowVerifyItem]:
    return [
        PolicyRowVerifyItem({"decision_id": index, "source": "local"}, degraded_mode=False) for index in range(rows)
    ]


def test_verify_batches_at_most_1024_rows_per_call_in_order(resident: _Resident, tmp_path: Path) -> None:
    results = native_verify_policy_rows(guard_home=tmp_path, items=_verify(2500), key=_KEY, key_id=_KEY_ID)

    assert [len(request["verify"]) for request in resident.requests] == [1024, 1024, 452]
    assert [result.payload_hash for result in results] == [str(index) for index in range(2500)]
    assert all(request["sign"] == [] for request in resident.requests)


def test_no_rows_never_calls_the_resident(resident: _Resident, tmp_path: Path) -> None:
    assert native_verify_policy_rows(guard_home=tmp_path, items=[], key=None, key_id=None) == []
    assert resident.requests == []


def test_sign_returns_the_resident_columns(resident: _Resident, tmp_path: Path) -> None:
    items = [PolicyRowSignItem({"decision_id": 7}, generation=4, signed_at="2026-01-01T00:00:00+00:00")]

    signed = native_sign_policy_rows(guard_home=tmp_path, items=items, key=_KEY, key_id=_KEY_ID)

    assert signed == [
        {
            "integrity_version": 2,
            "integrity_generation": 4,
            "payload_hash": "h",
            "payload_mac": "m",
            "integrity_key_id": _KEY_ID,
            "signed_at": "2026-01-01T00:00:00+00:00",
        }
    ]
    request = resident.requests[0]
    assert request["integrity_key_b64"] == base64.urlsafe_b64encode(_KEY).rstrip(b"=").decode("ascii")
    key_path = tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME
    assert key_path.is_file()
    assert key_path.stat().st_size == 32
    assert key_path.stat().st_mode & 0o077 == 0


def test_reply_digest_excludes_the_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = _Resident(include_key_in_digest=True)
    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    with pytest.raises(NativePolicyIntegrityUnavailableError):
        native_verify_policy_rows(guard_home=tmp_path, items=_verify(1), key=_KEY, key_id=_KEY_ID)


def test_reply_digest_is_the_same_for_any_key(resident: _Resident, tmp_path: Path) -> None:
    native_verify_policy_rows(guard_home=tmp_path, items=_verify(1), key=_KEY, key_id=_KEY_ID)
    first = dict(resident.requests[0])
    second = dict(first, integrity_key_b64=base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode("ascii"))

    assert _digest(first) == _digest(second)
    assert _digest(first) != _digest(dict(first, integrity_key_id="other"))


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {"status": "error", "code": "native_policy_integrity_key_invalid"},
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"payload": {"verify": [], "sign": []}},
        {"payload": {"verify": [{"status": "trusted"}], "sign": []}},
        {"payload": {"verify": [{"status": "valid"}], "sign": [{}]}},
    ],
)
def test_unavailable_or_unbound_replies_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object] | None
) -> None:
    honest = _Resident()

    def answer(**kwargs: object) -> dict[str, object] | None:
        response = honest(**kwargs)
        if reply is None or response is None:
            return None
        return {**response, **reply}

    monkeypatch.setattr(bridge, "_resident_request", answer)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    with pytest.raises(NativePolicyIntegrityUnavailableError):
        native_verify_policy_rows(guard_home=tmp_path, items=_verify(1), key=_KEY, key_id=_KEY_ID)


def test_signature_for_another_generation_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    honest = _Resident()

    def answer(**kwargs: object) -> dict[str, object] | None:
        response = honest(**kwargs)
        assert response is not None
        response["payload"]["sign"][0]["integrity_generation"] = 3  # type: ignore[index]
        return response

    monkeypatch.setattr(bridge, "_resident_request", answer)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))
    items = [PolicyRowSignItem({"decision_id": 1}, generation=4, signed_at="now")]

    with pytest.raises(NativePolicyIntegrityUnavailableError):
        native_sign_policy_rows(guard_home=tmp_path, items=items, key=_KEY, key_id=_KEY_ID)


def test_rows_ship_only_integrity_columns_with_foreign_values_as_null(resident: _Resident, tmp_path: Path) -> None:
    row = {"decision_id": 1, "reason": b"blob", "expires_at": 1.5, "notes": "not shipped", "owner": "me"}

    native_verify_policy_rows(
        guard_home=tmp_path,
        items=[PolicyRowVerifyItem(row, degraded_mode=False, trusted_generation=2)],
        key=None,
        key_id=None,
    )

    item = resident.requests[0]["verify"][0]
    assert item == {
        "row": {"decision_id": 1, "expires_at": None, "owner": "me", "reason": None},
        "degraded_mode": False,
        "trusted_generation": 2,
    }
    assert "integrity_key_b64" not in resident.requests[0]
    assert not (tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME).exists()


def test_degraded_rows_are_answered_without_the_resident(resident: _Resident, tmp_path: Path) -> None:
    row = {"decision_id": 1, "payload_hash": "sha256:stored", "integrity_key_id": "", "owner": "me"}

    results = native_verify_policy_rows(
        guard_home=tmp_path,
        items=[PolicyRowVerifyItem(row, degraded_mode=True)],
        key=None,
        key_id=None,
    )

    assert resident.requests == []
    assert results == [
        PolicyIntegrityVerificationResult(
            status="degraded_mode",
            payload_hash="sha256:stored",
            key_id=None,
            message="policy_integrity_backend_unavailable",
        )
    ]


def test_reset_discards_a_verifier_only_row_signing_relied_on(tmp_path: Path) -> None:
    state = tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY
    state.mkdir()
    verifier = state / NATIVE_POLICY_VERIFIER_KEY_NAME
    verifier.write_bytes(b"v" * 32)

    discard_row_signing_verifier_key(tmp_path)

    assert not verifier.exists()
    discard_row_signing_verifier_key(tmp_path)


def test_reset_keeps_a_verifier_other_native_state_is_bound_to(tmp_path: Path) -> None:
    state = tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY
    state.mkdir()
    verifier = state / NATIVE_POLICY_VERIFIER_KEY_NAME
    verifier.write_bytes(b"v" * 32)
    (state / _RUST_GENERATION_FLOOR_NAME).write_text("{}")

    discard_row_signing_verifier_key(tmp_path)

    assert verifier.read_bytes() == b"v" * 32


_STATE = {"cutover_complete": False, "generation": 3, "pending_generation": None, "version": 1}


def _generation_resident(outcome: object) -> Callable[..., dict[str, object] | None]:
    honest = _Resident()

    def answer(**kwargs: object) -> dict[str, object] | None:
        response = honest(**kwargs)
        assert response is not None
        response["payload"]["generation"] = outcome  # type: ignore[index]
        return response

    answer.requests = honest.requests  # type: ignore[attr-defined]
    return answer


def test_generation_returns_the_resident_decision(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    prepared = dict(_STATE, cutover_complete=True)
    fake = _generation_resident({"prepared_state": prepared, "still_matches": True})
    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    result = native_prepare_policy_integrity_generation(
        guard_home=tmp_path, store_path=tmp_path / "guard.db", key=_KEY, key_id=_KEY_ID, trusted_state=_STATE
    )

    assert result == (prepared, True)
    request = fake.requests[0]  # type: ignore[attr-defined]
    assert request["verify"] == [] and request["sign"] == []
    assert request["generation"] == {
        "store_path": str(tmp_path / "guard.db"),
        "guard_home": str(tmp_path),
        "trusted_state": _STATE,
    }
    assert (tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME).is_file()


@pytest.mark.parametrize(
    "outcome",
    [
        None,
        {"prepared_state": _STATE},
        {"prepared_state": _STATE, "still_matches": 1},
        {"prepared_state": [], "still_matches": True},
        {"prepared_state": _STATE, "still_matches": True, "extra": 1},
    ],
)
def test_malformed_generation_replies_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome: object
) -> None:
    monkeypatch.setattr(bridge, "_resident_request", _generation_resident(outcome))
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    with pytest.raises(NativePolicyIntegrityUnavailableError):
        native_prepare_policy_integrity_generation(
            guard_home=tmp_path, store_path=tmp_path / "guard.db", key=_KEY, key_id=_KEY_ID, trusted_state=_STATE
        )


def test_verify_reply_with_a_generation_section_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    outcome = {"prepared_state": _STATE, "still_matches": True}
    monkeypatch.setattr(bridge, "_resident_request", _generation_resident(outcome))
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    with pytest.raises(NativePolicyIntegrityUnavailableError):
        native_verify_policy_rows(guard_home=tmp_path, items=_verify(1), key=_KEY, key_id=_KEY_ID)
