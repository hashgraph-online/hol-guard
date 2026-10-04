"""Negative controls for the MCP policy response leakage assertion."""

from __future__ import annotations

import pytest

from tests.guard_mcp_policy_test_support import (
    _BASIC_POLICY_YAML,
    _CREDENTIAL_WORDS,
    _FIXTURE_TOTP_REQUEST_ID,
    _assert_no_policy_response_leaks,
)


class TestPolicyResponseLeakAssertionEnforcement:
    @pytest.mark.parametrize("field", (*_CREDENTIAL_WORDS, "canonicalPolicyYaml", "canonical_policy_yaml"))
    @pytest.mark.parametrize("nested", (False, True))
    def test_rejects_sensitive_fields(self, field: str, nested: bool) -> None:
        leaked = {field: "fixture-value"}
        payload = {"requestId": _FIXTURE_TOTP_REQUEST_ID, **({"details": [leaked]} if nested else leaked)}
        with pytest.raises(AssertionError, match="Response leaked"):
            _assert_no_policy_response_leaks(payload, request_id=_FIXTURE_TOTP_REQUEST_ID)

    @pytest.mark.parametrize("word", (*_CREDENTIAL_WORDS, "apiVersion:"))
    def test_rejects_sensitive_values_in_nested_lists(self, word: str) -> None:
        payload = {"requestId": _FIXTURE_TOTP_REQUEST_ID, "details": [{"message": f"{word} fixture-value"}]}
        with pytest.raises(AssertionError, match="Response leaked"):
            _assert_no_policy_response_leaks(payload, request_id=_FIXTURE_TOTP_REQUEST_ID)

    def test_rejects_full_policy_yaml(self) -> None:
        payload = {"requestId": _FIXTURE_TOTP_REQUEST_ID, "message": _BASIC_POLICY_YAML}
        with pytest.raises(AssertionError, match="Response leaked policy YAML"):
            _assert_no_policy_response_leaks(payload, request_id=_FIXTURE_TOTP_REQUEST_ID)

    def test_request_id_exception_is_root_only(self) -> None:
        payload = {"requestId": _FIXTURE_TOTP_REQUEST_ID, "details": [{"requestId": _FIXTURE_TOTP_REQUEST_ID}]}
        with pytest.raises(AssertionError, match="Response leaked credential-like key or value: totp"):
            _assert_no_policy_response_leaks(payload, request_id=_FIXTURE_TOTP_REQUEST_ID)

    @pytest.mark.parametrize(
        "payload",
        (
            {"requestId": _FIXTURE_TOTP_REQUEST_ID, "message": "fixture-auth-value"},
            {"requestId": _FIXTURE_TOTP_REQUEST_ID},
        ),
        ids=("message-field", "requestId-field"),
    )
    def test_rejects_known_credentials_in_payload(self, payload: dict[str, object]) -> None:
        sensitive_value = (
            str(payload["message"]) if "message" in payload else _FIXTURE_TOTP_REQUEST_ID
        )
        with pytest.raises(AssertionError, match="Response leaked sensitive value"):
            _assert_no_policy_response_leaks(
                payload, request_id=_FIXTURE_TOTP_REQUEST_ID, sensitive_values=(sensitive_value,)
            )

    @pytest.mark.parametrize("value", (None, {"totp": "123456"}, "OtherRequestId0123456789AB"))
    def test_rejects_unverified_request_id(self, value: object) -> None:
        with pytest.raises(AssertionError, match="Response request ID changed"):
            _assert_no_policy_response_leaks({"requestId": value}, request_id=_FIXTURE_TOTP_REQUEST_ID)

    def test_rejects_invalid_expected_request_id(self) -> None:
        with pytest.raises(AssertionError, match="Invalid expected request ID"):
            _assert_no_policy_response_leaks({"requestId": "totp: 123456"}, request_id="totp: 123456")
