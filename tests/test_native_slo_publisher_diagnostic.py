from __future__ import annotations

import hashlib
import json

import pytest

from scripts import native_slo_publisher_diagnostic as diagnostic
from scripts.native_slo_contract import assert_privacy_safe


@pytest.mark.parametrize(
    "code",
    (
        "native_policy_windows_acl_verify_failed",
        "native_policy_snapshot_generation_lock_timeout",
        "native_command_control_binding_changed",
        "native_policy_snapshot_generation_state_identity_failed",
        "guardconfigsourceerror",
        "databaseerror",
        "native_client_endpoint_invalid",
    ),
)
def test_public_publisher_codes_retain_the_exact_already_observed_label(code: str) -> None:
    result = diagnostic.publisher_error_diagnostic(code)
    assert result == {
        "publisher_error_state": "known",
        "publisher_error_value": code,
        "publisher_error_digest": hashlib.sha256(code.encode()).hexdigest(),
        "publisher_error_digest_complete": True,
    }
    reason = "HOL Guard could not prepare the native policy safely. " + code + "."
    observed = diagnostic.policy_refusal_diagnostic(reason)
    assert all(observed[key] == value for key, value in result.items())
    assert_privacy_safe({"failure": {"policy_refusal_diagnostic": observed}})


def test_every_catalog_label_passes_the_unchanged_private_evidence_privacy_contract() -> None:
    for code in diagnostic._PUBLISHER_CODES:
        assert_privacy_safe(diagnostic.publisher_error_diagnostic(code))


@pytest.mark.parametrize(
    "value",
    (
        "private publisher failure at C:\\Users\\private\\database with password=hidden",
        "native_policy_windows_acl_verify_failed:private_detail",
        "a" * 128,
        "private-data-" * 10000,
        "\N{SNOWMAN}" * 128,
        "\ud800" * 129,
    ),
)
def test_unlisted_errors_retain_only_a_bounded_fingerprint(value: str) -> None:
    result = diagnostic.publisher_error_diagnostic(value)
    assert result == {
        "publisher_error_state": "unlisted",
        "publisher_error_digest": hashlib.sha256(value[:128].encode("utf-8", errors="replace")).hexdigest(),
        "publisher_error_digest_complete": len(value) <= 128,
    }
    serialized = json.dumps(assert_privacy_safe(result))
    assert len(serialized) < 256
    assert "private_detail" not in serialized and "password" not in serialized
    reason = "HOL Guard could not prepare the native policy safely. " + value + "."
    observed = diagnostic.policy_refusal_diagnostic(reason)
    assert all(observed[key] == field for key, field in result.items())


def test_parameterized_acl_failure_retains_only_the_fixed_base_and_fingerprint() -> None:
    base = "native_policy_windows_acl_not_private"
    first = base + ":protected=0,count=3,sidclass=foreign"
    second = base + ":protected=1,count=4,sidclass=foreign"
    results = [diagnostic.publisher_error_diagnostic(value) for value in (first, second)]
    assert results[0]["publisher_error_digest"] != results[1]["publisher_error_digest"]
    for result in results:
        assert result["publisher_error_state"] == "parameterized"
        assert result["publisher_error_value"] == base
        assert result["publisher_error_digest_complete"] is True
        serialized = json.dumps(assert_privacy_safe(result))
        assert "sidclass" not in serialized and "protected=" not in serialized
    assert diagnostic.publisher_error_diagnostic(base)["publisher_error_state"] == "known"
    assert diagnostic.publisher_error_diagnostic(base + ":" + "x" * 200)["publisher_error_digest_complete"] is False


def test_absent_invalid_and_unrecognized_evidence_are_not_observed_zero() -> None:
    for value in (None, ""):
        assert diagnostic.publisher_error_diagnostic(value) == {"publisher_error_state": "absent"}
    for value in (0, False, {}, b"native_policy_windows_acl_verify_failed"):
        assert diagnostic.publisher_error_diagnostic(value) == {"publisher_error_state": "invalid_type"}
    assert (
        diagnostic.policy_refusal_diagnostic("HOL Guard could not prepare the native policy safely.")[
            "publisher_error_state"
        ]
        == "absent"
    )
    for reason in ("", "unrecognized private reason", "HOL Guard could not prepare the native policy safely. ."):
        result = diagnostic.policy_refusal_diagnostic(reason)
        assert result["publisher_error_state"] == "unrecognized_reason"
        assert "publisher_error_digest" not in result


def test_custom_objects_string_subclasses_and_metaclasses_cannot_run_callbacks() -> None:
    def hostile(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a custom diagnostic callback ran")

    class HostileMeta(type):
        __hash__ = __eq__ = hostile

    class HostileText(str, metaclass=HostileMeta):
        __str__ = __repr__ = __len__ = __bool__ = __hash__ = __eq__ = __getitem__ = __getattribute__ = hostile

    class HostileObject(metaclass=HostileMeta):
        __str__ = __repr__ = __len__ = __bool__ = __hash__ = __eq__ = __getitem__ = __getattribute__ = hostile

    for value in (HostileText("native_policy_windows_acl_verify_failed"), HostileObject(), HostileText):
        assert diagnostic.publisher_error_diagnostic(value) == {"publisher_error_state": "invalid_type"}
        assert diagnostic.policy_refusal_diagnostic(value)["publisher_error_state"] == "invalid_type"
