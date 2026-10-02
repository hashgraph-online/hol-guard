from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import structured_output_mediation
from codex_plugin_scanner.guard.runtime.structured_output_mediation import (
    canonical_structured_content_bytes,
    resolve_managed_structured_output_binding,
    resolve_managed_structured_output_resolution,
)
from tests.structured_output_mediation_support import (
    _config,
    _NativeRouteFixture,
    _policy_value,
)


def test_managed_policy_requires_active_locked_reserved_setting() -> None:
    assert resolve_managed_structured_output_binding(_config(status="absent"), harness="pi") is None
    assert resolve_managed_structured_output_binding(_config(locked=()), harness="pi") is None
    assert resolve_managed_structured_output_binding(_config(), harness="codex") is None

    invalid = _config()
    invalid.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    assert resolve_managed_structured_output_binding(invalid, harness="pi") is None


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered", "revoked"])
def test_configured_authority_failure_is_required_and_fail_closed(status: str) -> None:
    resolution = resolve_managed_structured_output_resolution(_config(status=status), harness="pi")
    assert resolution.binding is None
    assert resolution.required is True
    assert resolution.reason_code in {
        "structured_managed_authority_unavailable",
        "structured_managed_authority_revoked",
    }


def test_active_locked_malformed_or_missing_setting_is_required() -> None:
    malformed = _config()
    malformed.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    malformed_resolution = resolve_managed_structured_output_resolution(malformed, harness="pi")
    assert malformed_resolution.binding is None
    assert malformed_resolution.required is True
    assert malformed_resolution.reason_code == "structured_managed_policy_invalid"

    missing = _config()
    missing.managed_policy.settings = {"mode": "enforce"}
    missing_resolution = resolve_managed_structured_output_resolution(missing, harness="pi")
    assert missing_resolution.binding is None
    assert missing_resolution.required is True
    assert missing_resolution.reason_code == "structured_managed_policy_invalid"

    missing_authority = _config()
    missing_authority.managed_policy = None
    missing_authority_resolution = resolve_managed_structured_output_resolution(missing_authority, harness="pi")
    assert missing_authority_resolution.binding is None
    assert missing_authority_resolution.required is True
    assert missing_authority_resolution.reason_code == "structured_managed_policy_missing"

    unlocked = _config(locked=())
    unlocked_resolution = resolve_managed_structured_output_resolution(unlocked, harness="pi")
    assert unlocked_resolution.binding is None
    assert unlocked_resolution.required is True
    assert unlocked_resolution.reason_code == "structured_managed_policy_invalid"

    explicitly_empty = _config(locked=())
    explicitly_empty.managed_policy.settings["data_control"]["structured_output"] = None
    explicitly_empty_resolution = resolve_managed_structured_output_resolution(explicitly_empty, harness="pi")
    assert explicitly_empty_resolution.required is True
    assert explicitly_empty_resolution.reason_code == "structured_managed_policy_invalid"

    changed_hash = _config()
    changed_hash.managed_policy.content_hash = "b" * 64
    changed_hash_resolution = resolve_managed_structured_output_resolution(changed_hash, harness="pi")
    assert changed_hash_resolution.required is True
    assert changed_hash_resolution.reason_code == "structured_managed_policy_invalid"


def test_absent_unconfigured_authority_stays_off() -> None:
    resolution = resolve_managed_structured_output_resolution(_config(status="absent", locked=()), harness="pi")
    assert resolution == type(resolution)(None, False)


@pytest.mark.parametrize(
    "candidate",
    (
        '{"employee":{"email":"","id":7},"note":"x"}',
        '{"note":"x","employee": {"email":"","id":7}}',
        '{"note":"x","employee":{"email":"\\u0061","id":7}}',
        '{"note":"x","employee":{"email":[],"id":7}}',
        '{"note":"x","employee":{"email":"","id":9007199254740992}}',
    ),
)
def test_canonical_structured_bytes_require_fixed_object_encoding(candidate: str) -> None:
    canonical = canonical_structured_content_bytes(candidate)
    if candidate == '{"employee":{"email":"","id":7},"note":"x"}':
        assert canonical == candidate.encode()
    else:
        assert canonical is None


def test_canonical_structured_bytes_honors_absolute_deadline() -> None:
    assert (
        canonical_structured_content_bytes(
            '{"employee":{"email":"","id":7},"note":"x"}',
            deadline_monotonic=time.monotonic() - 1,
        )
        is None
    )


def test_canonical_structured_bytes_withholds_recursion_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_recursion(*_args: object, **_kwargs: object) -> bool:
        raise RecursionError("fixture recursion")

    monkeypatch.setattr(structured_output_mediation, "_has_safe_numbers", raise_recursion)
    assert canonical_structured_content_bytes('{"value":1}') is None


@pytest.mark.parametrize("property_name", ["role", "valueType", "category"])
def test_policy_rejects_untyped_field_values(property_name: str) -> None:
    policy = _policy_value()
    field: dict[str, object] = {
        "path": ["note"],
        "role": "protected_personal",
        "valueType": "string",
        "category": "person_name",
    }
    field[property_name] = ["unexpected"]
    policy["schema"] = {"fields": [field]}
    with pytest.raises(ValueError, match="is invalid"):
        structured_output_mediation.parse_structured_output_policy(policy)


@pytest.mark.parametrize("variant", ["malformed", "missing", "revoked"])
def test_native_route_does_not_skip_configured_authority_failures(tmp_path: Path, variant: str) -> None:
    config = _config(status="revoked" if variant == "revoked" else "active")
    if variant == "malformed":
        config.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    elif variant == "missing":
        config.managed_policy = None
    fixture = _NativeRouteFixture(config)
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] in {
        "structured_managed_policy_invalid",
        "structured_managed_policy_missing",
        "structured_managed_authority_revoked",
    }


@pytest.mark.parametrize(
    ("variant", "expected_message"),
    [
        ("root_not_object", "must be an object"),
        ("unknown_top_level", "unknown or missing keys"),
        ("wrong_version", "version is unsupported"),
        ("disabled", "must be enabled"),
        ("empty_harnesses", "non-empty array"),
        ("duplicate_harnesses", "must not contain duplicates"),
        ("unsupported_harness", "harness is unsupported"),
        ("wrong_event", "event is unsupported"),
        ("wrong_destination", "destination role is unsupported"),
        ("permissive_disposition", "must withhold"),
        ("schema_extra", "schema has unknown or missing keys"),
        ("empty_fields", "fields must be non-empty"),
        ("field_extra", "field 0 has unknown or missing keys"),
        ("field_bad_path", "field 0 path is invalid"),
    ],
)
def test_managed_policy_parser_rejects_untrusted_authority_shapes(
    variant: str,
    expected_message: str,
) -> None:
    policy = _policy_value()
    candidate: object = policy
    if variant == "root_not_object":
        candidate = []
    elif variant == "unknown_top_level":
        policy["unexpected"] = True
    elif variant == "wrong_version":
        policy["version"] = "other-policy.v1"
    elif variant == "disabled":
        policy["enabled"] = False
    elif variant == "empty_harnesses":
        policy["harnesses"] = []
    elif variant == "duplicate_harnesses":
        policy["harnesses"] = ["pi", "pi"]
    elif variant == "unsupported_harness":
        policy["harnesses"] = ["codex"]
    elif variant == "wrong_event":
        policy["event"] = "PreToolUse"
    elif variant == "wrong_destination":
        policy["destinationRole"] = "terminal_output"
    elif variant == "permissive_disposition":
        policy["onMatch"] = "allow"
    elif variant == "schema_extra":
        policy["schema"] = {"fields": policy["schema"]["fields"], "extra": True}
    elif variant == "empty_fields":
        policy["schema"] = {"fields": []}
    elif variant == "field_extra":
        field = dict(policy["schema"]["fields"][0])
        field["extra"] = True
        policy["schema"] = {"fields": [field]}
    elif variant == "field_bad_path":
        field = dict(policy["schema"]["fields"][0])
        field["path"] = []
        policy["schema"] = {"fields": [field]}
    else:
        raise AssertionError(variant)

    with pytest.raises(ValueError, match=expected_message):
        structured_output_mediation.parse_structured_output_policy(candidate)


@pytest.mark.parametrize(
    ("variant", "expected_required", "expected_reason"),
    [
        ("unsupported_harness", False, None),
        ("unknown_status", True, "structured_managed_authority_unavailable"),
        ("absent_stale_hash", True, "structured_managed_authority_revoked"),
        ("active_unlocked_without_setting", False, None),
        ("invalid_policy_hash", True, "structured_managed_policy_invalid"),
        ("non_mapping_settings", True, "structured_managed_policy_invalid"),
        ("harness_not_enrolled", False, None),
    ],
)
def test_managed_resolution_keeps_malformed_authority_fail_closed(
    variant: str,
    expected_required: bool,
    expected_reason: str | None,
) -> None:
    config = _config()
    harness = "pi"
    if variant == "unsupported_harness":
        harness = "codex"
    elif variant == "unknown_status":
        config.managed_policy_status = "future-status"
    elif variant == "absent_stale_hash":
        config = _config(status="absent", locked=())
        config.managed_policy_hash = "a" * 64
    elif variant == "active_unlocked_without_setting":
        config = _config(locked=())
        config.managed_policy.settings = {}
    elif variant == "invalid_policy_hash":
        config.managed_policy_hash = "not-a-policy-hash"
    elif variant == "non_mapping_settings":
        config.managed_policy.settings = []
    elif variant == "harness_not_enrolled":
        config.managed_policy.settings["data_control"]["structured_output"]["harnesses"] = ["pi"]
        harness = "omp"
    else:  # pragma: no cover - the parameter table is exhaustive
        raise AssertionError(variant)

    resolution = resolve_managed_structured_output_resolution(config, harness=harness)
    assert resolution.binding is None
    assert resolution.required is expected_required
    assert resolution.reason_code == expected_reason


def test_managed_resolution_rejects_binding_validation_disagreement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        structured_output_mediation,
        "resolve_managed_structured_output_binding",
        lambda *_args, **_kwargs: None,
    )
    resolution = resolve_managed_structured_output_resolution(_config(), harness="pi")
    assert resolution.binding is None
    assert resolution.required is True
    assert resolution.reason_code == "structured_managed_policy_invalid"


@pytest.mark.parametrize(
    "candidate",
    [
        '{"value":1.5}',
        '{"value":NaN}',
        '{"value":[1]}',
        '{"value":"' + chr(0xD800) + '"}',
        '{"value":"' + ("x" * (64 * 1024)) + '"}',
        '{"value":1,"value":2}',
    ],
)
def test_canonical_structured_bytes_withholds_malformed_or_oversized_payload(candidate: str) -> None:
    assert canonical_structured_content_bytes(candidate) is None
