"""Fixture and refusal contracts, separate from installed native acceptance."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from ci.native_runtime import probe_installed_scoped_policy as probe
from ci.native_runtime.installed_scoped_policy_fixture import WORKSPACE, SignedPolicyFixture
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.runtime import runner


@pytest.fixture
def fixture(tmp_path: Path) -> Iterator[SignedPolicyFixture]:
    value = SignedPolicyFixture(tmp_path)
    try:
        yield value
    finally:
        value.close()


def validate(fixture: SignedPolicyFixture, bundle: dict[str, object]):
    return validate_synced_policy_bundle(
        bundle,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )


def request(fixture: SignedPolicyFixture, *, token: str | None = None) -> urllib.request.Request:
    return urllib.request.Request(
        fixture.sync_url,
        data=b"{}",
        headers={"Authorization": f"Bearer {fixture.token if token is None else token}"},
        method="POST",
    )


def test_actual_signed_delivery_does_not_preinstall_policy_authority(fixture: SignedPolicyFixture) -> None:
    fixture.bundle = fixture.signed_bundle(1)
    context = ssl.create_default_context(cafile=str(fixture.ca_file))
    with urllib.request.urlopen(request(fixture), context=context, timeout=2) as response:
        received = json.load(response)
    assert received["policyBundle"] == fixture.bundle
    accepted, reason, _keys = validate(fixture, received["policyBundle"])
    assert accepted is not None and reason is None
    assert fixture.requests == 1
    assert fixture.store.get_cloud_workspace_id() == WORKSPACE
    assert fixture.store.get_sync_payload("policy_bundle") is None
    assert fixture.store.get_sync_payload("policy_bundle_ack") is None
    assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    assert not fixture.store.list_policy_decisions()


def test_untrusted_tls_fails_before_authenticated_delivery(fixture: SignedPolicyFixture) -> None:
    with pytest.raises(urllib.error.URLError) as error:
        urllib.request.urlopen(request(fixture), context=ssl.create_default_context(), timeout=2)
    assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
    assert fixture.requests == 0


def test_actual_auth_resolver_preserves_the_synthetic_enrolled_connection(fixture: SignedPolicyFixture) -> None:
    observed: list[OAuthConnectionSnapshot] = []
    context = runner._resolve_guard_sync_auth_context(fixture.store, connection_observer=observed.append)
    assert context["sync_url"] == fixture.sync_url
    assert context["access_token"] == fixture.token
    assert isinstance(context["dpop_key_material"], GuardDpopKeyMaterial)
    assert observed == [fixture.store.capture_oauth_connection()]
    assert fixture.requests == 0


def test_fixture_event_response_uses_the_actual_sender_protocol(
    fixture: SignedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TLS transport contract only, not remote signed-event ingestion proof."""
    from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import post_review_events

    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    auth = runner._resolve_guard_sync_auth_context(fixture.store)
    result = post_review_events(
        auth,
        events=[
            {"eventId": "synthetic-event-first", "localStreamSequence": 7},
            {"eventId": "synthetic-event-second", "localStreamSequence": 8},
        ],
    )
    assert result == {
        "accepted": 2,
        "delivered": 2,
        "rejected": 0,
        "perEventResults": [
            {"index": 0, "accepted": True, "code": None, "error": None},
            {"index": 1, "accepted": True, "code": None, "error": None},
        ],
        "acknowledgedThrough": 8,
        "protocolVersion": 2,
    }
    assert fixture.requests == 0


@pytest.mark.parametrize("fault", ["version", "sequence", "boundary"])
def test_fixture_does_not_acknowledge_malformed_event_transport(fixture: SignedPolicyFixture, fault: str) -> None:
    event: dict[str, object] = {"eventId": "synthetic-event", "localStreamSequence": 1}
    body: dict[str, object] = {"protocolVersion": 2, "events": [event], "firstSequence": 1, "lastSequence": 1}
    if fault == "version":
        body["protocolVersion"] = 1
    elif fault == "sequence":
        event["localStreamSequence"] = True
    else:
        body["lastSequence"] = 2
    response = fixture.response_for_request("/api/guard/review/v2/events:batch", body)
    assert response["accepted"] == 0 and response["rejected"] == 1
    assert response["acknowledgedThrough"] == 0
    assert response["results"] == [
        {"eventId": "synthetic-event", "status": "rejected", "code": "synthetic_fixture_event_shape_invalid"}
    ]


def test_wrong_hostname_and_credentials_cannot_deliver(fixture: SignedPolicyFixture) -> None:
    context = ssl.create_default_context(cafile=str(fixture.ca_file))
    original = request(fixture)
    wrong_host = urllib.request.Request(
        original.full_url.replace("127.0.0.1", "localhost"), data=b"{}", headers=dict(original.headers), method="POST"
    )
    with pytest.raises(urllib.error.URLError) as error:
        urllib.request.urlopen(wrong_host, context=context, timeout=2)
    assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
    with pytest.raises(urllib.error.HTTPError) as unauthorized:
        urllib.request.urlopen(request(fixture, token="synthetic-invalid"), context=context, timeout=2)
    assert unauthorized.value.code == 401
    assert fixture.requests == 0


@pytest.mark.parametrize("mutation", ["signature", "payload", "workspace", "expired"])
def test_signed_fixture_exercises_actual_source_refusals(fixture: SignedPolicyFixture, mutation: str) -> None:
    bundle = fixture.signed_bundle(1)
    if mutation == "signature":
        cast(dict[str, Any], bundle["verifier"])["signature"] = "invalid"
    elif mutation == "payload":
        cast(dict[str, Any], bundle["payload"])["metadata"]["revision"] = 2
    elif mutation == "workspace":
        bundle = fixture.signed_bundle(1, workspace="synthetic-foreign-workspace")
    else:
        now = datetime.now(timezone.utc)
        bundle["issuedAt"] = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        bundle["expiresAt"] = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        fixture.sign(bundle)
    accepted, reason, _keys = validate(fixture, bundle)
    assert accepted is None and reason
    assert fixture.store.get_sync_payload("policy_bundle") is None


def test_fixture_does_not_log_request_secrets(fixture: SignedPolicyFixture, capsys: pytest.CaptureFixture[str]) -> None:
    canary = "synthetic-private-request-canary"
    context = ssl.create_default_context(cafile=str(fixture.ca_file))
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(request(fixture, token=canary), context=context, timeout=2)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("lifetime", ["once", "session", "project", "machine", "workspace", "team"])
def test_authentic_source_cannot_silently_flatten_unsupported_lifetimes(
    fixture: SignedPolicyFixture, lifetime: str
) -> None:
    bundle = fixture.signed_bundle(1, lifetime=lifetime)
    accepted, reason, _keys = validate(fixture, bundle)
    assert accepted is not None and reason is None
    document = parse_policy_document_yaml(json.dumps(bundle["payload"]))
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_lifetime"):
        compile_policy_document(document)


def test_probe_reports_only_finite_prerequisite_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.json"
    monkeypatch.setattr(probe.codex_plugin_scanner, "__file__", "/synthetic-private-canary/package.py")
    monkeypatch.setattr(probe.sys, "argv", ["probe", "--json", str(report), "--expected-source-sha", "a" * 40])
    assert probe.main() == 1
    expected = {"schema": "guard.installed-scoped-policy.v1", "passed": False, "failure": "not_installed_package"}
    assert json.loads(report.read_text()) == expected
    output = capsys.readouterr()
    assert "synthetic-private-canary" not in output.out + output.err
    assert json.loads(output.out) == expected


def test_probe_preserves_primary_failure_and_400ms_budget() -> None:
    assert probe.MAX_READINESS_P95_MS == 400
    assert probe.HOOK_SCANNER_DEFAULT_BUDGET_MS == 750

    def cleanup() -> None:
        raise RuntimeError("synthetic-cleanup-canary")

    with pytest.raises(probe.ProbeError, match="readiness_deadline"), probe.cleanup_preserving_failure(cleanup):
        raise probe.ProbeError("readiness_deadline")


@pytest.mark.parametrize("value", ["1", "0", ""])
def test_standalone_probe_refuses_python_oracle_presence(value: str) -> None:
    assert probe.environment_is_clean({})
    assert not probe.environment_is_clean({"HOL_GUARD_PYTHON_ORACLE": value})
    assert not probe.environment_is_clean({"HOL_GUARD_NATIVE": "auto"})
    assert not probe.environment_is_clean({"HOL_GUARD_TEST_MODE": "0"})


@pytest.mark.parametrize(
    "reason",
    [
        "canonical_enforcement_disabled",
        "native_policy_publication_pending",
        "native_policy_consumer_unavailable",
        "native_policy_authority_changed",
        "native_policy_authority_unavailable",
    ],
)
def test_application_failure_reports_returned_finite_reason(reason: str, capsys: pytest.CaptureFixture[str]) -> None:
    posture = {
        "configured_enforcement_lane": "canonical",
        "selected_enforcement_lane": "unverified",
        "canonical_policy_application_status": "unverified",
        "canonical_incompatibility_reason": reason,
    }
    with pytest.raises(probe.ProbeError, match=r"^current_application_missing$"):
        probe.require_current_application(posture, version=2, completed_cases=11)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema": "guard.installed-scoped-application-failure.v1",
        "bundle_version": 2,
        "completed_cases": 11,
        "configured_lane": "canonical",
        "selected_lane": "unverified",
        "application_status": "unverified",
        "reason": reason,
    }


def test_application_diagnostic_omits_unknown_values(capsys: pytest.CaptureFixture[str]) -> None:
    canary = "synthetic-private-posture-canary"
    with pytest.raises(probe.ProbeError, match=r"^current_application_missing$"):
        probe.require_current_application(
            {
                "configured_enforcement_lane": canary,
                "selected_enforcement_lane": [canary],
                "canonical_incompatibility_reason": canary,
                "unrelated_detail": canary,
            },
            version=1,
            completed_cases=1,
        )
    captured = capsys.readouterr()
    assert captured.out == "" and canary not in captured.err
    report = json.loads(captured.err)
    assert report["configured_lane"] == report["selected_lane"] == report["reason"] == "other"
    assert report["application_status"] == "missing"


def test_current_application_has_no_diagnostic(capsys: pytest.CaptureFixture[str]) -> None:
    probe.require_current_application({"canonical_policy_application_status": "current"}, version=1, completed_cases=1)
    assert capsys.readouterr() == ("", "")


def test_application_diagnostic_failure_preserves_original_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_output(*_args: object, **_kwargs: object) -> None:
        raise BrokenPipeError("synthetic-output-failure")

    monkeypatch.setattr(probe, "print", broken_output, raising=False)
    with pytest.raises(probe.ProbeError, match=r"^current_application_missing$"):
        probe.require_current_application({}, version=1, completed_cases=1)
