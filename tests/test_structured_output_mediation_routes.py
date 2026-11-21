"""The daemon's outage-only structured-output adapter behavior.

The Rust edge resolves the authenticated direct-lane binding and mediates the
content. Native mediation semantics live in the Rust edge and content
sensitivity tests. These tests cover the daemon's fail-safe overlay.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.hook_review.hook_worker_unavailable import (
    read_structured_view,
    structured_outage_overlay,
)
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from tests.structured_output_mediation_support import (
    WITHHOLD,
    _config,
    _DenyingNativeRouteFixture,
    _mediation,
    _native_result,
    _NativeRouteFixture,
    _ObserveNativeRouteFixture,
    _real_observe_managed_config,
    _receipt,
    _review,
    _UnavailableLoadErrorNativeRouteFixture,
    _UnavailableNativeRouteFixture,
)

_VIEW_KEYS = {"managed_policy_status", "managed_policy_hash", "managed_locked_settings", "managed_policy"}


class _Metrics:
    def record_route(self, _route: str) -> None:
        return None


def _without_native_edge(fixture: _NativeRouteFixture) -> _NativeRouteFixture:
    """The fixture, with the daemon's route metrics and activity log stubbed."""

    fixture.metrics = _Metrics()  # type: ignore[attr-defined]
    fixture.activity_writer = None  # type: ignore[attr-defined]
    return fixture


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered"])
def test_load_config_fail_closed_floor_keeps_structured_authority_required(
    tmp_path: Path,
    status: str,
) -> None:
    config = load_guard_config(
        tmp_path / "guard-home",
        managed_policy_state=ManagedPolicyState(status, "machine-policy-fixture"),
    )
    assert config.managed_policy_status == status
    assert config.mode == "enforce"
    assert config.default_action == "block"
    assert config.managed_policy is not None
    view = read_structured_view(lambda: config)
    assert set(view) == _VIEW_KEYS
    assert structured_outage_overlay(
        harness="pi", event_name="PostToolUse", guard_home=tmp_path, deadline=None, load_config=lambda: config
    )["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_the_edge_uses_the_authenticated_managed_view_and_passes_its_answer_through(
    tmp_path: Path,
    harness: str,
) -> None:
    fixture = _NativeRouteFixture(_config(), mediation=WITHHOLD)
    response, native_used = _review(fixture, tmp_path, harness=harness)
    assert native_used is True
    (request,) = fixture.captured
    assert "structured_output_config" not in request
    # The edge's disposition is what the harness sees, and its verdict is
    # untouched by the projection. The managed view comes from the
    # authenticated Rust direct-lane binding, so the daemon sends no copy.
    assert response["structured_content_mediation"] == WITHHOLD
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert fixture.raw_result == _native_result()
    assert fixture.recorded_receipt == _receipt()
    assert fixture.reads == 0


def test_a_hook_the_edge_does_not_mediate_carries_no_view(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config())
    response, _native_used = _review(fixture, tmp_path, harness="codex")
    (request,) = fixture.captured
    assert "structured_output_config" not in request
    assert "structured_content_mediation" not in response
    assert fixture.reads == 0


def test_native_denial_does_not_bypass_revoked_structured_authority_on_next_allow(tmp_path: Path) -> None:
    fixture = _DenyingNativeRouteFixture(_config())
    denied, _native_used = _review(fixture, tmp_path)
    assert denied["decision"] == "deny"
    assert denied["policy_action"] == "block"
    assert denied["reason_code"] == "native_secret_detected"
    assert "structured_content_mediation" not in denied

    # The next hook uses the newly acknowledged Rust direct-lane binding.
    fixture.config = _config(status="revoked")
    allowing = _NativeRouteFixture(
        fixture.config,
        mediation=_mediation("withhold", "structured_managed_authority_revoked"),
    )
    allowed, _native_used = _review(allowing, tmp_path)
    assert allowed["decision"] == "allow"
    assert allowed["structured_content_mediation"]["reason_code"] == "structured_managed_authority_revoked"  # type: ignore[index]
    assert "content_sha256" not in allowed["structured_content_mediation"]  # type: ignore[operator]


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_native_unavailable_required_structured_route_withholds_model_output(
    tmp_path: Path,
    harness: str,
) -> None:
    fixture = _without_native_edge(_UnavailableNativeRouteFixture(_config()))
    response, native_used = _review(fixture, tmp_path, harness=harness)

    assert native_used is False
    assert response["decision"] == "allow"
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }


def test_native_unavailable_route_with_an_unreadable_config_withholds(tmp_path: Path) -> None:
    fixture = _without_native_edge(_UnavailableLoadErrorNativeRouteFixture(_config()))
    response, native_used = _review(fixture, tmp_path)
    assert native_used is False
    assert response["structured_content_mediation"]["reason_code"] == "structured_native_edge_unavailable"  # type: ignore[index]


def test_recording_only_hands_the_edge_the_real_managed_policy(tmp_path: Path) -> None:
    config = _real_observe_managed_config(tmp_path)
    fixture = _ObserveNativeRouteFixture(config, mediation=WITHHOLD)
    response, native_used = _review(fixture, tmp_path, recording_only=True)
    assert native_used is True
    (request,) = fixture.captured
    assert request["observe_mode"] is True
    assert "structured_output_config" not in request
    assert response["observe_mode"] is True
    assert fixture.raw_result == _native_result(observe_mode=True)
    assert fixture.recorded_receipt == _receipt()
    assert response["decision"] == fixture.raw_result["decision"]  # type: ignore[index]
    assert response["structured_content_mediation"] == WITHHOLD


def test_recording_only_unconfigured_route_keeps_existing_watch_behavior(tmp_path: Path) -> None:
    config = _config(status="absent", locked=())
    fixture = _ObserveNativeRouteFixture(config)
    response, native_used = _review(fixture, tmp_path, recording_only=True)
    assert native_used is True
    (request,) = fixture.captured
    assert "structured_output_config" not in request
    assert response["observe_mode"] is True
    assert "structured_content_mediation" not in response


def test_the_unavailable_overlay_withholds_only_what_native_resolution_requires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter([("document", {}), None])
    queries: list[tuple[str, str]] = []

    def render(kind: str, harness: str, _params: object, **_transport: object) -> object:
        queries.append((kind, harness))
        return next(answers)

    monkeypatch.setattr("codex_plugin_scanner.guard.hook_review.hook_worker_unavailable.native_render_cli", render)
    fixture = _UnavailableNativeRouteFixture(_config())
    overlay = fixture._apply_structured_unavailable_overlay
    kwargs = {"harness": "omp", "event_name": "PostToolUse", "guard_home": tmp_path, "workspace": None}
    assert overlay({"decision": "allow"}, **kwargs) == {"decision": "allow"}
    withheld = overlay({"decision": "allow"}, **kwargs)
    assert withheld["structured_content_mediation"]["reason_code"] == "structured_native_edge_unavailable"  # type: ignore[index]
    assert queries == [("structured_outage", "omp"), ("structured_outage", "omp")]
    # No managed destination, no query.
    assert overlay({"decision": "allow"}, **{**kwargs, "event_name": "PreToolUse"}) == {"decision": "allow"}
    assert len(queries) == 2
