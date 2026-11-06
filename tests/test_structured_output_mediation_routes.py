"""The daemon's side of Oh My Pi structured-output mediation.

The Rust edge resolves the managed policy and mediates the content; the
daemon reads Guard config, sends the edge the managed-policy view, and passes
the edge's answer through. Mediation semantics are covered natively: the
parity vectors replayed in `guard-command` `content_sensitivity_tests.rs`, its
`mediation_*` tests, and `guard-runtime` `edge_structured_tests.rs`. These
tests cover what only the daemon does.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import hook_worker_structured
from codex_plugin_scanner.guard.daemon.hook_worker_structured import (
    read_structured_view,
    structured_destination_required,
)
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.native_content_sensitivity import NativeContentSensitivityError
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_structured import structured_output_view
from tests.structured_output_mediation_support import (
    FORWARD,
    STRUCTURED_OUTPUT_SETTING_PATH,
    WITHHOLD,
    _config,
    _DenyingNativeRouteFixture,
    _LoadErrorNativeRouteFixture,
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
    assert structured_destination_required(view, harness="pi") is True


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_the_edge_is_sent_the_managed_policy_view_and_its_answer_passes_through(
    tmp_path: Path,
    harness: str,
) -> None:
    fixture = _NativeRouteFixture(_config(), mediation=WITHHOLD)
    response, native_used = _review(fixture, tmp_path, harness=harness)
    assert native_used is True
    (request,) = fixture.captured
    view = request["structured_output_config"]
    assert isinstance(view, dict)
    assert set(view) == _VIEW_KEYS
    assert view == structured_output_view(_config())
    assert view["managed_policy_status"] == "active"
    assert view["managed_locked_settings"] == [STRUCTURED_OUTPUT_SETTING_PATH]
    # The edge's disposition is what the harness sees, and its verdict is
    # untouched by the projection.
    assert response["structured_content_mediation"] == WITHHOLD
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert fixture.raw_result == _native_result()
    assert fixture.recorded_receipt == _receipt()
    # A withhold needs no second read of the config.
    assert fixture.reads == 1


def test_a_hook_the_edge_does_not_mediate_carries_no_view(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config())
    response, _native_used = _review(fixture, tmp_path, harness="codex")
    (request,) = fixture.captured
    assert "structured_output_config" not in request
    assert "structured_content_mediation" not in response
    assert fixture.reads == 0


def test_a_forward_is_released_while_the_config_still_holds_the_scanned_view(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config(), mediation=FORWARD)
    response, _native_used = _review(fixture, tmp_path, deadline=time.monotonic() + 60)
    assert response["structured_content_mediation"] == FORWARD
    # One read to hand the edge, one to confirm after it scanned.
    assert fixture.reads == 2


@pytest.mark.parametrize("revoked", ["status", "policy_removed"])
def test_a_forward_is_withheld_when_the_config_changed_after_the_scan(tmp_path: Path, revoked: str) -> None:
    after = _config(status="revoked") if revoked == "status" else _config(status="absent", locked=())
    fixture = _NativeRouteFixture(_config(), mediation=FORWARD, config_after_edge=after)
    response, _native_used = _review(fixture, tmp_path)
    assert response["structured_content_mediation"] == _mediation("withhold", "structured_binding_changed")
    assert response["decision"] == "allow"


def test_an_unmediated_allow_is_withheld_when_a_policy_is_activated_during_the_review(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config(status="absent", locked=()), config_after_edge=_config())
    response, _native_used = _review(fixture, tmp_path)
    # Nothing was mediated, so the withhold names no native decision.
    expected = _mediation("withhold", "structured_binding_changed")
    del expected["native_decision_id"]
    assert response["structured_content_mediation"] == expected
    assert response["decision"] == "allow"
    assert fixture.reads == 2


def test_a_forward_is_withheld_when_the_config_cannot_be_read_again(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fixture = _NativeRouteFixture(_config(), mediation=FORWARD, reload_error=OSError("untrusted callback detail"))
    response, _native_used = _review(fixture, tmp_path)
    assert response["structured_content_mediation"] == _mediation("withhold", "structured_binding_recheck_failed")
    assert "content_sha256" not in response["structured_content_mediation"]
    assert "OSError" in caplog.text
    assert "untrusted callback detail" not in caplog.text
    assert "untrusted callback detail" not in str(response)


def test_a_forward_is_withheld_once_the_hook_deadline_has_passed(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config(), mediation=FORWARD)
    response, _native_used = _review(fixture, tmp_path, deadline=time.monotonic() - 1)
    assert response["structured_content_mediation"] == _mediation("withhold", "structured_review_deadline_exceeded")
    # The scan already ran past its budget; nothing more is read.
    assert fixture.reads == 1


def test_native_denial_does_not_bypass_revoked_structured_authority_on_next_allow(tmp_path: Path) -> None:
    fixture = _DenyingNativeRouteFixture(_config())
    denied, _native_used = _review(fixture, tmp_path)
    assert denied["decision"] == "deny"
    assert denied["policy_action"] == "block"
    assert denied["reason_code"] == "native_secret_detected"
    assert "structured_content_mediation" not in denied

    # The next hook reads the config afresh, so a revocation reaches the edge.
    fixture.config = _config(status="revoked")
    allowing = _NativeRouteFixture(
        fixture.config,
        mediation=_mediation("withhold", "structured_managed_authority_revoked"),
    )
    allowed, _native_used = _review(allowing, tmp_path)
    assert allowed["decision"] == "allow"
    (request,) = allowing.captured
    assert request["structured_output_config"]["managed_policy_status"] == "revoked"  # type: ignore[index]
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


@dataclass
class _UnavailableAfterTryFixture(_NativeRouteFixture):
    """An edge that is tried, so the config can change, and never answers."""

    def _review_raw_hook_native(self, **_kwargs: object) -> None:
        self.answered = True


def test_native_unavailable_route_reads_a_policy_activated_while_the_edge_was_tried(tmp_path: Path) -> None:
    fixture = _without_native_edge(
        _UnavailableAfterTryFixture(_config(status="absent", locked=()), config_after_edge=_config())
    )
    response, native_used = _review(fixture, tmp_path)
    assert native_used is False
    assert response["structured_content_mediation"]["reason_code"] == "structured_native_edge_unavailable"  # type: ignore[index]
    assert fixture.reads == 2


def test_native_route_load_error_sends_an_unreadable_view_the_edge_withholds_under(tmp_path: Path) -> None:
    fixture = _LoadErrorNativeRouteFixture(
        _config(),
        mediation=_mediation("withhold", "structured_managed_authority_unavailable"),
    )
    response, native_used = _review(fixture, tmp_path)
    assert native_used is True
    # `{}` is not a view the edge can resolve; it answers as for a config it
    # could not read, which here is the mediation the fixture stands in for.
    (request,) = fixture.captured
    assert request["structured_output_config"] == {}
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] == "structured_managed_authority_unavailable"


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
    view = request["structured_output_config"]
    assert isinstance(view, dict)
    assert view == structured_output_view(config)
    assert view["managed_locked_settings"] == [STRUCTURED_OUTPUT_SETTING_PATH]
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
    assert request["structured_output_config"] == structured_output_view(config)
    assert response["observe_mode"] is True
    assert "structured_content_mediation" not in response


def test_the_unavailable_overlay_withholds_only_what_native_resolution_requires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter([{"binding": None, "required": False, "reason_code": None}, NativeContentSensitivityError("down")])
    queries: list[tuple[str, object]] = []

    def resolve(query: str, body: dict[str, object]) -> object:
        queries.append((query, body["harness"]))
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(hook_worker_structured, "content_query", resolve)
    fixture = _UnavailableNativeRouteFixture(_config())
    overlay = fixture._apply_structured_unavailable_overlay
    kwargs = {"harness": "omp", "event_name": "PostToolUse", "guard_home": tmp_path, "workspace": None}
    assert overlay({"decision": "allow"}, **kwargs) == {"decision": "allow"}
    withheld = overlay({"decision": "allow"}, **kwargs)
    assert withheld["structured_content_mediation"]["reason_code"] == "structured_native_edge_unavailable"  # type: ignore[index]
    assert queries == [("resolution", "omp"), ("resolution", "omp")]
    # No managed destination, no query.
    assert overlay({"decision": "allow"}, **{**kwargs, "event_name": "PreToolUse"}) == {"decision": "allow"}
    assert len(queries) == 2
