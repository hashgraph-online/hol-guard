"""The modes the relay drain records a package call under: queued, asked, observed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import mcp_relay_package_evidence_drain
from codex_plugin_scanner.guard.daemon.mcp_relay_package_evidence_drain import (
    record_mcp_relay_package_evidence,
)

from .mcp_relay_package_evidence_support import (
    WORKSPACE,
    _decision,
    _package,
    _record,
    calls,
    parsed,
    reviews,
)

__all__ = ["calls", "parsed", "reviews"]


NOTICE = {
    "request_id": "req-1",
    "harness": "codex",
    "workspace": "/work",
    "approval_url": "http://127.0.0.1:8787/requests/req-1",
    "artifact_name": "left-pad",
    "risk_headline": "left-pad has a known advisory",
    "trigger_summary": "npm install left-pad",
}


def _asked(**fields: object) -> dict[str, object]:
    """The record a request the `ask` mode queued leaves."""

    package = _package()
    del package["policy_workspace"]
    queued: dict[str, object] = {
        "outcome": "block",
        "decision_source": "approval-center-pending",
        "policy_action": "review",
        "decision": _decision("review"),
        "package": package,
        "approval": {
            "approval_center_url": "http://127.0.0.1:8787",
            "review_url": "http://127.0.0.1:8787/requests/req-1",
            "request_id": "req-1",
            "workspace": "/work",
            "notices": [dict(NOTICE)],
        },
    }
    queued.update(fields)
    return _record(**queued)


@pytest.fixture
def surfaces(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, Path, str, object]]:
    """The approval surfaces the drain raises after a queued request's receipt."""

    raised: list[tuple[object, Path, str, object]] = []
    monkeypatch.setattr(
        mcp_relay_package_evidence_drain,
        "_raise_approval_surface",
        lambda store, guard_home, harness, queued: raised.append((store, guard_home, harness, queued)),
    )
    return raised


def test_a_request_the_ask_mode_queued_is_blocked_on_its_approval_row(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _asked())

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["decision_source"] == "approval-center-pending"
    assert recorded["policy_action"] == "review"
    assert recorded["signals"] == ("left-pad has an advisory",)
    # The `ask` branch projects the call without its artifact, so the receipt
    # carries no risk categories and the plain safe arguments.
    assert "risk_categories" not in recorded
    assert recorded["arguments"] == {"safe": True, "artifact": False}
    assert "policy_workspace" not in recorded
    # It writes no inbox row; the approval request answers the call instead.
    assert reviews == []
    [(raised_store, guard_home, harness, queued)] = surfaces
    assert raised_store is store
    assert guard_home == tmp_path
    assert harness == "codex"
    assert queued.request_id == "req-1"
    assert queued.review_url == "http://127.0.0.1:8787/requests/req-1"
    assert queued.notices == (NOTICE,)


@pytest.mark.parametrize(
    "fields",
    [
        # A surface the proxy never raises.
        {"approval": {**_asked()["approval"], "request_id": " "}},  # pyright: ignore[reportGeneralTypeIssues]
        {"approval": {**_asked()["approval"], "notices": [{"request_id": "req-1"}]}},  # pyright: ignore[reportGeneralTypeIssues]
        {"approval": {"request_id": "req-1"}},
        # Only the ask branch is recorded as pending.
        {"decision_source": "policy-safe-alternative"},
        # The two queue routes are never both taken.
        {"review": {"redaction_level": "partial"}},
    ],
)
def test_an_approval_surface_the_proxy_could_not_have_raised_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _asked(**fields))
    assert calls == [] and reviews == [] and surfaces == []


def test_a_forwarded_call_never_carries_an_approval_surface(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(approval=_asked()["approval"]))
    # And a pending block with no row to point at is not that branch's receipt.
    record = _asked()
    del record["approval"]
    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    assert calls == [] and surfaces == []


def _observed(**fields: object) -> dict[str, object]:
    """The record a forward under `mode = "observe"` leaves."""

    forwarded: dict[str, object] = {
        "decision_source": "policy-observe",
        "policy_action": "allow",
        "observed": {"notices": [dict(NOTICE)]},
    }
    forwarded.update(fields)
    return _record(**forwarded)


@pytest.fixture
def notices(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, object]]:
    """The desktop notices the drain raises for the observed requests."""

    raised: list[tuple[object, object]] = []
    monkeypatch.setattr(
        mcp_relay_package_evidence_drain,
        "_raise_notices",
        lambda store, queued: raised.append((store, queued)),
    )
    return raised


def test_an_observed_forward_is_recorded_under_the_mode_it_forwarded_in(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _observed())

    [(kind, recorded)] = calls
    # The call reached the child, so the receipt is the ordinary allow receipt
    # under the action it was executed with, named by the mode rather than it.
    assert kind == "allow"
    assert recorded["decision_source"] == "policy-observe"
    assert recorded["policy_action"] == "allow"
    assert recorded["policy_workspace"] == WORKSPACE
    assert recorded["remember"] is False
    # The observed rows raise their desktop notices and nothing else: nothing
    # is waiting on an answer, so there is no approval center to open.
    assert notices == [(store, (NOTICE,))]
    assert surfaces == []


def test_an_observation_that_queued_no_row_still_names_the_mode(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
) -> None:
    # Both policies permitted the call, so the observation has nothing to
    # raise; the receipt is still the one this mode writes.
    assert record_mcp_relay_package_evidence(object(), tmp_path, _observed(observed={"notices": []}))

    [(kind, recorded)] = calls
    assert kind == "allow" and recorded["decision_source"] == "policy-observe"
    assert notices == []


@pytest.mark.parametrize(
    "fields",
    [
        # A notice the proxy never raises.
        {"observed": {"notices": [{"request_id": "req-1"}]}},
        {"observed": {"notices": "none"}},
        # The observation is the notices alone.
        {"observed": {"notices": [], "extra": True}},
        {"observed": []},
        # The mode's source belongs to an observed forward and to nothing else.
        {"observed": None},
        # A block is never the receipt an observed forward leaves.
        {"outcome": "block", "policy_action": "block", "decision": _decision("block")},
        # The forward is never queued on a row of its own.
        {"review": {"redaction_level": "partial"}},
        {"approval": _asked()["approval"]},
    ],
)
def test_an_observation_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _observed(**fields))
    assert calls == [] and notices == [] and reviews == [] and surfaces == []


def test_an_enforced_forward_is_never_recorded_under_the_observed_mode(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
) -> None:
    # The source names the mode only where the observation it left is stated.
    record = _observed()
    del record["observed"]
    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    # And an observed forward recorded under its action is the enforced one.
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _observed(decision_source="policy-allow"))
    assert calls == [] and notices == []
