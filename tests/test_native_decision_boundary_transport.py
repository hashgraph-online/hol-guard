from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority, native_signal_projection
from codex_plugin_scanner.guard.decision_boundaries import (
    canonical_approval_decision,
    canonical_approval_surfaces,
    canonical_approval_surfaces_batch,
    canonical_receipt_decision,
)
from codex_plugin_scanner.guard.native_approval_queue_identity import bind_connection_guard_home
from codex_plugin_scanner.guard.native_signal_projection import NativeSignalProjectionUnavailableError
from codex_plugin_scanner.guard.store_approvals import resolvable_approval_request_ids


@pytest.mark.parametrize("operation", ("approval", "receipt", "surfaces", "batch"))
def test_boundary_native_outage_has_no_local_verdict(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    def unavailable(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runtime_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    with pytest.raises(NativeSignalProjectionUnavailableError, match="native_runtime_unavailable") as caught:
        if operation == "approval":
            canonical_approval_decision("allow", None, reject_contradiction=False)
        elif operation == "receipt":
            canonical_receipt_decision("allow", None, reject_contradiction=False)
        elif operation == "surfaces":
            canonical_approval_surfaces("allow", None, None, reject_contradiction=False)
        else:
            canonical_approval_surfaces_batch([("allow", None, None)])
    assert not isinstance(caught.value, ValueError)
    assert isinstance(caught.value.__cause__, native_runner_authority.NativeRunnerAuthorityError)


@pytest.mark.usefixtures("native_prompt_runtime")
@pytest.mark.parametrize("count,expected_calls", ((0, 0), (25, 1), (129, 2)))
def test_queue_projection_uses_one_native_call_per_bounded_page(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    count: int,
    expected_calls: int,
) -> None:
    from codex_plugin_scanner.guard.native_context import bind_context_digest_home, reset_context_digest_home

    original = native_signal_projection._request
    calls: list[str] = []

    def tracked(kind: str, args: dict[str, object], *, guard_home: Path | None = None) -> dict[str, object]:
        calls.append(kind)
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_signal_projection, "_request", tracked)
    token = bind_context_digest_home(tmp_path)
    try:
        result = canonical_approval_surfaces_batch([("review", None, None)] * count)
    finally:
        reset_context_digest_home(token)
    assert len(result) == count
    assert calls == ["projection_surfaces_batch"] * expected_calls
    assert all(item.policy_action == "review" and item.contract_error is None for item in result)


@pytest.mark.usefixtures("native_prompt_runtime")
def test_store_read_projections_use_the_connection_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.models import GuardApprovalRequest
    from codex_plugin_scanner.guard.store import GuardStore

    home = tmp_path / "custom-guard-home"
    store = GuardStore(home)
    request = GuardApprovalRequest(
        request_id="custom-home-request",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="fixture",
        artifact_hash="sha256:" + "a" * 64,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="project",
        config_path="config.toml",
        review_command="review",
        approval_url="",
    )
    original = native_runner_authority.native_runner_authority
    homes: list[Path] = []

    def bound(kind: str, args: object, guard_home: Path | None = None):
        if kind.startswith("projection_"):
            if guard_home is None:
                raise native_runner_authority.NativeRunnerAuthorityError("default_home_unavailable")
            assert guard_home == home
            homes.append(guard_home)
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", bound)
    # The resident projects the insert itself; the reads project through the
    # store's home even when the default home is not set up.
    store.add_approval_request(request, "2026-01-01T00:00:00+00:00")
    store.add_approval_request(request, "2026-01-01T00:00:01+00:00")
    page = store.list_approval_request_page(include_totals=False)
    detail = store.get_approval_request(request.request_id, derive_scope=False)
    assert page["items"][0]["request_id"] == request.request_id
    assert detail is not None and detail["policy_action"] == "review"
    assert len(homes) >= 2 and set(homes) == {home}


@pytest.mark.usefixtures("native_prompt_runtime")
def test_listing_outage_reports_scope_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.models import GuardApprovalRequest
    from codex_plugin_scanner.guard.native_approval_scope import ApprovalScopeUnavailableError
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "outage-home")
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="outage-request",
            harness="codex",
            artifact_id="artifact-1",
            artifact_name="fixture",
            artifact_hash="sha256:" + "a" * 64,
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=(),
            source_scope="project",
            config_path="config.toml",
            review_command="review",
            approval_url="",
        ),
        "2026-01-01T00:00:00+00:00",
    )

    def unavailable(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runtime_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    # Daemon polls and /requests treat this as the 503 scope outage, not a crash.
    with pytest.raises(ApprovalScopeUnavailableError):
        store.list_approval_requests(status="pending", limit=1)
    with pytest.raises(ApprovalScopeUnavailableError):
        store.list_approval_request_page(include_totals=False)
    # The approval write path reads the row with derive_scope=False; it must surface the same outage.
    with pytest.raises(ApprovalScopeUnavailableError):
        store.get_approval_request("outage-request", derive_scope=False)


def test_boundary_healthy_refusal_is_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityRefusalError("native_runner_authority_request_too_large")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", refuse)
    with pytest.raises(native_signal_projection.NativeSignalProjectionError, match="too_large") as caught:
        canonical_approval_surfaces_batch([("review", None, None)])
    assert not isinstance(caught.value, NativeSignalProjectionUnavailableError)


@pytest.mark.usefixtures("native_prompt_runtime")
def test_unkeyed_projection_home_never_creates_store_signing_state(tmp_path: Path) -> None:
    home = tmp_path / "uninitialized-read-home"
    home.mkdir()
    result = canonical_approval_surfaces("review", None, None, reject_contradiction=False, guard_home=home)
    assert result.policy_action == "review"
    assert list(home.iterdir()) == []


@pytest.mark.usefixtures("native_prompt_runtime")
def test_large_readable_rows_split_without_reordering(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "large-page-home"
    source = canonical_approval_decision("review", None, reject_contradiction=False, guard_home=home).decision_v2_json
    inputs = [("review", {**source, "policyVersion": str(index) + ":" + "x" * 30_000}, None) for index in range(100)]
    original = native_signal_projection._request
    batches: list[int] = []

    def tracked(kind: str, args: dict[str, object], *, guard_home: Path | None = None):
        if kind == "projection_surfaces_batch":
            batches.append(len(args["rows"]))
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_signal_projection, "_request", tracked)
    results = canonical_approval_surfaces_batch(inputs, guard_home=home)
    assert [row.decision_v2_json["policyVersion"] for row in results] == [row[1]["policyVersion"] for row in inputs]
    assert batches == [100, 50, 50]
    # Each admitted string stays below 1 MiB; the combined result exceeds 2 MiB.
    signals = [{"signal_id": f"large:{index}", "technical_detail": "x" * (800 * 1024)} for index in range(3)]
    oversized = [("review", None, None), ("review", {**source, "signals": signals}, None)]
    # One unreadable row fails closed on its own; the rest of the page still projects.
    readable, unreadable = canonical_approval_surfaces_batch(oversized, guard_home=home)
    assert (readable.policy_action, readable.contract_error) == ("review", None)
    assert unreadable.contract_error == "authoritative_decision_inconsistent"
    assert unreadable.policy_action in {"review", "require-reapproval"}


@pytest.mark.usefixtures("native_prompt_runtime")
def test_unencodable_row_fails_closed_without_hiding_the_page(tmp_path: Path) -> None:
    home = tmp_path / "unencodable-home"
    results = canonical_approval_surfaces_batch(
        [("review", None, None), ("block", {"score": float("nan")}, None)], guard_home=home
    )
    assert (results[0].policy_action, results[0].contract_error) == ("review", None)
    assert (results[1].policy_action, results[1].contract_error) == ("block", "authoritative_decision_inconsistent")


def test_resolution_sweep_skips_an_unencodable_row_in_one_projection(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    bind_connection_guard_home(connection, tmp_path / "sweep-home")
    rows = connection.execute(
        """
        select 'readable' as request_id, 'review' as policy_action,
               null as decision_v2_json, null as action_envelope_json
        union all
        select 'unencodable', 'review', '{"score": NaN}', null
        """
    ).fetchall()
    assert resolvable_approval_request_ids(connection, rows) == ["readable"]


def test_batch_request_bytes_are_bounded_even_below_the_row_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    batches: list[int] = []

    def request(kind: str, args: dict[str, object], *, guard_home: Path | None = None):
        rows = args["rows"]
        batches.append(len(rows))
        return {
            "status": "ok",
            "value": [
                {
                    "policy_action": "review",
                    "decision_v2_json": {},
                    "action_envelope_json": None,
                    "contract_error": None,
                }
                for _ in rows
            ],
        }

    monkeypatch.setattr(native_signal_projection, "_request", request)
    results = canonical_approval_surfaces_batch([("review", {"user_body": "x" * 100_000}, None)] * 40)
    assert len(results) == 40
    assert len(batches) == 2 and sum(batches) == 40 and max(batches) < 40
