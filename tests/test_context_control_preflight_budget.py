"""Cold native attestation and optional control RPCs have separate budgets."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context_assistance as api
from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_execution as execution
from codex_plugin_scanner.guard import native_resident_decision as shared
from tests.test_native_context_assistance import state
from tests.test_native_daemon_route import _good, _resident

pytestmark = pytest.mark.native_route_unpinned


class Slots:
    def __init__(self, clock: list[float], wait: float, acquired: bool) -> None:
        self.clock = clock
        self.wait = wait
        self.acquired = acquired
        self.budgets: list[float] = []
        self.releases = 0

    def acquire(self, timeout: float) -> bool:
        self.budgets.append(timeout)
        self.clock[0] += self.wait
        return self.acquired

    def release(self) -> None:
        self.releases += 1


def setup(monkeypatch: pytest.MonkeyPatch, *, cold: float = 2.115, wait: float = 0, acquired: bool = True):
    clock = [100.0]
    calls: list[dict] = []
    _resident(monkeypatch, lambda request: None)
    ready = shared.native_runtime_status()

    def preflight():
        clock[0] += cold
        return ready

    def transport(*, request, timeout_seconds, **kwargs):
        calls.append({"timeout_seconds": timeout_seconds, **kwargs})
        return _good(
            request,
            {"kind": request["query"]["kind"], "state": state()},
            schema=api._OPERATION.result_schema,
        )

    slots = Slots(clock, wait, acquired)
    monkeypatch.setattr(route, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(route, "_ASK_SLOTS", slots)
    monkeypatch.setattr(route, "_resident_request", transport)
    monkeypatch.setattr(shared, "native_runtime_status", preflight)
    return calls, slots


@pytest.mark.parametrize("kind", ["status", "installations", "stop", "activate", "recheck"])
def test_cold_valid_attestation_keeps_the_control_rpc_budget(monkeypatch, tmp_path: Path, kind: str):
    calls, slots = setup(monkeypatch)
    answer = api.control(kind, guard_home=tmp_path)
    assert answer["availability"] == "off" and not answer["effective_enabled"]
    assert len(calls) == 1
    assert calls[0]["timeout_seconds"] == pytest.approx(2.0)
    assert calls[0]["record_resilience"] is False
    assert slots.budgets == [pytest.approx(2.0)] and slots.releases == 1


def test_control_queue_wait_still_consumes_the_same_rpc_budget(monkeypatch, tmp_path: Path):
    calls, slots = setup(monkeypatch, wait=1.5)
    api.control("status", guard_home=tmp_path)
    assert len(calls) == 1 and calls[0]["timeout_seconds"] == pytest.approx(0.5)
    assert slots.budgets == [pytest.approx(2.0)] and slots.releases == 1


def test_control_queue_expiry_does_not_send_or_reset_the_budget(monkeypatch, tmp_path: Path):
    calls, slots = setup(monkeypatch, wait=2.1)
    with pytest.raises(api.ContextAssistanceError, match="unavailable"):
        api.control("status", guard_home=tmp_path)
    assert calls == [] and slots.releases == 1


def test_unacquired_control_slot_is_never_released_or_dispatched(monkeypatch, tmp_path: Path):
    calls, slots = setup(monkeypatch, acquired=False)
    with pytest.raises(api.ContextAssistanceError, match="unavailable"):
        api.control("status", guard_home=tmp_path)
    assert calls == [] and slots.releases == 0


def test_hook_route_preparation_still_consumes_its_original_total_budget(monkeypatch, tmp_path: Path):
    calls, slots = setup(monkeypatch)
    with pytest.raises(route.NativeDaemonRouteError, match="unavailable"):
        route.native_route_facts("POST", "/v1/hooks/codex/pre", guard_home=tmp_path)
    assert calls == [] and slots.releases == 1


def test_workspace_operations_keep_their_existing_preparation_budget(monkeypatch, tmp_path: Path):
    calls, _slots = setup(monkeypatch, cold=8.115)
    with pytest.raises(api.ContextAssistanceError, match="unavailable"):
        api.workspace("workspace", guard_home=tmp_path, payload={"action": "list"})
    assert calls == []


def test_separate_preflight_never_makes_an_unavailable_native_runtime_authoritative(monkeypatch, tmp_path: Path):
    setup(monkeypatch)
    monkeypatch.setattr(shared, "native_runtime_status", lambda: SimpleNamespace(available=False, compatible=False))
    monkeypatch.setattr(route, "_resident_request", execution._resident_request)
    monkeypatch.setattr(execution, "native_resident_client_request", lambda **_kwargs: pytest.fail("no native client"))
    with pytest.raises(api.ContextAssistanceError, match="unavailable"):
        api.control("status", guard_home=tmp_path)


def test_unbound_control_reply_stays_rejected_after_cold_preflight(monkeypatch, tmp_path: Path):
    calls, _slots = setup(monkeypatch)

    def unbound(*, request, **kwargs):
        calls.append(kwargs)
        return _good(
            request,
            {"kind": "status", "state": state()},
            schema=api._OPERATION.result_schema,
            request_id="another-request",
        )

    monkeypatch.setattr(route, "_resident_request", unbound)
    with pytest.raises(api.ContextAssistanceError, match="unavailable"):
        api.control("status", guard_home=tmp_path)
    assert len(calls) == 1
