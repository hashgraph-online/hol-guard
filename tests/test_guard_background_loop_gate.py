"""Degraded background loops back off and log once, across library restarts.

A host whose resident library process was replaced every few minutes logged
about 1,900 catalog refresh failures and 650 skipped enrollments in five days:
each new process started its loops from a clean slate, refetched the release,
failed the same way and logged the same lines. These tests pin the fix. The
runtime's ledger outlives the process, so a failing loop waits before its next
attempt and an unchanged failure is logged once.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from codex_plugin_scanner.guard import extension_control_host
from codex_plugin_scanner.guard.catalog_delivery import current_refresh, discovery
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime_health import background_diagnostics, background_loop_gate
from codex_plugin_scanner.guard.runtime_health.background_diagnostics import failure_detail


class Ledger:
    """The runtime ledger's contract, kept in memory for one test."""

    FIRST_WAIT = 300

    def __init__(self) -> None:
        self.loops: dict[str, dict[str, object]] = {}
        self.now = 0
        self.calls: list[tuple[str, str | None]] = []

    def ask(self, _home: Path, op: str, loop: str | None = None, failure_key: str | None = None):
        self.calls.append((op, loop))
        if op == "status":
            return {"ok": True, "loops": [{"loop": name, "state": "healthy"} for name in background_loop_gate.LOOPS]}
        state = self.loops.setdefault(loop or "", {"failures": 0, "key": None, "attempt": None})
        if op == "attempt":
            failures = int(state["failures"])
            last = state["attempt"]
            if failures and last is not None and self.now - int(last) < self.FIRST_WAIT * 2 ** (failures - 1):
                return {"ok": True, "run": False}
            state["attempt"] = self.now
            return {"ok": True, "run": True}
        if failure_key is None:
            failures = int(state["failures"])
            state.update(failures=0, key=None)
            return {"ok": True, "log": False, "recovered": failures > 0, "failures": failures}
        log = state["failures"] == 0 or state["key"] != failure_key
        state["failures"] = int(state["failures"]) + 1
        state["key"] = failure_key
        return {"ok": True, "log": log, "recovered": False, "failures": state["failures"], "repeats": 0}


@pytest.fixture
def ledger(monkeypatch) -> Ledger:
    held = Ledger()
    monkeypatch.setattr(background_loop_gate, "_ask", held.ask)
    return held


@pytest.fixture
def recorded():
    events: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        events.append((event, detail))

    background_diagnostics.install_sink(sink, notice=lambda event, detail: events.append((event, detail)))
    yield events
    background_diagnostics.release_sink(sink)


def _fresh_library_process(monkeypatch, home: Path) -> None:
    """What a replaced library process starts with: no in-memory backoff at all."""

    for field, value in dict(
        _home=home, _worker=None, _handle=None, _retry_after=0.0, _failures=0, _noted_engine_mismatch=None
    ).items():
        monkeypatch.setattr(discovery, field, value)
    monkeypatch.setattr(discovery, "_refresh_after", 0.0)
    monkeypatch.setattr(discovery, "_refresh_worker", None)


def _failing_fetch(monkeypatch) -> list[int]:
    fetches: list[int] = []

    def refresh(_store):
        fetches.append(1)
        raise ValueError("release transport body length invalid")

    def restore(_store):
        raise ValueError("discovery_current_engine_incompatible")

    monkeypatch.setattr(current_refresh, "refresh", refresh)
    monkeypatch.setattr(current_refresh, "restore", restore)
    return fetches


def test_a_restarted_library_process_does_not_refetch_or_relog_a_failing_refresh(
    tmp_path, monkeypatch, ledger, recorded
) -> None:
    home = tmp_path.absolute()
    fetches = _failing_fetch(monkeypatch)

    # Three library processes, three minutes apart, as the live host ran.
    for minute in (0, 3, 6):
        ledger.now = minute * 60
        _fresh_library_process(monkeypatch, home)
        discovery._refresh(home, SimpleNamespace())

    assert len(fetches) == 2, "the restart inside the first wait must not refetch"
    assert [event for event, _ in recorded] == [
        "catalog_publication_refresh_failed",
        "catalog_publication_restore_failed",
    ]
    assert recorded[0][1].endswith(" failures=1")


def test_a_changed_failure_is_logged_again(tmp_path, monkeypatch, ledger, recorded) -> None:
    outcomes = iter(["error", AuthorityHealth.TAMPERED, AuthorityHealth.TAMPERED])

    def enroll(_digest):
        outcome = next(outcomes)
        if outcome == "error":
            raise ValueError("authority lease busy")
        return SimpleNamespace(health=outcome)

    store = SimpleNamespace(guard_home=tmp_path, enroll_extension_control_authority_by_default=enroll)
    for _ in range(3):
        host = object.__new__(extension_control_host.ExtensionControlHost)
        host.store = store
        host._enroll_authority_by_default()

    # The failure turned into a skip, so the skip is new and is logged; the
    # same skip a third time is not.
    assert [event for event, _ in recorded] == [
        "default_authority_enrollment_failed",
        "default_authority_enrollment_skipped",
    ]
    assert recorded[1][1] == "health=tampered failures=2"


def test_a_refresh_that_recovers_says_so_once(tmp_path, monkeypatch, ledger, recorded) -> None:
    home = tmp_path.absolute()
    _failing_fetch(monkeypatch)
    discovery._refresh(home, SimpleNamespace())
    handle = object()
    monkeypatch.setattr(current_refresh, "refresh", lambda _store: handle)
    for step in (1, 2):
        ledger.now = 10_000 * step
        _fresh_library_process(monkeypatch, home)
        discovery._refresh(home, SimpleNamespace())

    assert recorded[-1] == ("catalog_publication_refresh_recovered", "failures=1")
    assert [event for event, _ in recorded].count("catalog_publication_refresh_recovered") == 1


def test_without_a_ledger_every_failure_is_logged_as_before(tmp_path, monkeypatch, recorded) -> None:
    home = tmp_path.absolute()
    fetches = _failing_fetch(monkeypatch)
    for _ in range(2):
        _fresh_library_process(monkeypatch, home)
        discovery._refresh(home, SimpleNamespace())

    assert len(fetches) == 2
    assert [event for event, _ in recorded].count("catalog_publication_refresh_failed") == 2


def test_an_unchanged_skipped_enrollment_is_logged_once(tmp_path, monkeypatch, ledger, recorded) -> None:
    store = SimpleNamespace(
        guard_home=tmp_path,
        enroll_extension_control_authority_by_default=lambda _digest: SimpleNamespace(health=AuthorityHealth.TAMPERED),
    )
    for _ in range(3):
        host = object.__new__(extension_control_host.ExtensionControlHost)
        host.store = store
        host._enroll_authority_by_default()

    assert recorded == [("default_authority_enrollment_skipped", "health=tampered failures=1")]


def test_a_protected_enrollment_after_a_skip_recovers(tmp_path, monkeypatch, ledger, recorded) -> None:
    views = iter([AuthorityHealth.TAMPERED, AuthorityHealth.PROTECTED, AuthorityHealth.PROTECTED])
    store = SimpleNamespace(
        guard_home=tmp_path,
        enroll_extension_control_authority_by_default=lambda _digest: SimpleNamespace(health=next(views)),
    )
    for _ in range(3):
        host = object.__new__(extension_control_host.ExtensionControlHost)
        host.store = store
        host._enroll_authority_by_default()

    assert recorded[-1] == ("default_authority_enrollment_recovered", "failures=1")
    # The second success in this process is already known; it asks nothing.
    assert ledger.calls.count(("outcome", background_loop_gate.AUTHORITY_ENROLLMENT)) == 2


def test_an_http_error_names_its_status_and_not_its_url() -> None:
    error = HTTPError("https://example.invalid/private/path?id=abc", 404, "Not Found", {}, None)  # type: ignore[arg-type]

    detail = failure_detail(error)

    assert detail == "error=HTTPError detail=HTTP 404 Not Found"


def test_doctor_drops_a_malformed_status(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        background_loop_gate,
        "_ask",
        lambda *_args, **_kwargs: {"ok": True, "loops": [{"loop": "catalog_publication_refresh", "state": "odd"}]},
    )
    assert background_loop_gate.loop_status(tmp_path) is None


def test_doctor_reports_each_loop(monkeypatch, tmp_path) -> None:
    failing = {
        "loop": "catalog_publication_refresh",
        "state": "failing",
        "failures": 4,
        "failing_for_seconds": 3600,
        "next_attempt_in_seconds": 1200,
    }
    healthy = [{"loop": name, "state": "healthy"} for name in background_loop_gate.LOOPS[1:]]
    monkeypatch.setattr(
        background_loop_gate, "_ask", lambda *_args, **_kwargs: {"ok": True, "loops": [failing, *healthy]}
    )
    assert background_loop_gate.loop_status(tmp_path) == [failing, *healthy]


def _runtime_binary() -> Path | None:
    configured = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    return Path(configured) if configured and Path(configured).is_file() else None


@pytest.mark.skipif(_runtime_binary() is None, reason="needs the native runtime binary")
def test_the_runtime_ledger_holds_a_failing_loop_across_processes(tmp_path) -> None:
    binary = _runtime_binary()
    assert binary is not None

    def ask(**fields: object) -> dict[str, object]:
        request = {"schema": "hol-guard-background-loop-gate.v1", "guard_home": str(tmp_path), **fields}
        completed = subprocess.run(
            [str(binary), "background-loop-gate", "--stdin"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)

    loop = background_loop_gate.CATALOG_REFRESH
    assert ask(op="attempt", loop=loop)["run"] is True
    assert ask(op="outcome", loop=loop, failure_key="refresh_failed")["log"] is True
    # A new process, as a restarted library process is.
    assert ask(op="attempt", loop=loop)["run"] is False
    assert ask(op="outcome", loop=loop, failure_key="refresh_failed")["log"] is False
    status = ask(op="status")["loops"]
    assert status[0]["state"] == "failing"
    assert status[0]["failures"] == 2
