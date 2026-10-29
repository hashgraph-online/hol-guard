from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli import doctor_native_runtime
from codex_plugin_scanner.guard.cli.render import _render_doctor
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus

JOURNAL_SCHEMA = "hol-guard-resident-lifecycle-journal.v1"
JOURNAL_FILE = "lifecycle-journal.json"
HOUR_MS = 60 * 60 * 1000


def _snapshot(**overrides: Any) -> dict[str, Any]:
    """A reply shaped the way the runtime's ``resident-health`` prints one."""

    health = {
        "state": "degraded",
        "starts": 7,
        "orderly_exits": 3,
        "failed_exits": 3,
        "premature_exits": 1,
        "refused_starts": 0,
        "last_event": "exited_failed",
        "last_event_age_seconds": 120,
        "window_age_seconds": 7200,
    }
    health.update(overrides)
    return health


def _installed(monkeypatch: pytest.MonkeyPatch, answer: str | None, *, asked: list[tuple[str, ...]] | None = None):
    identity = NativeRuntimeIdentity(path=Path("/opt/guard/hol-guard-runtime"), size=1, mtime_ns=2, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_available", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)

    def run(path: Path, args: tuple[str, ...], **_: Any) -> str | None:
        if asked is not None:
            asked.append(args)
        return answer

    monkeypatch.setattr(native_runtime, "_run_native_process", run)


def _never_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*_: Any, **__: Any) -> str | None:
        raise AssertionError("a passive report must not run the runtime")

    monkeypatch.setattr(native_runtime, "_run_native_process", run)


def test_the_runtime_answers_the_day_and_doctor_reports_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    asked: list[tuple[str, ...]] = []
    _installed(monkeypatch, json.dumps({"health": _snapshot()}), asked=asked)

    lifecycle = doctor_native_runtime.native_resident_lifecycle(tmp_path)

    assert lifecycle == _snapshot()
    assert asked == [("resident-health", "--state-dir", str(tmp_path / "native-runtime"))]


def test_a_read_only_caller_never_asks_for_the_journal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``runtime status`` and the global doctor promise never to run the binary."""

    _installed(monkeypatch, json.dumps({"health": _snapshot()}))
    _never_run(monkeypatch)

    with without_command_probes():
        assert doctor_native_runtime.native_resident_lifecycle(tmp_path) is None


def test_an_install_with_no_home_has_no_journal_to_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(monkeypatch, json.dumps({"health": _snapshot()}))
    _never_run(monkeypatch)

    assert doctor_native_runtime.native_resident_lifecycle(None) is None


@pytest.mark.parametrize(
    ("available", "compatible"),
    [(False, False), (True, False)],
)
def test_a_runtime_that_cannot_serve_is_never_run_for_a_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, available: bool, compatible: bool
) -> None:
    identity = NativeRuntimeIdentity(path=Path("/opt/guard/hol-guard-runtime"), size=1, mtime_ns=2, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto",
        available=available,
        compatible=compatible,
        reason="native_binary_missing",
        identity=identity if available else None,
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    _never_run(monkeypatch)

    assert doctor_native_runtime.native_resident_lifecycle(tmp_path) is None


@pytest.mark.parametrize("exception", [OSError, RuntimeError, ValueError])
def test_a_failed_read_leaves_the_report_without_a_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exception: type[Exception]
) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=1, mtime_ns=2, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_available", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)

    def run(*_: Any, **__: Any) -> str | None:
        raise exception("/private/user/native-secret")

    monkeypatch.setattr(native_runtime, "_run_native_process", run)

    assert doctor_native_runtime.native_resident_lifecycle(tmp_path) is None


@pytest.mark.parametrize(
    "answer",
    [
        None,
        "",
        "not json",
        "[]",
        json.dumps({}),
        json.dumps({"health": None}),
        json.dumps({"health": "degraded"}),
        # A state the renderer has no copy for, and codes outside the runtime's
        # vocabulary: a path, an overlong one, and an invented code that would
        # otherwise read as a sentence of its own in the panel.
        json.dumps({"health": _snapshot(state="failing")}),
        json.dumps({"health": _snapshot(last_event="/private/user/run.log")}),
        json.dumps({"health": _snapshot(last_event="x" * 65)}),
        json.dumps({"health": _snapshot(last_event="your_runtime_is_infected")}),
        json.dumps({"health": _snapshot(last_event="EXITED_FAILED")}),
        # A code that is not text at all: the vocabulary is a set, so this
        # has to be refused rather than hashed.
        json.dumps({"health": _snapshot(last_event=[])}),
        json.dumps({"health": _snapshot(last_event={})}),
        json.dumps({"health": _snapshot(last_event=3)}),
        # Counts and ages outside what the runtime can produce.
        json.dumps({"health": _snapshot(starts=-1)}),
        json.dumps({"health": _snapshot(starts=2**32)}),
        json.dumps({"health": _snapshot(failed_exits=True)}),
        json.dumps({"health": _snapshot(window_age_seconds=26 * 60 * 60)}),
        json.dumps({"health": _snapshot(last_event_age_seconds="recent")}),
        # A field added or dropped is a file this reader does not know.
        json.dumps({"health": _snapshot(stderr="boom")}),
        json.dumps({"health": {key: value for key, value in _snapshot().items() if key != "starts"}}),
    ],
)
def test_a_damaged_or_forged_journal_never_reaches_the_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: str | None
) -> None:
    _installed(monkeypatch, answer)

    assert doctor_native_runtime.native_resident_lifecycle(tmp_path) is None


def test_the_section_carries_the_journal_and_no_private_detail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _installed(monkeypatch, json.dumps({"health": _snapshot()}))
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "0" * 64)

    section = doctor_native_runtime.native_runtime_section(tmp_path)

    assert section["lifecycle"] == _snapshot()
    encoded = json.dumps(section["lifecycle"])
    assert "/" not in encoded
    assert "opt" not in encoded


def _rendered(lifecycle: object) -> str:
    stream = StringIO()
    console = Console(file=stream, width=100, color_system=None)
    _render_doctor(console, {"tables": [], "native_runtime": {"lifecycle": lifecycle}})
    return " ".join(stream.getvalue().split())


def test_a_degraded_day_is_reported_even_while_the_runtime_is_up() -> None:
    output = _rendered(_snapshot())

    assert "Native runtime unhealthy today" in output
    assert "7 starts, 3 ended cleanly, 3 failed, 1 stopped early, 0 starts refused." in output
    assert "Last event: exited_failed, 2m ago." in output
    assert "hol-guard runtime status" in output


def test_a_runtime_that_is_not_being_restarted_is_reported_as_such() -> None:
    output = _rendered(_snapshot(state="critical", last_event="start_refused", last_event_age_seconds=7400))

    assert "Native runtime not restarting" in output
    assert "Last event: start_refused, 2h ago." in output


@pytest.mark.parametrize("lifecycle", [_snapshot(state="healthy"), "degraded", None, {}])
def test_a_healthy_or_absent_journal_says_nothing(lifecycle: object) -> None:
    output = _rendered(lifecycle)

    assert "Native runtime" not in output


def test_a_journal_with_no_event_left_to_name_prints_the_counts_alone() -> None:
    output = _rendered(_snapshot(last_event="", last_event_age_seconds=0))

    assert "Native runtime unhealthy today" in output
    assert "Last event" not in output


def _forced_runtime(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make the caller-pinned runtime the one doctor reads, as hook tests do."""

    runtime = Path(os.environ["HOL_GUARD_NATIVE_BINARY"]).resolve(strict=True)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    return runtime


@pytest.mark.skipif(
    not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file(),
    reason="needs HOL_GUARD_NATIVE_BINARY for the compiled runtime",
)
def test_the_compiled_runtime_reads_a_planted_journal_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real binary, the real state layout, no doubles in between."""

    binary = _forced_runtime(monkeypatch)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    guard_home = tmp_path / "home"
    scope = guard_home / "native-runtime" / f"resident-v3-{digest[:16]}"
    scope.mkdir(parents=True)
    for directory in (guard_home, guard_home / "native-runtime", scope):
        directory.chmod(stat.S_IRWXU)
    now_ms = int(time.time() * 1000)
    journal = scope / JOURNAL_FILE
    journal.write_text(
        json.dumps(
            {
                "schema": JOURNAL_SCHEMA,
                "hours": [
                    {
                        "hour": now_ms // HOUR_MS,
                        "starts": 4,
                        "orderly_exits": 1,
                        "failed_exits": 2,
                        "premature_exits": 1,
                        "refused_starts": 0,
                    }
                ],
                "last_event": "exited_failed",
                "last_event_ms": now_ms,
            }
        ),
        encoding="utf-8",
    )
    journal.chmod(stat.S_IRUSR | stat.S_IWUSR)

    lifecycle = doctor_native_runtime.native_resident_lifecycle(guard_home)

    assert lifecycle is not None
    assert lifecycle["state"] == "degraded"
    assert lifecycle["starts"] == 4
    assert lifecycle["failed_exits"] == 2
    assert lifecycle["premature_exits"] == 1
    assert lifecycle["last_event"] == "exited_failed"
    assert lifecycle["last_event_age_seconds"] < 60
    assert "Native runtime unhealthy today" in _rendered(lifecycle)


@pytest.mark.skipif(
    not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file(),
    reason="needs HOL_GUARD_NATIVE_BINARY for the compiled runtime",
)
def test_an_install_with_no_history_reports_no_journal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forced_runtime(monkeypatch)
    guard_home = tmp_path / "home"
    guard_home.mkdir()
    guard_home.chmod(stat.S_IRWXU)

    assert doctor_native_runtime.native_resident_lifecycle(guard_home) is None
