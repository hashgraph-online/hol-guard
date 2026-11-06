"""A failing catalog preparation must leave a record and a distinguishable code.

3.50.0 shipped with a macOS bundle whose sealed manifests disagreed, so
``load_installed_bundle()`` raised on every call. The preparation worker
swallowed it, ``daemon.log`` held no catalog record at all, and every v2 read
answered the same 503 a cold start answers. These tests pin both halves of the
fix: the failure is recorded, and a preparation that keeps failing is reported
with its own code instead of the one a starting daemon uses.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_catalog_read as native
from codex_plugin_scanner.guard.catalog_delivery import (
    active_security,
    current_refresh,
    discovery,
    installed_bundle,
    transport,
)
from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.catalog_delivery.lifecycle import NativePackLifecycleUnavailableError
from codex_plugin_scanner.guard.daemon import background_diagnostics
from codex_plugin_scanner.guard.daemon.diagnostics import DaemonDiagnostics


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    """Isolated discovery module state that starts no background IO of its own."""

    home = (tmp_path / "home").absolute()
    for field, value in dict(
        _home=home, _worker=None, _handle=None, _retry_after=0.0, _failures=0, _noted_engine_mismatch=None
    ).items():
        monkeypatch.setattr(discovery, field, value)
    monkeypatch.setattr(discovery, "_cached", None)
    monkeypatch.setattr(discovery, "request_refresh", lambda *_args, **_kwargs: None)
    # The worker loads the installed bundle before it prepares. These tests are
    # about what happens to a preparation failure, so the load is made to
    # succeed and the failure is injected into `prepare_discovery` itself.
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", lambda: object())
    return home


@pytest.fixture
def sink():
    """Install a background sink for one test and release it afterwards."""

    installed: list[background_diagnostics.BackgroundSink] = []

    def install(target: background_diagnostics.BackgroundSink) -> None:
        background_diagnostics.install_sink(target)
        installed.append(target)

    yield install
    for target in installed:
        background_diagnostics.release_sink(target)


@pytest.fixture
def recorded(sink):
    events: list[tuple[str, str]] = []
    sink(lambda event, detail: events.append((event, detail)))
    return events


def fail_preparation(monkeypatch, error: BaseException) -> None:
    def raise_error(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(discovery, "prepare_discovery", raise_error)


def test_preparation_failure_is_recorded_with_its_exception(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("source compiler manifest size does not match the executable"))

    discovery._prepare_ready(prepared)

    assert recorded == [
        (
            "catalog_preparation_failed",
            "error=ValueError detail=source compiler manifest size does not match the executable",
        )
    ]


def test_preparation_failure_stays_non_fatal_and_keeps_its_backoff(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, OSError("unreadable"))
    started = time.monotonic()

    discovery._prepare_ready(prepared)

    assert discovery._handle is None
    assert discovery._worker is None
    # The one-second backoff the worker has always applied after a failure.
    assert discovery._retry_after >= started + 1.0
    assert recorded and recorded[0][0] == "catalog_preparation_failed"


def test_recorded_detail_carries_no_path(prepared, recorded, monkeypatch) -> None:
    secret = Path.home() / ".ssh/id_ed25519"
    fail_preparation(monkeypatch, ValueError(f"installed bundle metadata unavailable: no such file: '{secret}'"))

    discovery._prepare_ready(prepared)

    (_event, detail) = recorded[0]
    assert "<path>" in detail
    assert "id_ed25519" not in detail
    assert str(Path.home()) not in detail


def test_a_quoted_path_with_spaces_is_redacted_whole(prepared, recorded, monkeypatch) -> None:
    secret = Path.home() / "Client Records" / "tax return 2025.pdf"
    fail_preparation(monkeypatch, ValueError(f"installed bundle metadata unavailable: '{secret}' missing"))

    discovery._prepare_ready(prepared)

    (_event, detail) = recorded[0]
    assert "Client" not in detail
    assert "return" not in detail
    assert detail.endswith("unavailable: <path> missing")


def test_an_os_error_detail_never_carries_its_file_name(prepared, recorded, monkeypatch) -> None:
    secret = Path.home() / "Client Records" / "tax return 2025.pdf"
    fail_preparation(monkeypatch, FileNotFoundError(2, "No such file or directory", str(secret)))

    discovery._prepare_ready(prepared)

    (_event, detail) = recorded[0]
    assert detail == "error=FileNotFoundError detail=[Errno 2] No such file or directory"


def test_recorded_detail_is_bounded(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("x" * 4096))

    discovery._prepare_ready(prepared)

    (_event, detail) = recorded[0]
    assert len(detail) <= background_diagnostics._MAX_FAILURE_DETAIL + 32


def test_a_failure_reaches_the_daemon_log(prepared, tmp_path, sink, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    diagnostics = DaemonDiagnostics(guard_home, start_worker=False, rotate=False)
    sink(diagnostics.record_background)
    fail_preparation(monkeypatch, ValueError("source compiler manifest size does not match the executable"))

    discovery._prepare_ready(prepared)
    assert diagnostics.close(timeout_seconds=5.0)

    written = [json.loads(line) for line in diagnostics.log_path.read_text(encoding="utf-8").splitlines() if line]
    records = [entry for entry in written if entry["event"] == "catalog_preparation_failed"]
    assert len(records) == 1
    assert records[0]["level"] == "error"
    assert records[0]["detail"].startswith("error=ValueError detail=source compiler manifest")
    # A traceback would disclose the absolute paths of the install.
    assert "exception" not in records[0]


def test_a_publication_refresh_failure_is_recorded(prepared, recorded, monkeypatch) -> None:
    def unavailable(_store):
        raise RuntimeError("no complete view")

    monkeypatch.setattr(current_refresh, "refresh", unavailable)
    monkeypatch.setattr(current_refresh, "restore", unavailable)

    discovery._refresh(prepared, SimpleNamespace())

    assert [event for event, _detail in recorded] == [
        "catalog_publication_refresh_failed",
        "catalog_publication_restore_failed",
    ]
    assert discovery._refresh_worker is None


def test_the_refresh_cause_is_recorded_when_restore_also_fails(prepared, recorded, monkeypatch) -> None:
    def refresh_fails(_store):
        raise ValueError("discovery_current_authenticated_publication_required")

    def nothing_retained(_store):
        raise ValueError("discovery_current_cached_publication_unavailable")

    monkeypatch.setattr(current_refresh, "refresh", refresh_fails)
    monkeypatch.setattr(current_refresh, "restore", nothing_retained)

    discovery._refresh(prepared, SimpleNamespace())

    assert recorded == [
        (
            "catalog_publication_refresh_failed",
            "error=ValueError detail=discovery_current_authenticated_publication_required",
        ),
        (
            "catalog_publication_restore_failed",
            "error=ValueError detail=discovery_current_cached_publication_unavailable",
        ),
    ]


def test_a_restored_view_records_nothing(prepared, recorded, monkeypatch) -> None:
    def refresh_fails(_store):
        raise ValueError("offline")

    monkeypatch.setattr(current_refresh, "refresh", refresh_fails)
    monkeypatch.setattr(current_refresh, "restore", lambda _store: None)

    discovery._refresh(prepared, SimpleNamespace())

    assert recorded == []


def test_a_cold_start_still_reports_preparing(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("installed bundle container invalid"))

    with pytest.raises(ValueError) as first:
        discovery.installed_discovery(prepared)
    assert str(first.value) == discovery.PREPARING
    discovery._worker.join(30)

    with pytest.raises(ValueError) as again:
        discovery.installed_discovery(prepared)
    assert str(again.value) == discovery.PREPARING


def test_repeated_failure_reports_a_failing_preparation(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("installed bundle container invalid"))

    for _attempt in range(discovery.PERSISTENT_PREPARATION_FAILURES):
        monkeypatch.setattr(discovery, "_retry_after", 0.0)
        with pytest.raises(ValueError):
            discovery.installed_discovery(prepared)
        worker = discovery._worker
        if worker is not None:
            worker.join(30)

    # Hold off the next attempt so this read sees only the failures above.
    monkeypatch.setattr(discovery, "_retry_after", time.monotonic() + 300.0)
    with pytest.raises(ValueError) as raised:
        discovery.installed_discovery(prepared)

    assert str(raised.value) == discovery.PREPARATION_FAILING
    assert len(recorded) == discovery.PERSISTENT_PREPARATION_FAILURES


def test_a_success_clears_the_failure_count(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("installed bundle container invalid"))
    for _attempt in range(discovery.PERSISTENT_PREPARATION_FAILURES):
        discovery._prepare_ready(prepared)
    assert discovery._failures == discovery.PERSISTENT_PREPARATION_FAILURES

    handle = object()
    monkeypatch.setattr(discovery, "prepare_discovery", lambda *_args, **_kwargs: handle)
    discovery._prepare_ready(prepared)

    assert discovery._failures == 0
    assert discovery.installed_discovery(prepared) is handle


@pytest.mark.parametrize("message", sorted(discovery._RETRYABLE_FAILURES))
def test_a_restarting_resident_never_counts_as_a_failing_preparation(prepared, recorded, monkeypatch, message) -> None:
    fail_preparation(monkeypatch, ValueError(message))

    for _attempt in range(discovery.PERSISTENT_PREPARATION_FAILURES + 1):
        discovery._prepare_ready(prepared)

    assert discovery._failures == 0
    monkeypatch.setattr(discovery, "_retry_after", time.monotonic() + 300.0)
    with pytest.raises(ValueError) as raised:
        discovery.installed_discovery(prepared)
    assert str(raised.value) == discovery.PREPARING


def test_a_refreshed_view_clears_an_older_failure_streak(prepared, recorded, monkeypatch) -> None:
    fail_preparation(monkeypatch, ValueError("installed bundle container invalid"))
    for _attempt in range(discovery.PERSISTENT_PREPARATION_FAILURES):
        discovery._prepare_ready(prepared)
    handle = object()
    monkeypatch.setattr(current_refresh, "refresh", lambda _store: handle)

    discovery._refresh(prepared, SimpleNamespace())
    assert discovery._handle is handle
    discovery.invalidate(prepared, handle)

    monkeypatch.setattr(discovery, "_retry_after", time.monotonic() + 300.0)
    with pytest.raises(ValueError) as raised:
        discovery.installed_discovery(prepared)
    assert str(raised.value) == discovery.PREPARING


def test_the_read_path_matches_the_message_discovery_raises() -> None:
    assert native.DISCOVERY_PREPARATION_FAILING == discovery.PREPARATION_FAILING


@pytest.mark.parametrize(
    ("raised", "code"),
    [
        (discovery.PREPARING, "catalog_read_model_unavailable"),
        (discovery.PREPARATION_FAILING, native.CATALOG_READ_PREPARATION_FAILED),
    ],
)
def test_a_failing_preparation_has_its_own_terminal_code(tmp_path, monkeypatch, raised, code) -> None:
    status = SimpleNamespace(
        identity=SimpleNamespace(path=tmp_path / "native"),
        capabilities=SimpleNamespace(features=[native.CATALOG_READ_FEATURE, native.CATALOG_DISCOVERY_FEATURE]),
    )
    monkeypatch.setattr(native, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native, "_supports_catalog_read", lambda _: True)
    sent: list[object] = []
    monkeypatch.setattr(native, "native_resident_client_request", lambda **kwargs: sent.append(kwargs))
    monkeypatch.setattr(discovery, "installed_discovery", lambda _home: (_ for _ in ()).throw(ValueError(raised)))

    result = native.native_catalog_read(
        guard_home=tmp_path, route="index", query="", if_none_match=None, expected_catalog_digest="b" * 64
    )

    # Neither answer is protocol absence: a 501 would send the page to v1 and
    # hide a broken installed runtime behind a rendered catalog.
    assert result is not None
    assert (result.status, result.error_code) == (503, code)
    assert not sent


# A released core meets a publication built from a later `main` with another
# compiler. This is the message 3.57.0a1 recorded for it every five minutes.
ENGINE_REFUSAL = (
    "native_pack_lifecycle_unavailable: source compiler returned invalid JSON: discovery_current_engine_incompatible"
)


def publication(publication_id: str) -> bytes:
    return json.dumps(
        {
            "schema": "guard.extension-distribution.v2",
            "publication_id": publication_id,
            "source_sha": "5bd0275611" + "0" * 30,
            "engine": "1361572645852941" + "0" * 48,
        }
    ).encode()


@pytest.fixture
def observed():
    """Failures and notices from one background sink pair, released afterwards."""

    errors: list[tuple[str, str]] = []
    notices: list[tuple[str, str]] = []

    def failure(event: str, detail: str) -> None:
        errors.append((event, detail))

    background_diagnostics.install_sink(failure, notice=lambda event, detail: notices.append((event, detail)))
    yield SimpleNamespace(errors=errors, notices=notices)
    background_diagnostics.release_sink(failure)


def refreshing_into(monkeypatch, tmp_path, refusal: str) -> None:
    """Run the real `refresh` up to the native publication check, which refuses."""

    authority = object.__new__(VerifiedDistribution)
    object.__setattr__(authority, "data", publication("40151296356.1"))
    monkeypatch.setattr(current_refresh, "_capture", lambda _store: ("floor", "cursor", "security"))
    monkeypatch.setattr(current_refresh, "_cache", lambda _store, name: tmp_path / name)
    monkeypatch.setattr(transport, "fetch_root", lambda **_kwargs: authority)
    monkeypatch.setattr(active_security, "observe_preparation", lambda _store, _authority: None)

    def invoke(_store, _captured, **fields):
        if "publication" in fields:
            raise NativePackLifecycleUnavailableError(refusal)
        return {}

    monkeypatch.setattr(current_refresh, "_invoke", invoke)


def test_a_publication_for_another_engine_names_itself(monkeypatch, tmp_path) -> None:
    refreshing_into(monkeypatch, tmp_path, ENGINE_REFUSAL)

    with pytest.raises(current_refresh.PublicationEngineMismatchError) as raised:
        current_refresh.refresh(SimpleNamespace())

    assert raised.value.describe() == "publication=40151296356.1 source=5bd027561100 engine=136157264585"
    assert isinstance(raised.value.__cause__, NativePackLifecycleUnavailableError)


def test_any_other_native_refusal_keeps_its_own_error(monkeypatch, tmp_path) -> None:
    refreshing_into(monkeypatch, tmp_path, "native_pack_lifecycle_unavailable: discovery_current_authority_expired")

    with pytest.raises(NativePackLifecycleUnavailableError, match="discovery_current_authority_expired"):
        current_refresh.refresh(SimpleNamespace())


def mismatched(monkeypatch, current: dict[str, str], restore_error: str) -> None:
    def refresh(_store):
        raise current_refresh.PublicationEngineMismatchError(publication(current["id"]))

    def restore(_store):
        raise ValueError(restore_error)

    monkeypatch.setattr(current_refresh, "refresh", refresh)
    monkeypatch.setattr(current_refresh, "restore", restore)


def test_an_engine_mismatch_with_nothing_kept_is_noted_once_per_publication(prepared, observed, monkeypatch) -> None:
    current = {"id": "40151296356.1"}
    mismatched(monkeypatch, current, "discovery_current_cached_publication_unavailable")

    discovery._refresh(prepared, SimpleNamespace())
    discovery._refresh(prepared, SimpleNamespace())
    current["id"] = "40160000000.1"
    discovery._refresh(prepared, SimpleNamespace())

    assert observed.errors == []
    assert observed.notices == [
        ("catalog_publication_engine_pending", "publication=40151296356.1 source=5bd027561100 engine=136157264585"),
        ("catalog_publication_engine_pending", "publication=40160000000.1 source=5bd027561100 engine=136157264585"),
    ]


def test_a_note_that_was_not_written_is_made_again(prepared, monkeypatch) -> None:
    mismatched(monkeypatch, {"id": "40151296356.1"}, "discovery_current_cached_publication_unavailable")
    # Before the daemon listens there is no sink at all.
    discovery._refresh(prepared, SimpleNamespace())
    notices: list[tuple[str, str]] = []

    def failure(_event: str, _detail: str) -> None:
        raise AssertionError("an engine mismatch is not a failure")

    def refused(_event: str, _detail: str) -> bool:
        # A full or closed daemon log queue answers False.
        return False

    try:
        background_diagnostics.install_sink(failure, notice=refused)
        discovery._refresh(prepared, SimpleNamespace())
        background_diagnostics.install_sink(failure, notice=lambda event, detail: notices.append((event, detail)))
        discovery._refresh(prepared, SimpleNamespace())
        discovery._refresh(prepared, SimpleNamespace())
    finally:
        background_diagnostics.release_sink(failure)

    assert [event for event, _detail in notices] == ["catalog_publication_engine_pending"]


def test_an_accepted_publication_clears_the_note(prepared, observed, monkeypatch) -> None:
    current = {"id": "40151296356.1"}
    mismatched(monkeypatch, current, "discovery_current_cached_publication_unavailable")
    discovery._refresh(prepared, SimpleNamespace())
    monkeypatch.setattr(current_refresh, "refresh", lambda _store: SimpleNamespace())
    discovery._refresh(prepared, SimpleNamespace())
    mismatched(monkeypatch, current, "discovery_current_cached_publication_unavailable")
    discovery._refresh(prepared, SimpleNamespace())

    assert len(observed.notices) == 2
    assert observed.errors == []


def test_an_engine_mismatch_with_a_broken_cache_is_still_a_failure(prepared, observed, monkeypatch) -> None:
    mismatched(monkeypatch, {"id": "40151296356.1"}, "discovery_current_cache_invalid")

    discovery._refresh(prepared, SimpleNamespace())

    assert observed.notices == []
    assert observed.errors == [
        (
            "catalog_publication_refresh_failed",
            "error=PublicationEngineMismatchError detail=discovery_current_engine_incompatible",
        ),
        ("catalog_publication_restore_failed", "error=ValueError detail=discovery_current_cache_invalid"),
    ]


def test_an_engine_mismatch_reaches_the_daemon_log_as_info(prepared, tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    diagnostics = DaemonDiagnostics(guard_home, start_worker=False, rotate=False)
    background_diagnostics.install_sink(diagnostics.record_background, notice=diagnostics.record_background_notice)
    try:
        mismatched(monkeypatch, {"id": "40151296356.1"}, "discovery_current_cached_publication_unavailable")
        discovery._refresh(prepared, SimpleNamespace())
    finally:
        assert diagnostics.close(timeout_seconds=5.0)

    written = [json.loads(line) for line in diagnostics.log_path.read_text(encoding="utf-8").splitlines() if line]
    catalog = [entry for entry in written if entry["event"].startswith("catalog_")]
    assert [(entry["event"], entry["level"]) for entry in catalog] == [("catalog_publication_engine_pending", "info")]
    # Closing the daemon releases the notice sink with the failure sink.
    assert background_diagnostics.record_background_notice("catalog_publication_engine_pending", "x") is False
