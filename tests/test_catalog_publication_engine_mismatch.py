"""A cached publication built by another compiler is expected skew, not a failure.

A released core reads publications produced by `main`. When `main` moves to a
newer source compiler, the core meets a publication whose engine it cannot
read, and both the refresh and the cached restore answer
``discovery_current_engine_incompatible``. 3.57.0a1 wrote that pair to
``daemon.log`` as a failure every five minutes. These tests pin the shape of
the fix: the skew carries its own error with the publication named, every
other native refusal keeps its own error, and the daemon records one notice per
publication instead of a failure pair per timer tick.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    active_security,
    current_refresh,
    discovery,
    installed_bundle,
    transport,
)
from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.catalog_delivery.lifecycle import NativePackLifecycleUnavailableError
from codex_plugin_scanner.guard.runtime_health import background_diagnostics
from codex_plugin_scanner.guard.runtime_health.diagnostics import DaemonDiagnostics


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
    # The worker loads the installed bundle before it refreshes, and these
    # tests are about the refresh, so the load is made to succeed.
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", lambda: object())
    return home


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


def restoring_into(monkeypatch, tmp_path, refusal: str) -> None:
    """Run the real `restore` up to the native publication check, which refuses."""

    authority = object.__new__(VerifiedDistribution)
    object.__setattr__(authority, "data", publication("40151296356.1"))
    monkeypatch.setattr(current_refresh, "_capture", lambda _store: ("floor", "cursor", "security"))
    monkeypatch.setattr(current_refresh, "_cache", lambda _store, name: tmp_path / name)
    monkeypatch.setattr(current_refresh, "_load", lambda _directory, _retained, now: authority)

    def invoke(_store, _captured, **fields):
        if "publication" in fields:
            raise NativePackLifecycleUnavailableError(refusal)
        return {"retained": {"root": "r", "source": "s"}}

    monkeypatch.setattr(current_refresh, "_invoke", invoke)


def test_a_cached_publication_for_another_engine_names_itself(monkeypatch, tmp_path) -> None:
    restoring_into(monkeypatch, tmp_path, ENGINE_REFUSAL)
    store = SimpleNamespace(_get_policy_integrity_secret_from_store=lambda _ref: None, _build_scoped_secret_ref=str)

    with pytest.raises(current_refresh.PublicationEngineMismatchError) as raised:
        current_refresh.restore(store)

    assert raised.value.describe() == "publication=40151296356.1 source=5bd027561100 engine=136157264585"
    assert isinstance(raised.value.__cause__, NativePackLifecycleUnavailableError)


def test_any_other_refusal_during_restore_keeps_its_own_error(monkeypatch, tmp_path) -> None:
    restoring_into(monkeypatch, tmp_path, "native_pack_lifecycle_unavailable: discovery_current_authority_expired")
    store = SimpleNamespace(_get_policy_integrity_secret_from_store=lambda _ref: None, _build_scoped_secret_ref=str)

    with pytest.raises(NativePackLifecycleUnavailableError, match="discovery_current_authority_expired"):
        current_refresh.restore(store)


def test_a_cached_publication_for_the_same_other_engine_is_noted_once(prepared, observed, monkeypatch) -> None:
    """A core released before the compiler changed keeps a cached publication it cannot read.

    Refresh and restore then both answer `discovery_current_engine_incompatible`,
    which is the same expected version skew as an empty cache and must not be
    logged as a failure pair on every five-minute timer tick.
    """

    def refresh(_store):
        raise current_refresh.PublicationEngineMismatchError(publication("40151296356.1"))

    def restore(_store):
        raise current_refresh.PublicationEngineMismatchError(publication("40140000000.1"))

    monkeypatch.setattr(current_refresh, "refresh", refresh)
    monkeypatch.setattr(current_refresh, "restore", restore)

    discovery._refresh(prepared, SimpleNamespace())
    discovery._refresh(prepared, SimpleNamespace())

    assert observed.errors == []
    assert observed.notices == [
        ("catalog_publication_engine_pending", "publication=40151296356.1 source=5bd027561100 engine=136157264585")
    ]
