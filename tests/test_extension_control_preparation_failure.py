"""A failed protection change must name its cause and leave a record."""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error

import pytest

from codex_plugin_scanner.guard.catalog_delivery.authority import ExpiredDistributionError
from codex_plugin_scanner.guard.catalog_delivery.preparation import UnavailablePackError
from codex_plugin_scanner.guard.catalog_delivery.revocations import RevokedPackError
from codex_plugin_scanner.guard.catalog_delivery.transport import MissingReleaseError
from codex_plugin_scanner.guard.daemon import background_diagnostics
from codex_plugin_scanner.guard.daemon.extension_control_errors import (
    _CAUSE_RECOVERY_ACTIONS,
    ExtensionControlApiError,
)
from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
    NativeSourceCompilerError,
)
from codex_plugin_scanner.guard.daemon.extension_control_preparation_failure import (
    classify,
    preparation_unavailable,
)


_CAUSES = (
    "installed_runtime_incomplete",
    "installed_runtime_unresponsive",
    "internal",
    "local_storage",
    "offline",
    "pack_authority_unavailable",
    "pack_revoked",
    "release_unavailable",
)


def _wrapped(error: BaseException) -> ValueError:
    """Rebuild the chain preparation raises: a ValueError over the real failure."""

    try:
        raise error
    except BaseException as exc:  # noqa: BLE001 - the chain is the point
        wrapper = ValueError(f"installed bundle metadata unavailable: {exc}")
        wrapper.__cause__ = exc
        return wrapper


@pytest.mark.parametrize(
    ("error", "cause"),
    [
        (urllib.error.URLError(OSError("unreachable")), "offline"),
        (socket.gaierror("name resolution failed"), "offline"),
        (ssl.SSLError("handshake failed"), "offline"),
        (ConnectionResetError("reset"), "offline"),
        (TimeoutError("timed out"), "offline"),
        # Guard storage raises a bare TimeoutError, which socket.timeout also
        # is, so only the wording tells a slow database from a dead network.
        (TimeoutError("Guard storage operation deadline expired."), "local_storage"),
        (_wrapped(TimeoutError("Guard storage operation deadline expired.")), "local_storage"),
        (urllib.error.HTTPError("https://example.invalid", 404, "missing", None, None), "release_unavailable"),
        (MissingReleaseError("no such release"), "release_unavailable"),
        (ExpiredDistributionError("expired"), "release_unavailable"),
        (UnavailablePackError("pack_absent"), "release_unavailable"),
        (RevokedPackError("command.git", 7), "pack_revoked"),
        (
            _wrapped(NativeSourceCompilerError("source compiler manifest is unavailable")),
            "installed_runtime_incomplete",
        ),
        (
            _wrapped(NativeSourceCompilerError("source compiler hash does not match its manifest")),
            "installed_runtime_incomplete",
        ),
        # The same exception type covers a process that would not start and one
        # that ran out of time. Neither is a broken install.
        (
            _wrapped(NativeSourceCompilerError("source compiler could not be started")),
            "installed_runtime_unresponsive",
        ),
        (
            _wrapped(NativeSourceCompilerError("source compiler timed out")),
            "installed_runtime_unresponsive",
        ),
        (ValueError("installed preparation authority is unavailable"), "pack_authority_unavailable"),
        (ValueError("pack_lifecycle_pack_authority_unavailable"), "pack_authority_unavailable"),
        (ValueError("committed subset requires an existing activation"), "pack_authority_unavailable"),
        (ValueError("target catalog shape invalid"), "internal"),
        (OSError("cache read failed"), "local_storage"),
        (RuntimeError("not a preparation failure"), "internal"),
    ],
)
def test_every_preparation_failure_is_classified(error, cause):
    assert classify(error) == cause


def _raised_while_handling(handled: BaseException, error: BaseException) -> BaseException:
    try:
        try:
            raise handled
        except BaseException:
            raise error  # noqa: B904 - deliberately left implicit
    except BaseException as exc:
        return exc


@pytest.mark.parametrize(
    ("error", "cause"),
    [
        (MissingReleaseError("no such release"), "release_unavailable"),
        (RevokedPackError("command.git", 7), "pack_revoked"),
        (_wrapped(RevokedPackError("command.git", 7)), "pack_revoked"),
    ],
)
def test_a_retried_network_error_does_not_hide_the_typed_failure(error, cause):
    assert classify(_raised_while_handling(ConnectionResetError("reset"), error)) == cause


def test_a_suppressed_context_is_not_a_cause():
    try:
        try:
            raise ConnectionResetError("reset")
        except ConnectionResetError:
            raise ValueError("target catalog shape invalid") from None
    except ValueError as exc:
        assert classify(exc) == "internal"


def test_failure_keeps_the_public_code_and_adds_a_cause_and_recovery():
    error = preparation_unavailable(OSError("cache read failed"), stage="candidate-preparation")
    assert isinstance(error, ExtensionControlApiError)
    assert error.status == 503
    assert error.code == "pack_preparation_unavailable"
    assert error.to_payload() == {
        "error": "pack_preparation_unavailable",
        "cause": "local_storage",
        "recovery": {"action": "repair_local_cache"},
    }


def test_an_unclassified_failure_still_offers_a_next_step():
    error = preparation_unavailable(ValueError("target catalog shape invalid"), stage="target-metadata")
    assert error.to_payload() == {
        "error": "pack_preparation_unavailable",
        "cause": "internal",
        "recovery": {"action": "inspect_daemon_log"},
    }


@pytest.mark.parametrize("cause", _CAUSES)
def test_every_cause_carries_its_own_recovery_action(cause):
    """The code-level fallback would tell a client to retry a withdrawn pack."""

    payload = ExtensionControlApiError(503, "pack_preparation_unavailable", cause=cause).to_payload()
    assert cause in _CAUSE_RECOVERY_ACTIONS
    assert payload["recovery"] == {"action": _CAUSE_RECOVERY_ACTIONS[cause]}


def test_a_withdrawn_pack_is_never_answered_with_a_retry():
    payload = ExtensionControlApiError(503, "pack_preparation_unavailable", cause="pack_revoked").to_payload()
    assert payload["recovery"] == {"action": "refresh_catalog"}


def test_the_real_exception_is_recorded_once_with_its_traceback(caplog):
    try:
        raise ValueError("installed preparation authority is unavailable")
    except ValueError as exc:
        with caplog.at_level(logging.ERROR):
            preparation_unavailable(exc, stage="candidate-preparation")
    records = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert len(records) == 1
    assert "candidate-preparation" in records[0].getMessage()
    assert "cause=pack_authority_unavailable" in records[0].getMessage()
    assert "ValueError" in records[0].getMessage()
    assert records[0].exc_info is not None


def _recorded(error: BaseException) -> list[tuple[str, str]]:
    """Run one failure through the sink the managed daemon installs."""

    taken: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        taken.append((event, detail))

    background_diagnostics.install_sink(sink)
    try:
        preparation_unavailable(error, stage="candidate-preparation")
    finally:
        background_diagnostics.release_sink(sink)
    return taken


def test_the_failure_reaches_the_daemon_log_not_only_python_logging():
    """The managed daemon discards stderr, so the record must go to its sink."""

    taken = _recorded(OSError("cache read failed"))
    assert len(taken) == 1
    event, detail = taken[0]
    assert event == "extension_control_preparation_failed"
    assert "stage=candidate-preparation" in detail
    assert "cause=local_storage" in detail
    assert "error=OSError" in detail


def test_the_daemon_record_carries_no_path():
    taken = _recorded(OSError("/Users/someone/.hol-guard/command-packs is unreadable"))
    assert "/Users" not in taken[0][1]


def test_the_cause_never_quotes_the_exception_message():
    error = preparation_unavailable(OSError("/Users/someone/.hol-guard/command-packs is unreadable"), stage="s")
    assert "/Users" not in repr(error.to_payload())
