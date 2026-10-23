"""A failed protection change must name its cause and leave a record."""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error
from pathlib import Path

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
from codex_plugin_scanner.guard.daemon.extension_control_preparation_failure import (
    classify,
    preparation_unavailable,
)
from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
    NativeRequestTooLargeError,
    NativeSourceCompilerError,
)

_CAUSES = (
    "installed_runtime_incomplete",
    "installed_runtime_unresponsive",
    "internal",
    "local_storage",
    "native_request_too_large",
    "offline",
    "pack_authority_unavailable",
    "pack_revoked",
    "release_unavailable",
)


def _wrapped(error: BaseException) -> ValueError:
    """Rebuild the chain preparation raises: a ValueError over the real failure."""

    try:
        raise error
    except BaseException as exc:
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
        # A request the runtime will not read says nothing about the installed
        # files, so it must not land on the broken-install verdict.
        (
            _wrapped(NativeRequestTooLargeError("compiler request exceeds the native input bound")),
            "native_request_too_large",
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


def test_an_oversized_native_request_is_not_answered_with_a_reinstall():
    """The payload is built from local data, so reinstalling cannot shrink it.

    This is the failure a real install hit: the runtime refused the request,
    the compiler reported unreadable JSON, and the classifier fell through to
    `installed_runtime_incomplete`, whose action is `repair_guard_installation`.
    """

    error = preparation_unavailable(
        _wrapped(NativeRequestTooLargeError("source compiler refused the request as too large")),
        stage="candidate-preparation",
    )
    assert error.to_payload() == {
        "error": "pack_preparation_unavailable",
        "cause": "native_request_too_large",
        "recovery": {"action": "inspect_daemon_log"},
    }


def test_the_daemon_log_records_the_request_that_grew_and_by_how_much(monkeypatch):
    """The dashboard sends the operator to the log, so the log has to answer.

    `native_request_too_large` is the one cause with no retry and no command
    behind it, so the sentence the operator reads points at the daemon log
    instead. That is only worth doing if the record names the request and the
    size it reached; a bare cause code repeats what they already saw.
    """

    from codex_plugin_scanner.guard.catalog_delivery import lifecycle
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

    monkeypatch.setattr(lifecycle._Session, "executable", lambda self: Path("/nonexistent/hol-guard-runtime"))

    def refuse(*args, **kwargs):
        raise AssertionError("a request past the lifecycle bound must not reach Popen")

    monkeypatch.setattr(transport.subprocess, "Popen", refuse)

    with pytest.raises(ValueError) as raised:
        lifecycle.invoke("preparation", history="x" * (transport._MAX_NATIVE_REQUEST_BYTES + 1))

    taken = _recorded(raised.value)
    assert len(taken) == 1
    _event, detail = taken[0]
    assert "cause=native_request_too_large" in detail
    assert "pack-lifecycle request is" in detail
    assert f"past the {transport._MAX_NATIVE_REQUEST_BYTES} byte native input bound" in detail


def test_a_lifecycle_request_the_compiler_bound_would_have_passed_is_still_refused(monkeypatch):
    """The two subcommands are read against different bounds.

    `pack-lifecycle` is read by the runtime's own stdin reader at 6 MiB, while
    the compiler front end reads 8 MiB. A request between the two is one the
    runtime refuses, so holding the lifecycle path to the larger number sends a
    process that is certain to fail and reports the refusal as a broken install.
    """

    from codex_plugin_scanner.guard.catalog_delivery import lifecycle
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

    assert transport._MAX_NATIVE_REQUEST_BYTES < transport._MAX_REQUEST_BYTES

    monkeypatch.setattr(lifecycle._Session, "executable", lambda self: Path("/nonexistent/hol-guard-runtime"))

    def refuse(*args, **kwargs):
        raise AssertionError("a request past the lifecycle bound must not reach Popen")

    monkeypatch.setattr(transport.subprocess, "Popen", refuse)

    between = "x" * (transport._MAX_NATIVE_REQUEST_BYTES + 1024)
    assert len(between) < transport._MAX_REQUEST_BYTES

    with pytest.raises(ValueError) as raised:
        lifecycle.invoke("preparation", history=between)

    payload = preparation_unavailable(raised.value, stage="candidate-preparation").to_payload()
    assert payload["cause"] == "native_request_too_large"
    assert payload["recovery"] == {"action": "inspect_daemon_log"}


def test_a_request_past_the_bound_reaches_that_answer_through_the_lifecycle_adapter(monkeypatch):
    """Drive the real adapter, which encodes its own JSON and spawns directly."""

    from codex_plugin_scanner.guard.catalog_delivery import lifecycle
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

    # Stand in for the verified executable so the request itself, not the
    # packaged runtime this checkout may not carry, decides the outcome.
    monkeypatch.setattr(lifecycle._Session, "executable", lambda self: Path("/nonexistent/hol-guard-runtime"))

    def refuse(*args, **kwargs):
        raise AssertionError("a request past the bound must not reach Popen")

    monkeypatch.setattr(transport.subprocess, "Popen", refuse)

    with pytest.raises(ValueError) as raised:
        lifecycle.invoke("preparation", history="x" * (transport._MAX_NATIVE_REQUEST_BYTES + 1))

    error = preparation_unavailable(raised.value, stage="candidate-preparation")
    payload = error.to_payload()
    assert payload["cause"] == "native_request_too_large"
    assert payload["recovery"] == {"action": "inspect_daemon_log"}
    assert payload["recovery"] != {"action": "repair_guard_installation"}


def test_a_release_root_the_runtime_refuses_is_not_answered_with_a_reinstall(monkeypatch):
    """A refused root names bad release data, not a broken installation."""

    from codex_plugin_scanner.guard.catalog_delivery import authority, lifecycle
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

    monkeypatch.setattr(lifecycle._Session, "executable", lambda self: Path("/nonexistent/hol-guard-runtime"))
    refusal = (1, b'{"code":"distribution_identity_invalid"}', b"")
    monkeypatch.setattr(transport, "_run_bounded", lambda *args, **kwargs: refusal)

    with pytest.raises(ValueError, match="identity") as raised:
        authority._native("root", data="{}", source="0" * 40, now=0)

    assert not any(isinstance(error, NativeSourceCompilerError) for error in _chain(raised.value))
    assert classify(raised.value) not in {"installed_runtime_incomplete", "installed_runtime_unresponsive"}


def _chain(error):
    while error is not None:
        yield error
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
