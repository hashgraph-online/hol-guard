from __future__ import annotations

import io
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.native_resident_decision import ResidentCallError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    ExtensionControlMutation,
    ExtensionControlProofError,
    _require_local_terminal_confirmation,
    _terminal_descriptors_share_session,
    _windows_console_descriptor_is_interactive,
    _windows_session_probe,
    consume_extension_control_enrollment_proof,
    consume_extension_control_proof,
    issue_extension_control_enrollment_proof,
    issue_extension_control_proof,
)

_PASSWORD = "correct horse battery staple"
_NOW = "2026-07-20T12:00:00+00:00"


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _guard_home, _enrollment: None,
    )


def _configure(guard_home: Path) -> None:
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
        now=_NOW,
    )


def _enrollment(*, actor_id: str = "local-admin", nonce: str = "enrollment-nonce") -> ExtensionControlEnrollment:
    return ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
    )


def _mutation(
    *, actor_id: str = "local-admin", layers: tuple[ExtensionControlLayer, ...] = ()
) -> ExtensionControlMutation:
    return ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=layers,
        actor_id=actor_id,
        idempotency_key="mutation-1",
        nonce="nonce-1",
    )


def test_extension_control_proof_requires_configured_gate(tmp_path: Path) -> None:
    with pytest.raises(ApprovalGateError, match="Configure the approval gate") as error:
        issue_extension_control_proof(
            tmp_path,
            _mutation(),
            approval_gate_input=ApprovalGateInput(password=_PASSWORD),
            session_nonce="session-1",
            now=_NOW,
        )

    assert error.value.code == "approval_gate_configuration_required"


def test_extension_control_proof_is_exact_and_one_use(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)

    with pytest.raises(ApprovalGateError, match="Approval proof is required"):
        consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)


def test_mismatched_mutation_does_not_consume_proof(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    with pytest.raises(ExtensionControlProofError, match="does not match"):
        consume_extension_control_proof(tmp_path, proof, _mutation(actor_id="different-actor"), now=_NOW)

    consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)


def test_enrollment_proof_is_exact_one_use_and_redacted(tmp_path: Path) -> None:
    _configure(tmp_path)
    enrollment = _enrollment()
    proof = issue_extension_control_enrollment_proof(
        tmp_path,
        enrollment,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="enrollment-session",
        now=_NOW,
    )

    rendered = repr(proof)
    assert rendered == "ExtensionControlEnrollmentProof(<redacted>)"
    for private_value in (
        _PASSWORD,
        proof.proof_id,
        proof.grant.grant_id,
        proof.actor_id,
        proof.nonce,
        proof.session_nonce,
    ):
        assert private_value not in rendered

    with pytest.raises(ExtensionControlProofError, match="does not match"):
        consume_extension_control_enrollment_proof(
            tmp_path,
            proof,
            _enrollment(actor_id="different-actor"),
            now=_NOW,
        )

    consume_extension_control_enrollment_proof(tmp_path, proof, enrollment, now=_NOW)
    with pytest.raises(ApprovalGateError, match="Approval proof is required"):
        consume_extension_control_enrollment_proof(tmp_path, proof, enrollment, now=_NOW)


_MODULE = "codex_plugin_scanner.guard.runtime.extension_control_proof"
_CONFIRMATION = "ENROLL EXTENSION CONTROL local-admin\n"


class _OpenStringIO(io.StringIO):
    """A stream whose text stays readable after the ``with`` block closes it."""

    def close(self) -> None:
        return None


def _record_verdict(monkeypatch: pytest.MonkeyPatch, verdict: str) -> list[dict[str, object]]:
    """Answer every resident call with ``verdict`` and keep what was asked."""

    asked: list[dict[str, object]] = []

    def resident(**request: object) -> str:
        asked.append(request)
        return verdict

    monkeypatch.setattr(f"{_MODULE}.native_extension_control_terminal_verdict", resident)
    return asked


def _record_outage(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    """Fail every resident call the way an unreachable runtime does."""

    def resident(**_request: object) -> str:
        raise ResidentCallError(code)

    monkeypatch.setattr(f"{_MODULE}.native_extension_control_terminal_verdict", resident)


def _probe_runner(
    who_output: str = "local-admin pts/0 2026-10-10 09:07\n",
    logind_output: str = "no\n",
) -> object:
    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = logind_output if command[0] == "/usr/bin/loginctl" else who_output
        return subprocess.CompletedProcess(command, 0, output, "")

    return run


def _patch_posix_session(monkeypatch: pytest.MonkeyPatch, *, confirmation: str = _CONFIRMATION) -> list[io.StringIO]:
    """Patch a POSIX session whose probes all answer for one owned local PTY.

    Returns the streams the confirmation prompt was written to and read from.
    """

    streams: list[io.StringIO] = []

    def fdopen(_descriptor: int, mode: str, **_kwargs: object) -> io.StringIO:
        stream = _OpenStringIO(confirmation if mode == "r" else "")
        streams.append(stream)
        return stream

    monkeypatch.setattr(f"{_MODULE}.os.open", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(f"{_MODULE}.os.close", lambda _descriptor: None)
    monkeypatch.setattr(f"{_MODULE}.os.dup", lambda descriptor: descriptor)
    monkeypatch.setattr(
        f"{_MODULE}.os.ttyname",
        lambda descriptor: "/dev/tty" if descriptor == 10 else "/dev/pts/0",
    )
    monkeypatch.setattr(f"{_MODULE}.os.isatty", lambda _descriptor: True)
    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", lambda _descriptor: 4200)
    monkeypatch.setattr(f"{_MODULE}.os.geteuid", lambda: 1000)
    monkeypatch.setattr(
        f"{_MODULE}.os.stat",
        lambda *_args, **_kwargs: SimpleNamespace(st_uid=1000, st_mode=stat.S_IFCHR),
    )
    monkeypatch.setattr(f"{_MODULE}._current_login_name", lambda: "local-admin")
    monkeypatch.setattr(f"{_MODULE}.sys.stdin", SimpleNamespace(isatty=lambda: True, fileno=lambda: 11))
    monkeypatch.setattr(f"{_MODULE}.os.fdopen", fdopen)
    monkeypatch.setattr(subprocess, "run", _probe_runner())
    return streams


def _without_remote_terminal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "MOSH_CONNECTION"):
        monkeypatch.delenv(name, raising=False)


def test_enrollment_reports_every_remote_terminal_variable_to_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    monkeypatch.setenv("SSH_CONNECTION", "client server")
    monkeypatch.setenv("MOSH_CONNECTION", "client server")
    monkeypatch.setattr(f"{_MODULE}.os.open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no terminal")))
    asked = _record_verdict(monkeypatch, "remote_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    assert asked[0]["remote_environment"] == ("SSH_CONNECTION", "MOSH_CONNECTION")
    assert asked[0]["guard_home"] == tmp_path


@pytest.mark.parametrize(
    ("verdict", "message"),
    (
        ("remote_terminal", "extension control enrollment requires a local terminal"),
        ("interactive_local_terminal", "extension control enrollment requires an interactive local terminal"),
        ("single_terminal", "extension control enrollment requires one interactive local terminal"),
    ),
)
def test_each_resident_verdict_renders_its_own_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict: str, message: str
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)
    _record_verdict(monkeypatch, verdict)

    with pytest.raises(ExtensionControlProofError) as refusal:
        _require_local_terminal_confirmation(tmp_path, enrollment)

    assert str(refusal.value) == message


def test_who_output_forwards_only_this_login_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)
    monkeypatch.setattr(
        subprocess,
        "run",
        _probe_runner(
            who_output=(
                "other-user pts/1 2026-10-10 09:01 (10.0.0.4)\n"
                "local-admin pts/0 2026-10-10 09:07\n"
                "other-user pts/2 2026-10-10 09:09 (10.0.0.5)\n"
                "local-admin pts/3 2026-10-10 09:11\n"
            )
        ),
    )
    asked = _record_verdict(monkeypatch, "local")

    _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    assert posix["who_output"] == "local-admin pts/0 2026-10-10 09:07\nlocal-admin pts/3 2026-10-10 09:11\n"


def test_who_output_is_dropped_when_the_login_name_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)
    monkeypatch.setattr(f"{_MODULE}._current_login_name", lambda: None)
    asked = _record_verdict(monkeypatch, "local")

    _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    # Without a login name the resident reads no record at all, so forwarding
    # the table would only spend the request bound.
    assert posix["login_name"] is None
    assert posix["who_output"] == ""


def test_an_unreachable_runtime_refuses_without_calling_the_session_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)
    _record_outage(monkeypatch, "native_extension_control_terminal_unavailable")

    with pytest.raises(ExtensionControlProofError) as refusal:
        _require_local_terminal_confirmation(tmp_path, enrollment)

    assert str(refusal.value) == (
        "extension control enrollment could not reach the Guard runtime (native_extension_control_terminal_unavailable)"
    )


def test_a_local_verdict_confirms_through_the_controlling_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    streams = _patch_posix_session(monkeypatch)
    asked = _record_verdict(monkeypatch, "local")

    _require_local_terminal_confirmation(tmp_path, enrollment)

    assert 'Type "ENROLL EXTENSION CONTROL local-admin"' in streams[0].getvalue()
    assert asked[0]["windows"] is None
    assert asked[0]["posix"] == {
        "controlling_terminal_opened": True,
        "controlling_terminal_is_tty": True,
        "stdin_is_tty": True,
        "descriptors_share_session": True,
        # stdin names the concrete PTY behind the /dev/tty alias.
        "terminal_name": "/dev/pts/0",
        "login_name": "local-admin",
        "who_output": "local-admin pts/0 2026-10-10 09:07\n",
        "logind_remote": "no\n",
        "terminal_owner_uid": 1000,
        "terminal_is_char_device": True,
        "effective_uid": 1000,
    }


def test_a_mismatched_confirmation_is_refused_after_a_local_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch, confirmation="ENROLL EXTENSION CONTROL another-actor\n")
    _record_verdict(monkeypatch, "local")

    with pytest.raises(ExtensionControlProofError, match="confirmation did not match"):
        _require_local_terminal_confirmation(tmp_path, enrollment)


def test_a_closed_controlling_terminal_is_reported_to_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    monkeypatch.setattr(f"{_MODULE}.os.open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no terminal")))
    asked = _record_verdict(monkeypatch, "interactive_local_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires an interactive local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    assert posix["controlling_terminal_opened"] is False
    assert posix["terminal_name"] == ""
    assert posix["who_output"] is None


def test_an_unshared_stdin_session_keeps_the_controlling_terminal_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)
    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", lambda descriptor: 4200 if descriptor == 10 else 4300)
    asked = _record_verdict(monkeypatch, "single_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires one interactive local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    assert posix["descriptors_share_session"] is False
    assert posix["terminal_name"] == "/dev/tty"


def test_an_unreadable_terminal_session_is_reported_as_unanswered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)

    def unreadable_process_group(_descriptor: int) -> int:
        raise OSError("not a terminal")

    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", unreadable_process_group)
    asked = _record_verdict(monkeypatch, "single_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires one interactive local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    assert posix["descriptors_share_session"] is None


def test_probes_that_cannot_run_are_reported_as_unanswered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    _patch_posix_session(monkeypatch)

    def unavailable(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("probe unavailable")

    monkeypatch.setattr(subprocess, "run", unavailable)
    monkeypatch.setattr(f"{_MODULE}.os.stat", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("gone")))
    monkeypatch.setattr(f"{_MODULE}._current_login_name", lambda: None)
    asked = _record_verdict(monkeypatch, "interactive_local_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires an interactive local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    posix = asked[0]["posix"]
    assert isinstance(posix, dict)
    assert posix["who_output"] is None
    assert posix["logind_remote"] is None
    assert posix["login_name"] is None
    assert posix["terminal_owner_uid"] is None
    assert posix["terminal_is_char_device"] is None


def test_terminal_descriptors_accept_linux_tty_alias_and_stdin_pty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_groups = {10: 4200, 11: 4200}

    def process_group(descriptor: int) -> int:
        try:
            return process_groups[descriptor]
        except KeyError as error:
            raise OSError("unknown terminal descriptor") from error

    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", process_group)

    assert _terminal_descriptors_share_session(10, 11) is True


def test_terminal_descriptors_reject_different_terminal_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_groups = {10: 4200, 11: 4300}
    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", process_groups.__getitem__)

    assert _terminal_descriptors_share_session(10, 11) is False


def test_terminal_descriptors_report_a_session_that_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable_process_group(_descriptor: int) -> int:
        raise OSError("not a terminal")

    monkeypatch.setattr(f"{_MODULE}.os.tcgetpgrp", unreadable_process_group)

    assert _terminal_descriptors_share_session(10, 11) is None


@pytest.mark.parametrize("console_mode_result, expected", [(1, True), (0, False)])
def test_windows_console_probe_checks_native_handle(
    monkeypatch: pytest.MonkeyPatch, console_mode_result: int, expected: bool
) -> None:
    import ctypes

    handle = 0x123456789
    get_osfhandle = Mock(return_value=handle)
    get_console_mode = Mock(return_value=console_mode_result)
    win_dll = Mock(return_value=SimpleNamespace(GetConsoleMode=get_console_mode))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=get_osfhandle))
    monkeypatch.setattr(ctypes, "WinDLL", win_dll, raising=False)

    assert _windows_console_descriptor_is_interactive(10) is expected

    get_osfhandle.assert_called_once_with(10)
    win_dll.assert_called_once_with("kernel32", use_last_error=True)
    assert get_console_mode.call_args.args[0].value == handle
    assert len(get_console_mode.argtypes) == 2
    assert get_console_mode.restype is ctypes.wintypes.BOOL


@pytest.mark.parametrize("handle", [-1, None])
def test_windows_console_probe_rejects_unusable_handle(monkeypatch: pytest.MonkeyPatch, handle: int | None) -> None:
    import ctypes

    get_osfhandle = Mock(return_value=handle) if handle is not None else Mock(side_effect=OSError("invalid descriptor"))
    win_dll = Mock(side_effect=AssertionError("must reject before loading kernel32"))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=get_osfhandle))
    monkeypatch.setattr(ctypes, "WinDLL", win_dll, raising=False)

    assert _windows_console_descriptor_is_interactive(10) is False
    win_dll.assert_not_called()


def test_windows_console_probe_fails_closed_on_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=Mock(return_value=10)))
    monkeypatch.setattr(ctypes, "WinDLL", Mock(side_effect=OSError("API unavailable")), raising=False)

    assert _windows_console_descriptor_is_interactive(10) is False


def _windows_session_libraries(protocol: object) -> dict[str, SimpleNamespace]:
    import ctypes

    def process_id_to_session_id(_process_id: object, session_id: object) -> int:
        session_id._obj.value = 42  # type: ignore[attr-defined]
        return 1

    def query_session_information(
        _server: object,
        _session_id: object,
        _info_class: object,
        buffer: object,
        bytes_returned: object,
    ) -> int:
        buffer._obj.value = ctypes.addressof(protocol)  # type: ignore[attr-defined]
        bytes_returned._obj.value = ctypes.sizeof(protocol)  # type: ignore[attr-defined]
        return 1

    return {
        "user32": SimpleNamespace(GetSystemMetrics=Mock(return_value=0)),
        "kernel32": SimpleNamespace(ProcessIdToSessionId=process_id_to_session_id),
        "wtsapi32": SimpleNamespace(
            WTSQuerySessionInformationW=query_session_information,
            WTSFreeMemory=Mock(),
        ),
    }


@pytest.mark.parametrize("protocol_type", [0, 2])
def test_windows_session_probe_reports_the_client_protocol_type(
    monkeypatch: pytest.MonkeyPatch, protocol_type: int
) -> None:
    import ctypes

    protocol = ctypes.c_ushort(protocol_type)
    libraries = _windows_session_libraries(protocol)
    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False)

    assert _windows_session_probe() == (False, protocol_type)
    libraries["user32"].GetSystemMetrics.assert_called_once_with(0x1000)


def test_windows_session_probe_reports_a_remote_console_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    get_system_metrics = Mock(return_value=1)
    win_dll = Mock(return_value=SimpleNamespace(GetSystemMetrics=get_system_metrics))
    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", win_dll, raising=False)

    assert _windows_session_probe() == (True, None)
    win_dll.assert_called_once_with("user32", use_last_error=True)


def test_windows_session_probe_reports_an_unanswered_native_api(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", Mock(side_effect=OSError("session API unavailable")), raising=False)

    assert _windows_session_probe() == (None, None)


class _ConsoleStream(io.StringIO):
    def __init__(self, value: str = "", descriptor: int = 10) -> None:
        super().__init__(value)
        self.descriptor = descriptor

    def fileno(self) -> int:
        return self.descriptor

    def isatty(self) -> bool:
        return True


def test_windows_enrollment_reports_its_console_signals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    stdout = _ConsoleStream("", 11)
    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(f"{_MODULE}.sys.stdin", _ConsoleStream(_CONFIRMATION, 10))
    monkeypatch.setattr(f"{_MODULE}.sys.stdout", stdout)
    monkeypatch.setattr(
        f"{_MODULE}._windows_console_descriptor_is_interactive",
        lambda descriptor: descriptor in {10, 11},
    )
    monkeypatch.setattr(f"{_MODULE}._windows_session_probe", lambda: (False, 0))
    monkeypatch.setenv("SESSIONNAME", "Console")
    monkeypatch.delenv("CLIENTNAME", raising=False)
    asked = _record_verdict(monkeypatch, "local")

    _require_local_terminal_confirmation(tmp_path, enrollment)

    assert 'Type "ENROLL EXTENSION CONTROL local-admin"' in stdout.getvalue()
    assert asked[0]["posix"] is None
    assert asked[0]["windows"] == {
        "stdio_is_tty": True,
        "console_descriptors_interactive": True,
        "session_name": "Console",
        "client_name": "",
        "remote_session_metric": False,
        "wts_protocol_type": 0,
    }


def test_windows_enrollment_rejects_mismatched_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)
    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(f"{_MODULE}.sys.stdin", _ConsoleStream("ENROLL EXTENSION CONTROL another-actor\n", 10))
    monkeypatch.setattr(f"{_MODULE}.sys.stdout", _ConsoleStream("", 11))
    monkeypatch.setattr(
        f"{_MODULE}._windows_console_descriptor_is_interactive",
        lambda descriptor: descriptor in {10, 11},
    )
    monkeypatch.setattr(f"{_MODULE}._windows_session_probe", lambda: (False, 0))
    _record_verdict(monkeypatch, "local")

    with pytest.raises(ExtensionControlProofError, match="confirmation did not match"):
        _require_local_terminal_confirmation(tmp_path, enrollment)


def test_windows_enrollment_reports_redirected_stdio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    enrollment = _enrollment()
    _without_remote_terminal_environment(monkeypatch)

    class RedirectedStream(io.StringIO):
        def fileno(self) -> int:
            return 10

        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(f"{_MODULE}.os.name", "nt")
    monkeypatch.setattr(f"{_MODULE}.sys.stdin", RedirectedStream())
    monkeypatch.setattr(f"{_MODULE}.sys.stdout", RedirectedStream())
    monkeypatch.setattr(f"{_MODULE}._windows_session_probe", lambda: (False, 0))
    monkeypatch.setattr(
        f"{_MODULE}._windows_console_descriptor_is_interactive",
        lambda _descriptor: pytest.fail("a redirected descriptor is never consulted"),
    )
    asked = _record_verdict(monkeypatch, "interactive_local_terminal")

    with pytest.raises(ExtensionControlProofError, match="requires an interactive local terminal"):
        _require_local_terminal_confirmation(tmp_path, enrollment)

    windows = asked[0]["windows"]
    assert isinstance(windows, dict)
    assert windows["stdio_is_tty"] is False
    assert windows["console_descriptors_interactive"] is False


def test_extension_control_proof_rejects_stale_grant(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    with pytest.raises(ApprovalGateError) as error:
        consume_extension_control_proof(
            tmp_path,
            proof,
            mutation,
            now="2026-07-20T12:06:00+00:00",
        )
    assert error.value.code == "approval_gate_grant_expired"


def test_extension_control_proof_repr_redacts_all_bindings(tmp_path: Path) -> None:
    _configure(tmp_path)
    proof = issue_extension_control_proof(
        tmp_path,
        _mutation(),
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    assert repr(proof) == "ExtensionControlProof(<redacted>)"


def test_preview_digest_is_independent_of_layer_and_control_order() -> None:
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    controls = (
        ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.alpha"), ControlState.DISABLED),
        ExtensionControl(
            ControlTarget(ControlTargetKind.PERMISSION, "command.alpha.permission.write"),
            ControlState.ENABLED,
        ),
    )
    local = ExtensionControlLayer(CONTROL_SCHEMA_VERSION, ControlLayerKind.LOCAL_ADMIN, digest, False, controls)
    cloud = ExtensionControlLayer(CONTROL_SCHEMA_VERSION, ControlLayerKind.SIGNED_CLOUD, digest, True, ())
    first = _mutation(layers=(local, cloud))
    reordered_local = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        digest,
        False,
        tuple(reversed(controls)),
    )
    second = _mutation(layers=(cloud, reordered_local))

    assert first.canonical_digest == second.canonical_digest


# The digests the Python proof computed for these inputs before the resident
# took them over; the resident must keep issuing them so outstanding proofs
# and recorded commits stay valid.
_GOLDEN_CATALOG = "ab" * 32
_GOLDEN_ACTOR = "local-admin é"


def test_resident_mutation_digest_matches_the_python_digest() -> None:
    local = ExtensionControlLayer(
        "1.0.0",
        ControlLayerKind.LOCAL_ADMIN,
        _GOLDEN_CATALOG,
        False,
        (
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, "command.alpha.permission.write"), ControlState.ENABLED
            ),
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.alpha"), ControlState.DISABLED),
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.alpha"), ControlState.ENABLED),
        ),
    )
    cloud = ExtensionControlLayer("1.0.0", ControlLayerKind.SIGNED_CLOUD, _GOLDEN_CATALOG, True, ())
    mutation = ExtensionControlMutation(
        previous_revision=7,
        catalog_digest=_GOLDEN_CATALOG,
        layers=(cloud, local),
        actor_id=_GOLDEN_ACTOR,
        idempotency_key="mutation-1",
        nonce="nonce-1",
    )

    assert mutation.canonical_digest == "864b425798605db58a8af6761e9224c5f8efca61761e95a8d3ecba1964c1febf"


def test_resident_enrollment_digest_matches_the_python_digest() -> None:
    enrollment = ExtensionControlEnrollment(
        catalog_digest=_GOLDEN_CATALOG, actor_id=_GOLDEN_ACTOR, nonce="enrollment-nonce"
    )

    assert enrollment.canonical_digest == "c11b524f977b40ba53292b2d956770a4186c3e46c9f88d2e46a1536ba2ec29e0"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"previous_revision": -1}, "invalid previous revision"),
        ({"previous_revision": True}, "invalid previous revision"),
        ({"previous_revision": 2**63}, "invalid previous revision"),
        ({"actor_id": "\ud800"}, "invalid mutation identity"),
        ({"catalog_digest": "AB" * 32}, "invalid catalog digest"),
        ({"actor_id": " \t"}, "invalid mutation identity"),
        ({"nonce": "n" * 257}, "invalid mutation identity"),
    ],
)
def test_resident_refuses_an_invalid_mutation(changes: dict[str, object], message: str) -> None:
    fields: dict[str, object] = {
        "previous_revision": 0,
        "catalog_digest": _GOLDEN_CATALOG,
        "layers": (),
        "actor_id": "local-admin",
        "idempotency_key": "mutation-1",
        "nonce": "nonce-1",
    }
    with pytest.raises(ExtensionControlProofError, match=message):
        ExtensionControlMutation(**{**fields, **changes})  # type: ignore[arg-type]


def test_resident_refuses_an_invalid_enrollment() -> None:
    with pytest.raises(ExtensionControlProofError, match="invalid catalog digest"):
        ExtensionControlEnrollment(catalog_digest="", actor_id="local-admin", nonce="nonce")
    with pytest.raises(ExtensionControlProofError, match="invalid enrollment identity"):
        ExtensionControlEnrollment(catalog_digest=_GOLDEN_CATALOG, actor_id="  ", nonce="nonce")
    with pytest.raises(ExtensionControlProofError, match="invalid enrollment identity"):
        ExtensionControlEnrollment(catalog_digest=_GOLDEN_CATALOG, actor_id="\ud800", nonce="nonce")


def test_enrollment_asks_the_resident_of_the_selected_guard_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime import extension_control_proof

    homes: list[object] = []

    def digest(*, guard_home: object = None, **_fields: object) -> str:
        homes.append(guard_home)
        return "0" * 64

    monkeypatch.setattr(extension_control_proof, "enrollment_digest", digest)
    ExtensionControlEnrollment(
        catalog_digest=_GOLDEN_CATALOG, actor_id="local-admin", nonce="nonce", guard_home=tmp_path
    )

    assert homes == [tmp_path]
