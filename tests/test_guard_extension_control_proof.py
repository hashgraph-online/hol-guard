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
    _terminal_session_is_local,
    _windows_console_descriptor_is_interactive,
    _windows_session_is_local,
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
        lambda _enrollment: None,
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


def test_enrollment_proof_rejects_remote_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(tmp_path)
    monkeypatch.setenv("SSH_CONNECTION", "client server")

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(_enrollment())


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


def test_windows_session_probe_accepts_native_local_console(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    protocol = ctypes.c_ushort(0)
    get_system_metrics = Mock(return_value=0)

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

    libraries = {
        "user32": SimpleNamespace(GetSystemMetrics=get_system_metrics),
        "kernel32": SimpleNamespace(ProcessIdToSessionId=process_id_to_session_id),
        "wtsapi32": SimpleNamespace(
            WTSQuerySessionInformationW=query_session_information,
            WTSFreeMemory=Mock(),
        ),
    }
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.delenv("CLIENTNAME", raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: libraries[name],
        raising=False,
    )

    assert _windows_session_is_local() is True
    get_system_metrics.assert_called_once_with(0x1000)


def test_windows_session_probe_rejects_remote_console_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    get_system_metrics = Mock(return_value=1)
    win_dll = Mock(return_value=SimpleNamespace(GetSystemMetrics=get_system_metrics))
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.delenv("CLIENTNAME", raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", win_dll, raising=False)

    assert _windows_session_is_local() is False
    win_dll.assert_called_once_with("user32", use_last_error=True)


def test_windows_session_probe_rejects_remote_session_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    win_dll = Mock(side_effect=AssertionError("native APIs must not be needed for an explicit RDP signal"))
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#7")
    monkeypatch.setattr(ctypes, "WinDLL", win_dll, raising=False)

    assert _windows_session_is_local() is False
    win_dll.assert_not_called()


def test_windows_session_probe_rejects_remote_wts_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    protocol = ctypes.c_ushort(2)

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

    libraries = {
        "user32": SimpleNamespace(GetSystemMetrics=Mock(return_value=0)),
        "kernel32": SimpleNamespace(ProcessIdToSessionId=process_id_to_session_id),
        "wtsapi32": SimpleNamespace(
            WTSQuerySessionInformationW=query_session_information,
            WTSFreeMemory=Mock(),
        ),
    }
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.delenv("CLIENTNAME", raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False)

    assert _windows_session_is_local() is False


def test_windows_session_probe_rejects_native_api_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.delenv("CLIENTNAME", raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", Mock(side_effect=OSError("session API unavailable")), raising=False)

    assert _windows_session_is_local() is False


def test_windows_enrollment_uses_console_stdio_without_posix_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    class ConsoleStream(io.StringIO):
        def __init__(self, value: str, descriptor: int) -> None:
            super().__init__(value)
            self.descriptor = descriptor

        def fileno(self) -> int:
            return self.descriptor

        def isatty(self) -> bool:
            return True

    expected = "ENROLL EXTENSION CONTROL local-admin\n"
    stdin = ConsoleStream(expected, 10)
    stdout = ConsoleStream("", 11)
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.delattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.O_NOCTTY", raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdin", stdin)
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdout", stdout)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_console_descriptor_is_interactive",
        lambda descriptor: descriptor in {10, 11},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_session_is_local",
        lambda: True,
    )

    _require_local_terminal_confirmation(_enrollment())

    assert 'Type "ENROLL EXTENSION CONTROL local-admin"' in stdout.getvalue()


def test_windows_enrollment_rejects_mismatched_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    class ConsoleStream(io.StringIO):
        def __init__(self, value: str, descriptor: int) -> None:
            super().__init__(value)
            self.descriptor = descriptor

        def fileno(self) -> int:
            return self.descriptor

        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdin",
        ConsoleStream("ENROLL EXTENSION CONTROL another-actor\n", 10),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdout",
        ConsoleStream("", 11),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_console_descriptor_is_interactive",
        lambda descriptor: descriptor in {10, 11},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_session_is_local",
        lambda: True,
    )

    with pytest.raises(ExtensionControlProofError, match="confirmation did not match"):
        _require_local_terminal_confirmation(_enrollment())


def test_windows_enrollment_rejects_redirected_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedirectedStream(io.StringIO):
        def fileno(self) -> int:
            return 10

        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdin", RedirectedStream())
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdout", RedirectedStream())

    with pytest.raises(ExtensionControlProofError, match="requires an interactive local terminal"):
        _require_local_terminal_confirmation(_enrollment())


def test_windows_enrollment_rejects_ssh_before_console_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.setenv("SSH_CONNECTION", "client server")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_console_descriptor_is_interactive",
        lambda _descriptor: pytest.fail("console probe must not run for a remote terminal"),
    )

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(_enrollment())


def test_windows_enrollment_rejects_remote_session_before_console_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    class ConsoleStream(io.StringIO):
        def fileno(self) -> int:
            return 10

        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.extension_control_proof.os.name", "nt")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdin",
        ConsoleStream(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdout",
        ConsoleStream(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_session_is_local",
        lambda: False,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._windows_console_descriptor_is_interactive",
        lambda _descriptor: pytest.fail("console probe must not run for a remote session"),
    )

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(_enrollment())


def test_terminal_descriptors_accept_linux_tty_alias_and_stdin_pty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_groups = {10: 4200, 11: 4200}

    def process_group(descriptor: int) -> int:
        try:
            return process_groups[descriptor]
        except KeyError as error:
            raise OSError("unknown terminal descriptor") from error

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.tcgetpgrp",
        process_group,
    )

    assert _terminal_descriptors_share_session(10, 11) is True


def test_terminal_descriptors_reject_different_terminal_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_groups = {10: 4200, 11: 4300}
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.tcgetpgrp",
        process_groups.__getitem__,
    )

    assert _terminal_descriptors_share_session(10, 11) is False


def test_terminal_descriptors_fail_closed_when_session_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable_process_group(_descriptor: int) -> int:
        raise OSError("not a terminal")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.tcgetpgrp",
        unreadable_process_group,
    )

    assert _terminal_descriptors_share_session(10, 11) is False


def test_enrollment_accepts_linux_tty_alias_for_same_controlling_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "ENROLL EXTENSION CONTROL local-admin\n"
    process_groups = {10: 4200, 11: 4200}

    def process_group(descriptor: int) -> int:
        try:
            return process_groups[descriptor]
        except KeyError as error:
            raise OSError("unknown terminal descriptor") from error

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.open",
        lambda *_args, **_kwargs: 10,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.close",
        lambda _descriptor: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.dup",
        lambda descriptor: descriptor,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.tcgetpgrp",
        process_group,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.ttyname",
        lambda descriptor: "/dev/tty" if descriptor == 10 else "/dev/pts/0",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.isatty",
        lambda _descriptor: True,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._terminal_session_is_local",
        lambda terminal_name: terminal_name == "/dev/pts/0",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.fdopen",
        lambda _descriptor, mode, **_kwargs: io.StringIO(expected if mode == "r" else ""),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.sys.stdin",
        type("InteractiveInput", (), {"isatty": lambda self: True, "fileno": lambda self: 11})(),
    )

    _require_local_terminal_confirmation(_enrollment())


@pytest.mark.parametrize(
    ("who_output", "expected"),
    (
        ("local-admin ttys020 Jul 21 09:07\n", True),
        ("local-admin ttys020 Jul 21 09:07 (203.0.113.8)\n", False),
        ("local-admin ttys021 Jul 21 09:07\n", False),
    ),
)
def test_terminal_locality_accepts_hostless_matching_login_record(
    monkeypatch: pytest.MonkeyPatch,
    who_output: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._current_login_name",
        lambda: "local-admin",
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(("/usr/bin/who",), 0, who_output, ""),
    )

    assert _terminal_session_is_local("/dev/ttys020") is expected


def test_terminal_locality_accepts_owned_desktop_pty_without_login_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._current_login_name",
        lambda: "local-admin",
    )

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "no\n" if command[0] == "/usr/bin/loginctl" else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.geteuid",
        lambda: 1000,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.stat",
        lambda *_args, **_kwargs: type("OwnedPty", (), {"st_uid": 1000, "st_mode": stat.S_IFCHR})(),
    )

    assert _terminal_session_is_local("/dev/pts/7") is True


def test_terminal_locality_rejects_foreign_desktop_pty_without_login_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._current_login_name",
        lambda: "local-admin",
    )

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "no\n" if command[0] == "/usr/bin/loginctl" else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.geteuid",
        lambda: 1000,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof.os.stat",
        lambda *_args, **_kwargs: type("ForeignPty", (), {"st_uid": 2000, "st_mode": stat.S_IFCHR})(),
    )

    assert _terminal_session_is_local("/dev/pts/7") is False


def test_terminal_locality_rejects_remote_logind_session_without_login_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._current_login_name",
        lambda: "local-admin",
    )

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "yes\n" if command[0] == "/usr/bin/loginctl" else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)

    assert _terminal_session_is_local("/dev/pts/7") is False


def test_enrollment_proof_rejects_mosh_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MOSH_CONNECTION", "client server")

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(_enrollment())


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
