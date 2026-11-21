"""Fresh, mutation-bound approval proofs for extension-control authority changes.

The digest a proof binds is the resident's (``extension_control``): it checks
the mutation or enrollment and computes the canonical digest, and the commit
plan recomputes it from the layers it seals. Python asks for the digest and
renders a refusal; a resident that does not answer fails the proof closed.
"""

from __future__ import annotations

import hmac
import os
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import InitVar, dataclass, field
from pathlib import Path

from ..approval_gate import (
    ApprovalGateGrant,
    ApprovalGateInput,
    consume_extension_control_grant,
    require_extension_control,
)
from ..native_extension_control import NativeExtensionControlError, enrollment_digest, mutation_digest
from ..native_extension_control_terminal import native_extension_control_terminal_verdict
from ..native_resident_decision import ResidentCallError
from .extension_control_contract import ExtensionControlLayer

EXTENSION_CONTROL_PROOF_ACTION = "commit-layers"
EXTENSION_CONTROL_ENROLLMENT_ACTION = "enroll-authority"
_MAX_IDENTITY_LENGTH = 256
_INVALID_REVISION = "native_extension_control_invalid_revision"
_INVALID_CATALOG_DIGEST = "native_extension_control_invalid_catalog_digest"
_INVALID_IDENTITY = "native_extension_control_invalid_identity"
_ENROLLMENT_CONFIRMATION_PREFIX = "ENROLL EXTENSION CONTROL"
_REMOTE_TERMINAL_REFUSAL = "extension control enrollment requires a local terminal"
_INTERACTIVE_TERMINAL_REFUSAL = "extension control enrollment requires an interactive local terminal"
_SINGLE_TERMINAL_REFUSAL = "extension control enrollment requires one interactive local terminal"
_RUNTIME_TERMINAL_REFUSAL = "extension control enrollment could not reach the Guard runtime"
# The resident names the refusal it reached; this module only renders it.
_TERMINAL_REFUSALS = {
    "remote_terminal": _REMOTE_TERMINAL_REFUSAL,
    "interactive_local_terminal": _INTERACTIVE_TERMINAL_REFUSAL,
    "single_terminal": _SINGLE_TERMINAL_REFUSAL,
}
_REMOTE_TERMINAL_ENVIRONMENT = ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "MOSH_CONNECTION")
_WINDOWS_SM_REMOTESESSION = 0x1000
_WINDOWS_WTS_CLIENT_PROTOCOL_TYPE = 16


class ExtensionControlProofError(PermissionError):
    """Raised when an extension-control proof is malformed or mismatched."""


def _resident_digest(compute: Callable[[], str], identity_refusal: str) -> str:
    """``compute``'s digest, with the resident's field refusals as proof errors.

    Any other resident failure propagates: without the resident's digest there
    is no proof to issue or check.
    """

    try:
        return compute()
    except NativeExtensionControlError as error:
        refusal = {
            _INVALID_REVISION: "invalid previous revision",
            _INVALID_CATALOG_DIGEST: "invalid catalog digest",
            _INVALID_IDENTITY: identity_refusal,
        }.get(error.code)
        if refusal is None:
            raise
        raise ExtensionControlProofError(refusal) from None


def _transportable(values: tuple[object, ...]) -> bool:
    """Whether every value is a string the resident request can carry.

    A lone surrogate is a Python string but not UTF-8, so the resident could
    not decode the request; refusing it here keeps it a field refusal rather
    than a resident failure.
    """

    for value in values:
        if not isinstance(value, str):
            return False
        try:
            _ = value.encode("utf-8")
        except UnicodeEncodeError:
            return False
    return True


@dataclass(frozen=True, slots=True)
class ExtensionControlEnrollment:
    catalog_digest: str
    actor_id: str
    nonce: str
    _digest: str = field(init=False, repr=False, compare=False)
    # The home whose resident digests the enrollment; not part of the proof.
    guard_home: InitVar[Path | None] = None

    def __post_init__(self, guard_home: Path | None) -> None:
        if not _transportable((self.catalog_digest, self.actor_id, self.nonce)):
            raise ExtensionControlProofError("invalid enrollment identity")
        digest = _resident_digest(
            lambda: enrollment_digest(
                catalog_digest=self.catalog_digest,
                actor_id=self.actor_id,
                nonce=self.nonce,
                guard_home=guard_home,
            ),
            "invalid enrollment identity",
        )
        object.__setattr__(self, "_digest", digest)

    @property
    def canonical_digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class ExtensionControlEnrollmentProof:
    proof_id: str
    grant: ApprovalGateGrant
    actor_id: str
    catalog_digest: str
    enrollment_digest: str
    nonce: str
    session_nonce: str

    def __repr__(self) -> str:
        return "ExtensionControlEnrollmentProof(<redacted>)"


def _current_login_name() -> str | None:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        return None


def _login_records(output: str | None, login_name: str | None) -> str | None:
    """``who``'s lines for ``login_name``, in the order it printed them.

    A shared host prints a record per login, and the whole table has to fit the
    resident's request bound. The resident reads only the records whose first
    column is this login name, and none at all without one, so dropping the
    rest bounds the request without deciding anything.
    """

    if output is None:
        return None
    if login_name is None:
        return ""
    return "".join(f"{line}\n" for line in output.splitlines() if line.split()[:1] == [login_name])


def _probe_output(command: tuple[str, ...]) -> str | None:
    """What ``command`` printed, or ``None`` when it could not be run.

    The output is forwarded to the resident verbatim; nothing here reads it.
    """

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout


def _terminal_descriptors_share_session(control_descriptor: int, input_descriptor: int) -> bool | None:
    """Whether stdin belongs to the foreground controlling-terminal session.

    ``None`` when the question could not be answered. Linux exposes
    ``/dev/tty`` as a character-device alias while stdin names the concrete
    PTY, so their device numbers are expected to differ.
    """

    try:
        return os.tcgetpgrp(control_descriptor) == os.tcgetpgrp(input_descriptor)
    except OSError:
        return None


def _posix_terminal_signals(descriptor: int | None) -> dict[str, object]:
    """Every POSIX signal the resident reads to place this session.

    All of them are collected, because the resident decides which one settles
    the question. A probe that could not run contributes ``None``.
    """

    signals: dict[str, object] = {
        "controlling_terminal_opened": descriptor is not None,
        "controlling_terminal_is_tty": False,
        "stdin_is_tty": False,
        "descriptors_share_session": None,
        "terminal_name": "",
        "login_name": None,
        "who_output": None,
        "logind_remote": None,
        "terminal_owner_uid": None,
        "terminal_is_char_device": None,
        "effective_uid": os.geteuid(),
    }
    if descriptor is None:
        return signals
    terminal_name = os.ttyname(descriptor)
    stdin_is_tty = sys.stdin.isatty()
    signals["stdin_is_tty"] = stdin_is_tty
    if stdin_is_tty:
        stdin_descriptor = sys.stdin.fileno()
        shared = _terminal_descriptors_share_session(descriptor, stdin_descriptor)
        signals["descriptors_share_session"] = shared
        if shared:
            terminal_name = os.ttyname(stdin_descriptor)
    signals["terminal_name"] = terminal_name
    signals["controlling_terminal_is_tty"] = os.isatty(descriptor)
    login_name = _current_login_name()
    signals["login_name"] = login_name
    signals["who_output"] = _login_records(_probe_output(("/usr/bin/who",)), login_name)
    signals["logind_remote"] = _probe_output(
        ("/usr/bin/loginctl", "show-session", "self", "--property=Remote", "--value")
    )
    try:
        terminal = os.stat(terminal_name, follow_symlinks=True)
    except OSError:
        return signals
    signals["terminal_owner_uid"] = terminal.st_uid
    signals["terminal_is_char_device"] = stat.S_ISCHR(terminal.st_mode)
    return signals


def _windows_console_descriptor_is_interactive(descriptor: int) -> bool:
    """Whether a descriptor is backed by a Windows console, not a redirected pipe."""

    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return False
        handle = msvcrt.get_osfhandle(descriptor)
        if handle == -1:
            return False
        kernel32 = win_dll("kernel32", use_last_error=True)
        get_console_mode = kernel32.GetConsoleMode
        get_console_mode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_console_mode.restype = wintypes.BOOL
        mode = wintypes.DWORD()
        return bool(get_console_mode(wintypes.HANDLE(handle), ctypes.byref(mode)))
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        return False


def _windows_session_probe() -> tuple[bool | None, int | None]:
    """The Windows remote-session metric and the session's client protocol type.

    ``None`` for either reading means the API did not answer it, which the
    resident treats as a session it cannot place locally.
    """

    if os.name != "nt":
        return None, None
    try:
        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return None, None
        user32 = win_dll("user32", use_last_error=True)
        get_system_metrics = user32.GetSystemMetrics
        get_system_metrics.argtypes = [ctypes.c_int]
        get_system_metrics.restype = ctypes.c_int
        if get_system_metrics(_WINDOWS_SM_REMOTESESSION):
            return True, None

        kernel32 = win_dll("kernel32", use_last_error=True)
        process_id_to_session_id = kernel32.ProcessIdToSessionId
        process_id_to_session_id.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        process_id_to_session_id.restype = wintypes.BOOL
        session_id = wintypes.DWORD()
        if not process_id_to_session_id(wintypes.DWORD(os.getpid()), ctypes.byref(session_id)):
            return False, None

        wtsapi32 = win_dll("wtsapi32", use_last_error=True)
        query_session_information = wtsapi32.WTSQuerySessionInformationW
        query_session_information.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        query_session_information.restype = wintypes.BOOL
        free_wts_memory = wtsapi32.WTSFreeMemory
        free_wts_memory.argtypes = [ctypes.c_void_p]
        free_wts_memory.restype = None

        buffer = ctypes.c_void_p()
        bytes_returned = wintypes.DWORD()
        try:
            if not query_session_information(
                None,
                session_id,
                _WINDOWS_WTS_CLIENT_PROTOCOL_TYPE,
                ctypes.byref(buffer),
                ctypes.byref(bytes_returned),
            ):
                return False, None
            if not buffer.value or bytes_returned.value < ctypes.sizeof(ctypes.c_ushort):
                return False, None
            return False, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ushort)).contents.value
        finally:
            if buffer.value:
                with suppress(OSError, TypeError, ValueError):
                    free_wts_memory(buffer)
    except (AttributeError, ImportError, OSError, TypeError, ValueError, OverflowError):
        return None, None


def _windows_terminal_signals() -> dict[str, object]:
    """Every Windows signal the resident reads to place this session."""

    try:
        stdio_is_tty = bool(sys.stdin.isatty() and sys.stdout.isatty())
        descriptors = (sys.stdin.fileno(), sys.stdout.fileno()) if stdio_is_tty else ()
    except (AttributeError, OSError, ValueError):
        stdio_is_tty = False
        descriptors = ()
    remote_session_metric, wts_protocol_type = _windows_session_probe()
    return {
        "stdio_is_tty": stdio_is_tty,
        "console_descriptors_interactive": bool(descriptors)
        and all(_windows_console_descriptor_is_interactive(descriptor) for descriptor in descriptors),
        "session_name": os.environ.get("SESSIONNAME", ""),
        "client_name": os.environ.get("CLIENTNAME", ""),
        "remote_session_metric": remote_session_metric,
        "wts_protocol_type": wts_protocol_type,
    }


def _require_resident_local_terminal(
    guard_home: Path,
    *,
    posix: dict[str, object] | None,
    windows: dict[str, object] | None,
) -> None:
    """Refuse unless the resident places this session at the local keyboard."""

    try:
        verdict = native_extension_control_terminal_verdict(
            remote_environment=tuple(name for name in _REMOTE_TERMINAL_ENVIRONMENT if os.environ.get(name)),
            posix=posix,
            windows=windows,
            guard_home=guard_home,
        )
    except ResidentCallError as outage:
        # An outage placed the session nowhere, so the enrollment is still
        # refused. Naming the runtime keeps an operator who is at the keyboard
        # from being told they are somewhere else.
        raise ExtensionControlProofError(f"{_RUNTIME_TERMINAL_REFUSAL} ({outage})") from outage
    if verdict == "local":
        return
    raise ExtensionControlProofError(_TERMINAL_REFUSALS.get(verdict, _REMOTE_TERMINAL_REFUSAL))


def _require_windows_local_terminal_confirmation(
    guard_home: Path,
    enrollment: ExtensionControlEnrollment,
) -> None:
    """Confirm through the current Windows console without accepting redirected input."""

    _require_resident_local_terminal(guard_home, posix=None, windows=_windows_terminal_signals())
    expected = f"{_ENROLLMENT_CONFIRMATION_PREFIX} {enrollment.actor_id}"
    try:
        sys.stdout.write(f'Type "{expected}" to confirm first enrollment: ')
        sys.stdout.flush()
        entered = sys.stdin.readline().rstrip("\r\n")
    except (EOFError, OSError, UnicodeError, ValueError) as exc:
        raise ExtensionControlProofError(_INTERACTIVE_TERMINAL_REFUSAL) from exc
    if not hmac.compare_digest(entered, expected):
        raise ExtensionControlProofError("extension control enrollment confirmation did not match")


def _require_local_terminal_confirmation(guard_home: Path, enrollment: ExtensionControlEnrollment) -> None:
    if os.name == "nt":
        _require_windows_local_terminal_confirmation(guard_home, enrollment)
        return
    descriptor: int | None
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        descriptor = None
    try:
        _require_resident_local_terminal(guard_home, posix=_posix_terminal_signals(descriptor), windows=None)
        if descriptor is None:
            # Unreachable through the resident's verdicts; a closed controlling
            # terminal is never local. Keep the refusal rather than prompt
            # through a descriptor that does not exist.
            raise ExtensionControlProofError(_INTERACTIVE_TERMINAL_REFUSAL)
        expected = f"{_ENROLLMENT_CONFIRMATION_PREFIX} {enrollment.actor_id}"
        with os.fdopen(os.dup(descriptor), "w", encoding="utf-8") as terminal_output:
            terminal_output.write(f'Type "{expected}" to confirm first enrollment: ')
            terminal_output.flush()
        with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as terminal_input:
            entered = terminal_input.readline().rstrip("\r\n")
        if not hmac.compare_digest(entered, expected):
            raise ExtensionControlProofError("extension control enrollment confirmation did not match")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def issue_extension_control_enrollment_proof(
    guard_home: Path,
    enrollment: ExtensionControlEnrollment,
    *,
    approval_gate_input: ApprovalGateInput | None,
    session_nonce: str,
    now: str | None = None,
) -> ExtensionControlEnrollmentProof:
    """Issue a one-shot enrollment proof after direct local-terminal confirmation."""

    _require_local_terminal_confirmation(guard_home, enrollment)
    if not session_nonce.strip() or len(session_nonce) > _MAX_IDENTITY_LENGTH:
        raise ExtensionControlProofError("invalid proof session nonce")
    digest = enrollment.canonical_digest
    grant = require_extension_control(
        guard_home,
        approval_gate_input=approval_gate_input,
        action=EXTENSION_CONTROL_ENROLLMENT_ACTION,
        subject=digest,
        session_nonce=session_nonce,
        now=now,
    )
    return ExtensionControlEnrollmentProof(
        proof_id=secrets.token_hex(32),
        grant=grant,
        actor_id=enrollment.actor_id,
        catalog_digest=enrollment.catalog_digest,
        enrollment_digest=digest,
        nonce=enrollment.nonce,
        session_nonce=session_nonce,
    )


def validate_extension_control_enrollment_proof(
    proof: ExtensionControlEnrollmentProof,
    enrollment: ExtensionControlEnrollment,
) -> None:
    """Validate every immutable first-enrollment binding."""

    _validate_proof_identifier(proof.proof_id)
    observed = (proof.actor_id, proof.catalog_digest, proof.nonce)
    expected = (enrollment.actor_id, enrollment.catalog_digest, enrollment.nonce)
    if observed != expected or not hmac.compare_digest(proof.enrollment_digest, enrollment.canonical_digest):
        raise ExtensionControlProofError("extension control enrollment proof does not match enrollment")


def consume_extension_control_enrollment_proof(
    guard_home: Path,
    proof: ExtensionControlEnrollmentProof,
    enrollment: ExtensionControlEnrollment,
    *,
    now: str | None = None,
) -> None:
    """Consume one exact first-enrollment proof."""

    validate_extension_control_enrollment_proof(proof, enrollment)
    consume_extension_control_grant(
        guard_home,
        proof.grant,
        action=EXTENSION_CONTROL_ENROLLMENT_ACTION,
        subject=proof.enrollment_digest,
        session_nonce=proof.session_nonce,
        now=now,
    )


def _validate_proof_identifier(proof_id: str) -> None:
    if len(proof_id) != 64 or any(character not in "0123456789abcdef" for character in proof_id):
        raise ExtensionControlProofError("invalid extension control proof identifier")


@dataclass(frozen=True, slots=True)
class ExtensionControlMutation:
    previous_revision: int
    catalog_digest: str
    layers: tuple[ExtensionControlLayer, ...]
    actor_id: str
    idempotency_key: str
    nonce: str

    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # The resident reads the revision as a signed 64-bit integer.
        if type(self.previous_revision) is not int or not -(2**63) <= self.previous_revision < 2**63:
            raise ExtensionControlProofError("invalid previous revision")
        if not _transportable((self.catalog_digest, self.actor_id, self.idempotency_key, self.nonce)):
            raise ExtensionControlProofError("invalid mutation identity")
        digest = _resident_digest(
            lambda: mutation_digest(
                previous_revision=self.previous_revision,
                catalog_digest=self.catalog_digest,
                layers=self.layers,
                actor_id=self.actor_id,
                idempotency_key=self.idempotency_key,
                nonce=self.nonce,
            ),
            "invalid mutation identity",
        )
        object.__setattr__(self, "_digest", digest)

    @property
    def canonical_digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class ExtensionControlProof:
    proof_id: str
    grant: ApprovalGateGrant
    actor_id: str
    previous_revision: int
    catalog_digest: str
    canonical_diff_digest: str
    idempotency_key: str
    nonce: str
    session_nonce: str

    def __repr__(self) -> str:
        return "ExtensionControlProof(<redacted>)"


def issue_extension_control_proof(
    guard_home: Path,
    mutation: ExtensionControlMutation,
    *,
    approval_gate_input: ApprovalGateInput | None,
    session_nonce: str,
    now: str | None = None,
) -> ExtensionControlProof:
    """Issue one strict local proof bound to an exact canonical mutation."""

    if not session_nonce.strip() or len(session_nonce) > _MAX_IDENTITY_LENGTH:
        raise ExtensionControlProofError("invalid proof session nonce")
    digest = mutation.canonical_digest
    grant = require_extension_control(
        guard_home,
        approval_gate_input=approval_gate_input,
        action=EXTENSION_CONTROL_PROOF_ACTION,
        subject=digest,
        session_nonce=session_nonce,
        now=now,
    )
    proof_id = secrets.token_hex(32)
    return ExtensionControlProof(
        proof_id=proof_id,
        grant=grant,
        actor_id=mutation.actor_id,
        previous_revision=mutation.previous_revision,
        catalog_digest=mutation.catalog_digest,
        canonical_diff_digest=digest,
        idempotency_key=mutation.idempotency_key,
        nonce=mutation.nonce,
        session_nonce=session_nonce,
    )


def validate_extension_control_proof(
    proof: ExtensionControlProof,
    mutation: ExtensionControlMutation,
) -> None:
    """Validate every immutable proof binding without consuming its grant."""

    _validate_proof_identifier(proof.proof_id)
    expected = (
        mutation.actor_id,
        mutation.previous_revision,
        mutation.catalog_digest,
        mutation.idempotency_key,
        mutation.nonce,
    )
    observed = (
        proof.actor_id,
        proof.previous_revision,
        proof.catalog_digest,
        proof.idempotency_key,
        proof.nonce,
    )
    if observed != expected or not hmac.compare_digest(proof.canonical_diff_digest, mutation.canonical_digest):
        raise ExtensionControlProofError("extension control proof does not match mutation")


def consume_extension_control_proof(
    guard_home: Path,
    proof: ExtensionControlProof,
    mutation: ExtensionControlMutation,
    *,
    now: str | None = None,
) -> None:
    """Validate every mutation binding and consume the proof exactly once."""

    validate_extension_control_proof(proof, mutation)
    consume_extension_control_grant(
        guard_home,
        proof.grant,
        action=EXTENSION_CONTROL_PROOF_ACTION,
        subject=proof.canonical_diff_digest,
        session_nonce=proof.session_nonce,
        now=now,
    )
