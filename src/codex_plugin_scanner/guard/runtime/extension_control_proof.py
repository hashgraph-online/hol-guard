"""Fresh, mutation-bound approval proofs for extension-control authority changes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ..approval_gate import (
    ApprovalGateGrant,
    ApprovalGateInput,
    consume_extension_control_grant,
    require_extension_control,
)
from .extension_control_authority import layers_to_json
from .extension_control_contract import ExtensionControlLayer

EXTENSION_CONTROL_PREVIEW_SCHEMA = "guard.extension-control-preview.v1"
EXTENSION_CONTROL_PROOF_ACTION = "commit-layers"
EXTENSION_CONTROL_ENROLLMENT_SCHEMA = "guard.extension-control-enrollment.v1"
EXTENSION_CONTROL_ENROLLMENT_ACTION = "enroll-authority"
_MAX_IDENTITY_LENGTH = 256
_ENROLLMENT_CONFIRMATION_PREFIX = "ENROLL EXTENSION CONTROL"
_REMOTE_TERMINAL_ENVIRONMENT = ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "MOSH_CONNECTION")
_WINDOWS_SM_REMOTESESSION = 0x1000
_WINDOWS_WTS_CLIENT_PROTOCOL_TYPE = 16
_WINDOWS_REMOTE_SESSION_NAME_PREFIXES = ("rdp-tcp", "ica-", "pcoip-", "blast-")


class ExtensionControlProofError(PermissionError):
    """Raised when an extension-control proof is malformed or mismatched."""


@dataclass(frozen=True, slots=True)
class ExtensionControlEnrollment:
    catalog_digest: str
    actor_id: str
    nonce: str

    def __post_init__(self) -> None:
        if len(self.catalog_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.catalog_digest
        ):
            raise ExtensionControlProofError("invalid catalog digest")
        for value in (self.actor_id, self.nonce):
            if not value.strip() or len(value) > _MAX_IDENTITY_LENGTH:
                raise ExtensionControlProofError("invalid enrollment identity")

    @property
    def canonical_digest(self) -> str:
        payload = {
            "action": EXTENSION_CONTROL_ENROLLMENT_ACTION,
            "actor_id": self.actor_id,
            "catalog_digest": self.catalog_digest,
            "nonce": self.nonce,
            "schema_version": EXTENSION_CONTROL_ENROLLMENT_SCHEMA,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        framed = f"{EXTENSION_CONTROL_ENROLLMENT_SCHEMA}\x00{len(canonical)}\x00{canonical}"
        return hashlib.sha256(framed.encode("utf-8")).hexdigest()


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


def _terminal_session_is_local(terminal_name: str) -> bool:
    """Accept a local login record or a user-owned desktop PTY."""

    expected_user = _current_login_name()
    if expected_user is None:
        return False
    try:
        completed = subprocess.run(
            ("/usr/bin/who",),
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        completed = None
    terminal_id = Path(terminal_name).name
    if completed is not None:
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] != expected_user or fields[1] != terminal_id:
                continue
            return not (fields[-1].startswith("(") and fields[-1].endswith(")"))
    # GNOME and other desktop terminal emulators often do not create utmp
    # records. systemd-logind provides the session origin independently of
    # mutable child-process environment variables.
    try:
        session = subprocess.run(
            ("/usr/bin/loginctl", "show-session", "self", "--property=Remote", "--value"),
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if session.stdout.strip().lower() != "no":
        return False
    try:
        terminal = os.stat(terminal_name, follow_symlinks=True)
    except OSError:
        return False
    return terminal.st_uid == os.geteuid() and stat.S_ISCHR(terminal.st_mode)


def _terminal_descriptors_share_session(control_descriptor: int, input_descriptor: int) -> bool:
    """Confirm that stdin belongs to the foreground controlling-terminal session.

    Linux exposes ``/dev/tty`` as a character-device alias while stdin names
    the concrete PTY, so their device numbers are expected to differ.
    """

    try:
        return os.tcgetpgrp(control_descriptor) == os.tcgetpgrp(input_descriptor)
    except OSError:
        return False


def _windows_console_descriptor_is_interactive(descriptor: int) -> bool:
    """Require a descriptor backed by a Windows console, not a redirected pipe."""

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


def _windows_session_is_local() -> bool:
    """Require native Windows session APIs to identify a direct local session."""

    if os.name != "nt":
        return False
    session_name = os.environ.get("SESSIONNAME", "").strip().lower()
    if session_name.startswith(_WINDOWS_REMOTE_SESSION_NAME_PREFIXES):
        return False
    # RDP and several other remote-terminal providers expose CLIENTNAME even
    # when they do not use the standard RDP-Tcp session name.
    if os.environ.get("CLIENTNAME", "").strip():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return False
        user32 = win_dll("user32", use_last_error=True)
        get_system_metrics = user32.GetSystemMetrics
        get_system_metrics.argtypes = [ctypes.c_int]
        get_system_metrics.restype = ctypes.c_int
        if get_system_metrics(_WINDOWS_SM_REMOTESESSION):
            return False

        kernel32 = win_dll("kernel32", use_last_error=True)
        process_id_to_session_id = kernel32.ProcessIdToSessionId
        process_id_to_session_id.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        process_id_to_session_id.restype = wintypes.BOOL
        session_id = wintypes.DWORD()
        if not process_id_to_session_id(wintypes.DWORD(os.getpid()), ctypes.byref(session_id)):
            return False

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
                return False
            if not buffer.value or bytes_returned.value < ctypes.sizeof(ctypes.c_ushort):
                return False
            protocol_type = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ushort)).contents.value
            # WTSClientProtocolType is zero for the local console and nonzero
            # for RDP/ICA/other remote session protocols.
            return protocol_type == 0
        finally:
            if buffer.value:
                with suppress(OSError, TypeError, ValueError):
                    free_wts_memory(buffer)
    except (AttributeError, ImportError, OSError, TypeError, ValueError, OverflowError):
        return False


def _require_windows_local_terminal_confirmation(enrollment: ExtensionControlEnrollment) -> None:
    """Confirm through the current Windows console without accepting redirected input."""

    try:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal")
        input_descriptor = sys.stdin.fileno()
        output_descriptor = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError) as exc:
        raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal") from exc
    if not _windows_session_is_local():
        raise ExtensionControlProofError("extension control enrollment requires a local terminal")
    if not (
        _windows_console_descriptor_is_interactive(input_descriptor)
        and _windows_console_descriptor_is_interactive(output_descriptor)
    ):
        raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal")
    expected = f"{_ENROLLMENT_CONFIRMATION_PREFIX} {enrollment.actor_id}"
    try:
        sys.stdout.write(f'Type "{expected}" to confirm first enrollment: ')
        sys.stdout.flush()
        entered = sys.stdin.readline().rstrip("\r\n")
    except (EOFError, OSError, UnicodeError, ValueError) as exc:
        raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal") from exc
    if not hmac.compare_digest(entered, expected):
        raise ExtensionControlProofError("extension control enrollment confirmation did not match")


def _require_local_terminal_confirmation(enrollment: ExtensionControlEnrollment) -> None:
    if any(os.environ.get(name) for name in _REMOTE_TERMINAL_ENVIRONMENT):
        raise ExtensionControlProofError("extension control enrollment requires a local terminal")
    if os.name == "nt":
        _require_windows_local_terminal_confirmation(enrollment)
        return
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal") from exc
    try:
        terminal_name = os.ttyname(descriptor)
        if sys.stdin.isatty():
            # Opening /dev/tty can preserve that alias rather than returning
            # the concrete /dev/pts or /dev/ttys device. stdin identifies the
            # same controlling terminal for an interactive CLI invocation.
            stdin_descriptor = sys.stdin.fileno()
            if not _terminal_descriptors_share_session(descriptor, stdin_descriptor):
                raise ExtensionControlProofError("extension control enrollment requires one interactive local terminal")
            terminal_name = os.ttyname(stdin_descriptor)
        if not os.isatty(descriptor) or not _terminal_session_is_local(terminal_name):
            raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal")
        expected = f"{_ENROLLMENT_CONFIRMATION_PREFIX} {enrollment.actor_id}"
        with os.fdopen(os.dup(descriptor), "w", encoding="utf-8") as terminal_output:
            terminal_output.write(f'Type "{expected}" to confirm first enrollment: ')
            terminal_output.flush()
        with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as terminal_input:
            entered = terminal_input.readline().rstrip("\r\n")
        if not hmac.compare_digest(entered, expected):
            raise ExtensionControlProofError("extension control enrollment confirmation did not match")
    finally:
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

    _require_local_terminal_confirmation(enrollment)
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

    def _canonical_layers(self) -> tuple[ExtensionControlLayer, ...]:
        return tuple(
            ExtensionControlLayer(
                schema_version=layer.schema_version,
                kind=layer.kind,
                catalog_digest=layer.catalog_digest,
                global_lockdown=layer.global_lockdown,
                controls=tuple(
                    sorted(
                        layer.controls,
                        key=lambda control: (
                            control.target.kind.value,
                            control.target.target_id,
                            control.state.value,
                        ),
                    )
                ),
            )
            for layer in sorted(self.layers, key=lambda value: value.kind.value)
        )

    def __post_init__(self) -> None:
        if type(self.previous_revision) is not int or self.previous_revision < 0:
            raise ExtensionControlProofError("invalid previous revision")
        if len(self.catalog_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.catalog_digest
        ):
            raise ExtensionControlProofError("invalid catalog digest")
        for value in (self.actor_id, self.idempotency_key, self.nonce):
            if not value.strip() or len(value) > _MAX_IDENTITY_LENGTH:
                raise ExtensionControlProofError("invalid mutation identity")

    @property
    def canonical_digest(self) -> str:
        canonical_layers = self._canonical_layers()
        payload = {
            "action": EXTENSION_CONTROL_PROOF_ACTION,
            "actor_id": self.actor_id,
            "catalog_digest": self.catalog_digest,
            "idempotency_key": self.idempotency_key,
            "layers": json.loads(layers_to_json(canonical_layers)),
            "nonce": self.nonce,
            "previous_revision": self.previous_revision,
            "schema_version": EXTENSION_CONTROL_PREVIEW_SCHEMA,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        framed = f"{EXTENSION_CONTROL_PREVIEW_SCHEMA}\x00{len(canonical)}\x00{canonical}"
        return hashlib.sha256(framed.encode("utf-8")).hexdigest()


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
