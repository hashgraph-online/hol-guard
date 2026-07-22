"""Trusted subprocess boundary for HOL Guard package maintenance."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import math
import ntpath
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO

from packaging.version import InvalidVersion, Version

from ..mdm.network import platform_system_proxies
from ..redaction import redact_sensitive_text
from ..shims import _trusted_python_flags
from ..windows_paths import (
    trusted_windows_roaming_appdata,
    trusted_windows_system_directories,
    trusted_windows_system_executable,
    trusted_windows_user_profile,
)

_DEFAULT_INDEX_URL = "https://pypi.org/simple"
_DEFAULT_TIMEOUT_SECONDS = 10 * 60.0
_DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024
_PROCESS_MONITOR_INTERVAL_SECONDS = 0.01
_PROCESS_TERMINATE_GRACE_SECONDS = 0.25
_STREAM_THREAD_JOIN_SECONDS = 1.0
_RUNTIME_DIR_NAME = "update-runtime"
_TRUSTED_SCRIPT_BOOTSTRAP = (
    "import json,sys; "
    "sys.path[:0]=json.loads(sys.argv.pop(1)); "
    "source=sys.argv.pop(1); "
    "sys.argv[0]='<guard-update>'; "
    "exec(compile(source, '<guard-update>', 'exec'), {'__name__':'__main__'})"
)
_TRUSTED_MODULE_BOOTSTRAP = (
    "import json,runpy,sys; "
    "sys.path[:0]=json.loads(sys.argv.pop(1)); "
    "module=sys.argv.pop(1); "
    "sys.argv[0]=module; "
    "runpy.run_module(module, run_name='__main__', alter_sys=True)"
)
_DISTRIBUTION_QUERY_SCRIPT = """
from __future__ import annotations

import importlib.metadata
import json
import stat
from pathlib import Path

distribution = importlib.metadata.distribution("hol-guard")
root = Path(distribution.locate_file("")).resolve()
direct_url = None
direct_url_entries = [
    entry
    for entry in (distribution.files or ())
    if entry.as_posix().endswith(".dist-info/direct_url.json")
]
if len(direct_url_entries) > 1:
    raise RuntimeError("multiple direct_url metadata files")
if direct_url_entries:
    direct_url_path = Path(distribution.locate_file(direct_url_entries[0])).resolve(strict=True)
    direct_url_path.relative_to(root)
    direct_url_stat = direct_url_path.stat()
    if not stat.S_ISREG(direct_url_stat.st_mode) or not 0 < direct_url_stat.st_size <= 65536:
        raise RuntimeError("invalid direct_url metadata file")
    direct_url = json.loads(direct_url_path.read_text(encoding="utf-8"))
    if not isinstance(direct_url, dict):
        raise RuntimeError("invalid direct_url metadata payload")
print(json.dumps({
    "direct_url": direct_url,
    "name": distribution.metadata.get("Name"),
    "version": distribution.version,
    "root": str(root),
}, sort_keys=True))
""".strip()
_PIP_QUERY_SCRIPT = """
from __future__ import annotations

import json
from pathlib import Path

import pip

print(json.dumps({"root": str(Path(pip.__file__).resolve())}, sort_keys=True))
""".strip()

_PRESERVED_OS_ENV_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "TZ",
        "USER",
        "USERNAME",
    }
)

_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_ALL = 0x00000007
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_ID_INFO_CLASS = 0x12
_WINDOWS_CREATE_SUSPENDED = 0x00000004
_WINDOWS_JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
_WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
_WINDOWS_TH32CS_SNAPTHREAD = 0x00000004
_WINDOWS_THREAD_SUSPEND_RESUME = 0x0002
_WINDOWS_RESUME_THREAD_FAILED = 0xFFFFFFFF
_WINDOWS_ERROR_NO_MORE_FILES = 18


class UpdateSubprocessError(RuntimeError):
    """A trusted updater subprocess could not be prepared or completed."""

    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str | None = None) -> None:
        self.reason_code = reason_code
        self.detail = redact_sensitive_text(detail or "")[:512]
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class UpdateSource:
    """One explicit installer source whose public identity contains no URL."""

    kind: str
    index_url: str
    fingerprint: str

    @property
    def public_name(self) -> str:
        return "pypi" if self.kind == "pypi" else "managed_index"


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    """Content-bound executable identity retained across every update phase."""

    launch_path: Path
    canonical_path: Path
    device: int
    inode: int
    sha256: str
    size: int
    mode: int
    shebang_sha256: str | None

    @classmethod
    def capture(
        cls,
        command: str | Path,
        *,
        search_path: str | None,
        cwd: Path,
        missing_reason: str,
        untrusted_reason: str,
    ) -> ExecutableIdentity:
        requested = Path(command).expanduser()
        if not requested.is_absolute():
            located = shutil.which(str(command), path=search_path)
            if located is None:
                raise UpdateSubprocessError(missing_reason)
            requested = Path(located)
        if not requested.is_absolute():
            raise UpdateSubprocessError(untrusted_reason)
        _ = cwd
        try:
            snapshot = _inspect_executable_path(requested)
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateSubprocessError(untrusted_reason) from error
        if snapshot.sha256 is None:
            raise UpdateSubprocessError(untrusted_reason)
        return cls(
            launch_path=requested,
            canonical_path=snapshot.canonical_path,
            device=snapshot.device,
            inode=snapshot.inode,
            sha256=snapshot.sha256,
            size=snapshot.size,
            mode=snapshot.mode,
            shebang_sha256=_snapshot_shebang_sha256(snapshot),
        )

    def revalidate(self, *, cwd: Path, changed_reason: str) -> None:
        _ = cwd
        try:
            current = _inspect_executable_path(self.launch_path)
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateSubprocessError(changed_reason) from error
        current_values = (
            current.canonical_path,
            current.device,
            current.inode,
            current.sha256,
            current.size,
            current.mode,
            _snapshot_shebang_sha256(current),
        )
        expected_values = (
            self.canonical_path,
            self.device,
            self.inode,
            self.sha256,
            self.size,
            self.mode,
            self.shebang_sha256,
        )
        if current_values != expected_values:
            raise UpdateSubprocessError(changed_reason)


@dataclass(frozen=True, slots=True)
class FilesystemIdentity:
    """Descriptor-bound identity for a trusted file or directory."""

    path: Path
    canonical_path: Path
    kind: str
    device: int
    inode: int
    mode: int
    size: int
    sha256: str | None

    @classmethod
    def capture(cls, path: Path, *, kind: str, failure_reason: str) -> FilesystemIdentity:
        try:
            snapshot = _inspect_filesystem_path(path, kind=kind)
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateSubprocessError(failure_reason) from error
        return cls(
            path=path,
            canonical_path=snapshot.canonical_path,
            kind=kind,
            device=snapshot.device,
            inode=snapshot.inode,
            mode=snapshot.mode,
            size=snapshot.size,
            sha256=snapshot.sha256,
        )

    def revalidate(self, *, changed_reason: str) -> None:
        try:
            snapshot = _inspect_filesystem_path(self.path, kind=self.kind)
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateSubprocessError(changed_reason) from error
        current = (
            snapshot.canonical_path,
            snapshot.device,
            snapshot.inode,
            snapshot.mode,
            snapshot.size,
            snapshot.sha256,
        )
        expected = (
            self.canonical_path,
            self.device,
            self.inode,
            self.mode,
            self.size,
            self.sha256,
        )
        if current != expected:
            raise UpdateSubprocessError(changed_reason)


@dataclass(frozen=True, slots=True)
class TrustedProcessResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    output_limited: bool = False


@dataclass(frozen=True, slots=True)
class InstalledDistribution:
    name: str
    version: str
    root: Path
    direct_url: dict[str, object] | None = None


@dataclass(slots=True)
class _BoundedStreamCapture:
    data: bytearray = field(default_factory=bytearray)
    limited: bool = False
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_limited: bool
    stderr_limited: bool


@dataclass(frozen=True, slots=True)
class _FilesystemSnapshot:
    canonical_path: Path
    device: int
    inode: int
    mode: int
    size: int
    sha256: str | None
    prefix: bytes | None


class _WindowsJobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _WindowsJobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _WindowsJobObjectBasicLimitInformation),
        ("io_info", _WindowsIoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class _WindowsThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


@dataclass(slots=True)
class _WindowsProcessJob:
    handle: int
    closed: bool = False

    def terminate(self) -> None:
        if self.closed:
            return
        kernel32 = _windows_kernel32()
        terminate_job = kernel32.TerminateJobObject
        terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminate_job.restype = wintypes.BOOL
        if not terminate_job(wintypes.HANDLE(self.handle), 1):
            raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")

    def close(self) -> None:
        if self.closed:
            return
        kernel32 = _windows_kernel32()
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        if not close_handle(wintypes.HANDLE(self.handle)):
            raise OSError(ctypes.get_last_error(), "CloseHandle failed")
        self.closed = True


@dataclass(frozen=True, slots=True)
class _SpawnedProcess:
    process: subprocess.Popen[bytes]
    windows_job: _WindowsProcessJob | None


@dataclass(frozen=True, slots=True)
class TrustedUpdateContext:
    """Immutable execution contract shared by all updater subprocesses."""

    python: ExecutableIdentity
    installer_kind: str
    installer: ExecutableIdentity | None
    installer_interpreters: tuple[ExecutableIdentity, ...]
    source: UpdateSource
    neutral_cwd: Path
    neutral_home: Path
    environment: Mapping[str, str]
    install_prefix: Path
    python_import_paths: tuple[Path, ...]
    neutral_identities: tuple[FilesystemIdentity, ...]
    python_import_identities: tuple[FilesystemIdentity, ...]
    ca_bundle_identity: FilesystemIdentity | None
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT_BYTES

    def python_command(self, script: str, *args: str) -> list[str]:
        return [
            str(self.python.launch_path),
            *_trusted_python_flags(),
            "-S",
            "-c",
            _TRUSTED_SCRIPT_BOOTSTRAP,
            self._python_import_paths_json(),
            script,
            *args,
        ]

    def python_module_command(self, module: str, *args: str) -> list[str]:
        if not module or not all(part.isidentifier() for part in module.split(".")):
            raise UpdateSubprocessError("update_installer_command_invalid")
        return [
            str(self.python.launch_path),
            *_trusted_python_flags(),
            "-S",
            "-c",
            _TRUSTED_MODULE_BOOTSTRAP,
            self._python_import_paths_json(),
            module,
            *args,
        ]

    def _python_import_paths_json(self) -> str:
        return json.dumps([str(path) for path in self.python_import_paths], separators=(",", ":"))

    def build_installer_command(self, display_command: list[str]) -> list[str]:
        """Translate an internal display argv into its isolated execution argv."""

        if self.installer_kind == "pip":
            if len(display_command) < 4 or display_command[1:3] != ["-m", "pip"]:
                raise UpdateSubprocessError("update_installer_command_invalid")
            pip_args = display_command[3:]
            command = self.python_module_command(
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                *pip_args,
            )
            return _append_pip_source(command, self.source.index_url)

        if self.installer is None:
            raise UpdateSubprocessError("update_installer_untrusted")
        if not display_command or display_command[0] != self.installer_kind:
            raise UpdateSubprocessError("update_installer_command_invalid")
        args = display_command[1:]
        if self.installer_kind == "uv":
            return _uv_execution_command(
                str(self.installer.launch_path),
                args,
                python=str(self.python.launch_path),
                index_url=self.source.index_url,
            )
        if self.installer_kind == "pipx":
            return _pipx_execution_command(
                str(self.installer.launch_path),
                args,
                python=str(self.python.launch_path),
                index_url=self.source.index_url,
            )
        raise UpdateSubprocessError("update_installer_untrusted")

    def run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        output_limit_bytes: int | None = None,
        allow_windows_job_breakaway: bool = False,
    ) -> TrustedProcessResult:
        """Revalidate the bound launcher and run with the exact trusted context."""

        if not command or not Path(command[0]).is_absolute():
            raise UpdateSubprocessError("update_installer_command_invalid")
        for identity in self.neutral_identities:
            identity.revalidate(changed_reason="update_neutral_context_changed")
        for identity in self.python_import_identities:
            identity.revalidate(changed_reason="update_python_import_path_changed")
        if self.ca_bundle_identity is not None:
            self.ca_bundle_identity.revalidate(changed_reason="update_ca_bundle_changed")
        for interpreter in self.installer_interpreters:
            interpreter.revalidate(
                cwd=self.neutral_cwd,
                changed_reason="update_installer_interpreter_identity_changed",
            )
        launcher = self._launcher_for(command[0])
        launcher.revalidate(
            cwd=self.neutral_cwd,
            changed_reason=(
                "update_python_identity_changed" if launcher is self.python else "update_installer_identity_changed"
            ),
        )
        limit = self.output_limit_bytes if output_limit_bytes is None else output_limit_bytes
        if limit < 0:
            raise UpdateSubprocessError("update_installer_command_invalid")
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        if not math.isfinite(timeout) or timeout <= 0:
            raise UpdateSubprocessError("update_installer_timeout")
        result = _run_bounded_process(
            command,
            input_text=input_text,
            cwd=self.neutral_cwd,
            environment=self.environment,
            timeout_seconds=timeout,
            output_limit_bytes=limit,
            allow_windows_job_breakaway=allow_windows_job_breakaway,
        )
        sensitive_values = tuple(
            value
            for value in (
                self.source.index_url if self.source.kind == "managed_index" else None,
                self.environment.get("HTTP_PROXY"),
                self.environment.get("HTTPS_PROXY"),
            )
            if isinstance(value, str) and value
        )
        stdout, stdout_redaction_limited = _bounded_redacted_text(
            result.stdout,
            limit,
            sensitive_values=sensitive_values,
        )
        stderr, stderr_redaction_limited = _bounded_redacted_text(
            result.stderr,
            limit,
            sensitive_values=sensitive_values,
        )
        return TrustedProcessResult(
            args=tuple(command),
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            output_limited=(
                result.stdout_limited or result.stderr_limited or stdout_redaction_limited or stderr_redaction_limited
            ),
        )

    def verify_pip_origin(self) -> None:
        if self.installer_kind != "pip":
            return
        result = self.run(self.python_command(_PIP_QUERY_SCRIPT), timeout_seconds=30.0, output_limit_bytes=8192)
        payload = _single_json_object(result, failure_reason="update_installer_untrusted")
        root_value = payload.get("root")
        if not isinstance(root_value, str):
            raise UpdateSubprocessError("update_installer_untrusted")
        try:
            pip_path = Path(root_value).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise UpdateSubprocessError("update_installer_untrusted") from error
        if not _path_is_within(pip_path, self.install_prefix):
            raise UpdateSubprocessError("update_installer_untrusted")

    def query_distribution(self) -> InstalledDistribution:
        result = self.run(
            self.python_command(_DISTRIBUTION_QUERY_SCRIPT),
            timeout_seconds=30.0,
            output_limit_bytes=8192,
        )
        payload = _single_json_object(result, failure_reason="update_version_output_invalid")
        if set(payload) != {"direct_url", "name", "root", "version"}:
            raise UpdateSubprocessError("update_version_output_invalid")
        name = payload.get("name")
        version = payload.get("version")
        root_value = payload.get("root")
        direct_url_value = payload.get("direct_url")
        if not isinstance(name, str) or name.lower().replace("_", "-") != "hol-guard":
            raise UpdateSubprocessError("update_version_output_invalid")
        if not isinstance(version, str):
            raise UpdateSubprocessError("update_version_output_invalid")
        try:
            normalized_version = str(Version(version))
        except InvalidVersion as error:
            raise UpdateSubprocessError("update_version_output_invalid") from error
        if not isinstance(root_value, str):
            raise UpdateSubprocessError("update_version_output_invalid")
        try:
            root = Path(root_value).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise UpdateSubprocessError("update_version_output_invalid") from error
        if not _path_is_within(root, self.install_prefix):
            raise UpdateSubprocessError("update_package_origin_mismatch")
        if direct_url_value is not None and not isinstance(direct_url_value, dict):
            raise UpdateSubprocessError("update_version_output_invalid")
        direct_url = None
        if isinstance(direct_url_value, dict):
            direct_url = {str(key): value for key, value in direct_url_value.items() if isinstance(key, str)}
            if len(direct_url) != len(direct_url_value):
                raise UpdateSubprocessError("update_version_output_invalid")
        return InstalledDistribution(
            name="hol-guard",
            version=normalized_version,
            root=root,
            direct_url=direct_url,
        )

    def _launcher_for(self, command_path: str) -> ExecutableIdentity:
        candidate = Path(command_path)
        if candidate == self.python.launch_path:
            return self.python
        if self.installer is not None and candidate == self.installer.launch_path:
            return self.installer
        raise UpdateSubprocessError("update_installer_command_invalid")


def build_trusted_update_context(
    *,
    guard_home: Path,
    workspace_dir: Path | None,
    installer_kind: str,
    source_url: str | None = None,
    source_kind: str | None = None,
    proxy_mode: str = "system",
    proxy_url: str | None = None,
    ca_bundle_path: str | None = None,
) -> TrustedUpdateContext:
    """Resolve and bind the updater's execution identity exactly once."""

    if installer_kind not in {"pip", "pipx", "uv"}:
        raise UpdateSubprocessError("update_installer_untrusted")
    source = _build_update_source(source_url, source_kind=source_kind)
    neutral_cwd, neutral_home, neutral_tmp = _prepare_neutral_directories(guard_home)
    trusted_search_path = _trusted_runtime_search_path(installer_kind=installer_kind)
    python_path = Path(sys.executable).expanduser()
    if not python_path.is_absolute():
        raise UpdateSubprocessError("update_python_untrusted")
    python = ExecutableIdentity.capture(
        python_path,
        search_path=None,
        cwd=neutral_cwd,
        missing_reason="update_python_untrusted",
        untrusted_reason="update_python_untrusted",
    )
    installer = None
    installer_interpreters: tuple[ExecutableIdentity, ...] = ()
    if installer_kind != "pip":
        manager_search_path = _trusted_manager_search_path(
            installer_kind=installer_kind,
            workspace_dir=workspace_dir,
            guard_home=guard_home,
        )
        manager_launch_path = _resolve_manager_launch_path(installer_kind, manager_search_path)
        installer = ExecutableIdentity.capture(
            manager_launch_path,
            search_path=None,
            cwd=neutral_cwd,
            missing_reason="update_installer_not_found",
            untrusted_reason="update_installer_untrusted",
        )
        try:
            excluded_installer_roots = [guard_home.expanduser().resolve()]
            if workspace_dir is not None:
                excluded_installer_roots.append(workspace_dir.expanduser().resolve())
        except (OSError, RuntimeError) as error:
            raise UpdateSubprocessError("update_installer_untrusted") from error
        if any(_path_is_within(installer.canonical_path, root) for root in excluded_installer_roots):
            raise UpdateSubprocessError("update_installer_untrusted")
        installer_interpreters = _capture_installer_interpreters(
            installer,
            search_path=trusted_search_path,
            cwd=neutral_cwd,
            excluded_roots=tuple(excluded_installer_roots),
        )
    install_prefix = Path(sys.prefix).expanduser().resolve()
    python_import_paths = _trusted_python_import_paths()
    environment = _trusted_environment(
        path=trusted_search_path,
        neutral_home=neutral_home,
        neutral_tmp=neutral_tmp,
        installer_kind=installer_kind,
        python=python.launch_path,
        proxy_mode=proxy_mode,
        proxy_url=proxy_url,
        ca_bundle_path=ca_bundle_path,
    )
    if os.name == "nt":
        command_processor = ExecutableIdentity.capture(
            Path(environment["COMSPEC"]),
            search_path=None,
            cwd=neutral_cwd,
            missing_reason="update_runtime_untrusted",
            untrusted_reason="update_runtime_untrusted",
        )
        installer_interpreters = (*installer_interpreters, command_processor)
    neutral_identities = tuple(
        FilesystemIdentity.capture(
            path,
            kind="directory",
            failure_reason="update_neutral_cwd_unavailable",
        )
        for path in (neutral_cwd, neutral_home, neutral_tmp)
    )
    python_import_identities = tuple(
        FilesystemIdentity.capture(
            path,
            kind="directory",
            failure_reason="update_python_untrusted",
        )
        for path in python_import_paths
    )
    ca_bundle_identity = (
        FilesystemIdentity.capture(
            Path(environment["SSL_CERT_FILE"]),
            kind="file",
            failure_reason="update_source_invalid",
        )
        if "SSL_CERT_FILE" in environment
        else None
    )
    context = TrustedUpdateContext(
        python=python,
        installer_kind=installer_kind,
        installer=installer,
        installer_interpreters=installer_interpreters,
        source=source,
        neutral_cwd=neutral_cwd,
        neutral_home=neutral_home,
        environment=MappingProxyType(environment),
        install_prefix=install_prefix,
        python_import_paths=python_import_paths,
        neutral_identities=neutral_identities,
        python_import_identities=python_import_identities,
        ca_bundle_identity=ca_bundle_identity,
    )
    context.verify_pip_origin()
    return context


def _build_update_source(source_url: str | None, *, source_kind: str | None) -> UpdateSource:
    candidate = source_url or _DEFAULT_INDEX_URL
    if candidate != candidate.strip() or any(character.isspace() for character in candidate):
        raise UpdateSubprocessError("update_source_invalid")
    try:
        parsed = urllib.parse.urlsplit(candidate)
        _ = parsed.port
    except ValueError as error:
        raise UpdateSubprocessError("update_source_invalid") from error
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise UpdateSubprocessError("update_source_invalid")
    normalized = urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/") or "/", "", ""))
    kind = source_kind or ("pypi" if normalized == _DEFAULT_INDEX_URL else "managed_index")
    if kind not in {"pypi", "managed_index"}:
        raise UpdateSubprocessError("update_source_invalid")
    if kind == "pypi" and normalized != _DEFAULT_INDEX_URL:
        raise UpdateSubprocessError("update_source_mismatch")
    fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return UpdateSource(kind=kind, index_url=normalized, fingerprint=fingerprint)


def _prepare_neutral_directories(guard_home: Path) -> tuple[Path, Path, Path]:
    try:
        expanded_home = guard_home.expanduser()
        if not expanded_home.is_absolute():
            raise UpdateSubprocessError("update_neutral_cwd_unavailable")
        lexical_home = Path(os.path.normpath(str(expanded_home)))
        _reject_linked_path_components(lexical_home)
        lexical_home.mkdir(parents=True, exist_ok=True)
        _reject_linked_path_components(lexical_home)
        home_metadata = lexical_home.lstat()
        if (
            not stat.S_ISDIR(home_metadata.st_mode)
            or stat.S_ISLNK(home_metadata.st_mode)
            or _metadata_is_reparse(home_metadata)
        ):
            raise UpdateSubprocessError("update_neutral_cwd_unavailable")
        runtime = lexical_home / _RUNTIME_DIR_NAME
        neutral_home = runtime / "home"
        neutral_tmp = runtime / "tmp"
        for directory in (runtime, neutral_home, neutral_tmp):
            try:
                metadata = directory.lstat()
            except FileNotFoundError:
                directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
                raise UpdateSubprocessError("update_neutral_cwd_unavailable")
            if os.name != "nt":
                directory.chmod(0o700)
                metadata = directory.stat()
                if metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
                    raise UpdateSubprocessError("update_neutral_cwd_unavailable")
        return runtime, neutral_home, neutral_tmp
    except UpdateSubprocessError:
        raise
    except (OSError, RuntimeError) as error:
        raise UpdateSubprocessError("update_neutral_cwd_unavailable") from error


def _reject_linked_path_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
            raise UpdateSubprocessError("update_neutral_cwd_unavailable")


def _metadata_is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)


def _inspect_filesystem_path(path: Path, *, kind: str) -> _FilesystemSnapshot:
    """Inspect one path through a non-following descriptor and reject entry races."""

    if kind not in {"directory", "file"} or not path.is_absolute():
        raise ValueError("invalid trusted filesystem identity")
    if os.name == "nt":
        return _inspect_windows_filesystem_path(path, kind=kind)
    entry_metadata = path.lstat()
    if stat.S_ISLNK(entry_metadata.st_mode):
        raise OSError("trusted path is a symbolic link")
    expected_type = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    if not expected_type(entry_metadata.st_mode):
        raise OSError("trusted path has an invalid type")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if kind == "directory":
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not expected_type(metadata.st_mode):
            raise OSError("trusted path changed type")
        if (entry_metadata.st_dev, entry_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise OSError("trusted path changed during inspection")
        digest = None
        prefix = None
        if kind == "file":
            hasher = hashlib.sha256()
            prefix_buffer = bytearray()
            while chunk := os.read(descriptor, 1024 * 1024):
                hasher.update(chunk)
                if len(prefix_buffer) < 4096:
                    prefix_buffer.extend(chunk[: 4096 - len(prefix_buffer)])
            digest = hasher.hexdigest()
            prefix = bytes(prefix_buffer)
    finally:
        os.close(descriptor)
    canonical_path = path.resolve(strict=True)
    canonical_metadata = canonical_path.stat()
    if (canonical_metadata.st_dev, canonical_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise OSError("trusted path changed after inspection")
    return _FilesystemSnapshot(
        canonical_path=canonical_path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        size=metadata.st_size if kind == "file" else 0,
        sha256=digest,
        prefix=prefix,
    )


def _inspect_windows_filesystem_path(path: Path, *, kind: str) -> _FilesystemSnapshot:
    """Bind a Windows file or directory through a non-following Win32 handle."""

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("windows_handle_api_unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _FileId128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FileId128),
        ]

    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    get_extended_information = kernel32.GetFileInformationByHandleEx
    get_extended_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_extended_information.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD
    read_file = kernel32.ReadFile
    read_file.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    read_file.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    desired_access = _WINDOWS_GENERIC_READ if kind == "file" else _WINDOWS_FILE_READ_ATTRIBUTES
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if kind == "directory":
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    handle = create_file(
        str(path),
        desired_access,
        _WINDOWS_FILE_SHARE_ALL,
        None,
        _WINDOWS_OPEN_EXISTING,
        flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise OSError("trusted Windows path could not be opened")
    try:
        information = _ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise OSError("trusted Windows path identity is unavailable")
        attributes = int(information.dwFileAttributes)
        is_directory = bool(attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if bool(kind == "directory") != is_directory or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("trusted Windows path has an invalid type")
        canonical_path = _windows_final_path(handle, get_final_path)
        digest, prefix = _windows_handle_sha256(handle, read_file) if kind == "file" else (None, None)
        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        file_id_information = _FileIdInfo()
        extended_identity_available = bool(
            get_extended_information(
                handle,
                _WINDOWS_FILE_ID_INFO_CLASS,
                ctypes.byref(file_id_information),
                ctypes.sizeof(file_id_information),
            )
        )
        extended_inode = int.from_bytes(bytes(file_id_information.FileId.Identifier), "little")
        if extended_identity_available and extended_inode != 0:
            device = int(file_id_information.VolumeSerialNumber)
            inode = extended_inode
        else:
            device = int(information.dwVolumeSerialNumber)
            inode = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
        return _FilesystemSnapshot(
            canonical_path=canonical_path,
            device=device,
            inode=inode,
            mode=attributes,
            size=size if kind == "file" else 0,
            sha256=digest,
            prefix=prefix,
        )
    finally:
        _ = close_handle(handle)


def _windows_final_path(
    handle: object,
    get_final_path: Callable[[object, object, int, int], int],
) -> Path:
    capacity = 32_768
    for _attempt in range(2):
        buffer = ctypes.create_unicode_buffer(capacity)
        length = int(get_final_path(handle, buffer, capacity, 0))
        if length <= 0:
            raise OSError("trusted Windows path canonicalization failed")
        if length < capacity:
            value = str(buffer.value)
            if value.startswith("\\\\?\\UNC\\"):
                value = "\\\\" + value[8:]
            elif value.startswith("\\\\?\\"):
                value = value[4:]
            canonical_path = Path(ntpath.normpath(value))
            if not canonical_path.is_absolute():
                raise OSError("trusted Windows path canonicalization failed")
            return canonical_path
        capacity = length + 1
    raise OSError("trusted Windows path canonicalization failed")


def _windows_handle_sha256(
    handle: object,
    read_file: Callable[[object, object, int, object, object], int],
) -> tuple[str, bytes]:
    hasher = hashlib.sha256()
    prefix = bytearray()
    buffer = ctypes.create_string_buffer(1024 * 1024)
    while True:
        bytes_read = wintypes.DWORD()
        succeeded = read_file(
            handle,
            buffer,
            len(buffer),
            ctypes.byref(bytes_read),
            None,
        )
        if not succeeded:
            raise OSError("trusted Windows file could not be read")
        count = int(bytes_read.value)
        if count == 0:
            return hasher.hexdigest(), bytes(prefix)
        chunk = buffer.raw[:count]
        hasher.update(chunk)
        if len(prefix) < 4096:
            prefix.extend(chunk[: 4096 - len(prefix)])


def _inspect_executable_path(path: Path) -> _FilesystemSnapshot:
    """Hash one executable without metadata-keyed caches and bind its launch target."""

    if not path.is_absolute():
        raise OSError("trusted executable path is not absolute")
    if os.name == "nt":
        entry_metadata = path.lstat()
        if stat.S_ISLNK(entry_metadata.st_mode) or _metadata_is_reparse(entry_metadata):
            raise OSError("trusted Windows executable is a reparse point")
    canonical_path = path.resolve(strict=True)
    if os.name != "nt" and not os.access(canonical_path, os.X_OK):
        raise OSError("trusted executable is not executable")
    snapshot = _inspect_filesystem_path(canonical_path, kind="file")
    if path.resolve(strict=True) != snapshot.canonical_path:
        raise OSError("trusted executable target changed during inspection")
    return snapshot


def _snapshot_shebang_sha256(snapshot: _FilesystemSnapshot) -> str | None:
    prefix = snapshot.prefix or b""
    if not prefix.startswith(b"#!"):
        return None
    first_line = prefix.splitlines()[0]
    try:
        shebang = first_line[2:].decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    return hashlib.sha256(shebang.encode("utf-8")).hexdigest() if shebang else None


def _capture_installer_interpreters(
    installer: ExecutableIdentity,
    *,
    search_path: str,
    cwd: Path,
    excluded_roots: tuple[Path, ...],
) -> tuple[ExecutableIdentity, ...]:
    """Bind script interpreters that the kernel will execute for a manager launcher."""

    tokens = _installer_shebang_tokens(installer, cwd=cwd)
    if not tokens:
        return ()
    interpreter_path = Path(tokens[0]).expanduser()
    if not interpreter_path.is_absolute():
        raise UpdateSubprocessError("update_installer_interpreter_untrusted")
    identities = [
        ExecutableIdentity.capture(
            interpreter_path,
            search_path=None,
            cwd=cwd,
            missing_reason="update_installer_interpreter_untrusted",
            untrusted_reason="update_installer_interpreter_untrusted",
        )
    ]
    if interpreter_path.name == "env":
        env_args = tokens[1:]
        if env_args[:1] == ["-S"]:
            env_args = env_args[1:]
        if not env_args or env_args[0].startswith("-") or "=" in env_args[0]:
            raise UpdateSubprocessError("update_installer_interpreter_untrusted")
        identities.append(
            ExecutableIdentity.capture(
                env_args[0],
                search_path=search_path,
                cwd=cwd,
                missing_reason="update_installer_interpreter_untrusted",
                untrusted_reason="update_installer_interpreter_untrusted",
            )
        )
    if any(_path_is_within(identity.canonical_path, root) for identity in identities for root in excluded_roots):
        raise UpdateSubprocessError("update_installer_interpreter_untrusted")
    return tuple(identities)


def _installer_shebang_tokens(installer: ExecutableIdentity, *, cwd: Path) -> list[str]:
    installer.revalidate(cwd=cwd, changed_reason="update_installer_identity_changed")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = -1
    try:
        descriptor = os.open(installer.canonical_path, flags)
        first_line = os.read(descriptor, 4096).splitlines()[0]
    except (IndexError, OSError) as error:
        raise UpdateSubprocessError("update_installer_untrusted") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    installer.revalidate(cwd=cwd, changed_reason="update_installer_identity_changed")
    if not first_line.startswith(b"#!"):
        return []
    try:
        shebang = first_line[2:].decode("utf-8", errors="strict").strip()
        tokens = shlex.split(shebang, posix=os.name != "nt")
    except (UnicodeDecodeError, ValueError) as error:
        raise UpdateSubprocessError("update_installer_interpreter_untrusted") from error
    if not tokens:
        raise UpdateSubprocessError("update_installer_interpreter_untrusted")
    return tokens


def _trusted_manager_search_path(
    *,
    installer_kind: str,
    workspace_dir: Path | None,
    guard_home: Path,
) -> str:
    """Return conventional manager roots, excluding project and Guard-controlled paths."""

    try:
        excluded = [guard_home.expanduser().resolve()]
        if workspace_dir is not None:
            excluded.append(workspace_dir.expanduser().resolve())
    except (OSError, RuntimeError) as error:
        raise UpdateSubprocessError("update_installer_not_found") from error
    selected = []
    for entry in _trusted_runtime_search_path(installer_kind=installer_kind).split(os.pathsep):
        resolved = Path(entry)
        if any(_path_is_within(resolved, root) for root in excluded):
            continue
        selected.append(str(resolved))
    if not selected:
        raise UpdateSubprocessError("update_installer_not_found")
    return os.pathsep.join(selected)


def _resolve_manager_launch_path(installer_kind: str, search_path: str) -> Path:
    """Resolve a manager without consuming ambient PATH or PATHEXT semantics."""

    names = (f"{installer_kind}.exe", installer_kind) if os.name == "nt" else (installer_kind,)
    for raw_directory in search_path.split(os.pathsep):
        directory = Path(raw_directory)
        if not directory.is_absolute():
            continue
        for name in names:
            candidate = directory / name
            try:
                metadata = candidate.stat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode):
                return candidate
    raise UpdateSubprocessError("update_installer_not_found")


def _trusted_runtime_search_path(*, installer_kind: str) -> str:
    """Retain only the derived manager bin and fixed OS executable directories."""

    allowed: list[Path] = []
    if installer_kind in {"pipx", "uv"}:
        _manager_home, manager_bin = _manager_home_from_prefix(installer_kind)
        allowed.append(manager_bin)
    if os.name != "nt":
        for raw_entry in os.defpath.split(os.pathsep):
            if raw_entry:
                allowed.append(Path(raw_entry))
        allowed.extend((Path("/usr/local/bin"), Path("/opt/homebrew/bin"), Path("/home/linuxbrew/.linuxbrew/bin")))
    else:
        try:
            windows_directory, system_directory = trusted_windows_system_directories()
            roaming_appdata = trusted_windows_roaming_appdata()
            user_profile = trusted_windows_user_profile()
        except OSError as error:
            raise UpdateSubprocessError("update_runtime_untrusted") from error
        allowed.extend(
            (
                windows_directory,
                system_directory,
                user_profile / ".local" / "bin",
                Path(sys.base_prefix) / "Scripts",
                roaming_appdata / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts",
            )
        )

    selected: list[str] = []
    seen: set[Path] = set()
    for candidate in allowed:
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_dir() or resolved in seen:
            continue
        seen.add(resolved)
        selected.append(str(resolved))
    if not selected:
        raise UpdateSubprocessError("update_runtime_untrusted")
    return os.pathsep.join(selected)


def _trusted_environment(
    *,
    path: str,
    neutral_home: Path,
    neutral_tmp: Path,
    installer_kind: str,
    python: Path,
    proxy_mode: str,
    proxy_url: str | None,
    ca_bundle_path: str | None,
) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if key.upper() in _PRESERVED_OS_ENV_KEYS}
    environment.update(
        {
            "HOME": str(neutral_home),
            "PATH": path,
            "PIP_CONFIG_FILE": os.devnull,
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "TEMP": str(neutral_tmp),
            "TMP": str(neutral_tmp),
            "TMPDIR": str(neutral_tmp),
        }
    )
    if os.name == "nt":
        try:
            windows_directory, _system_directory = trusted_windows_system_directories()
            command_processor = trusted_windows_system_executable("cmd.exe")
        except OSError as error:
            raise UpdateSubprocessError("update_runtime_untrusted") from error
        system_drive, _tail = ntpath.splitdrive(str(windows_directory))
        environment.update(
            {
                "COMSPEC": str(command_processor),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "SYSTEMDRIVE": system_drive,
                "SYSTEMROOT": str(windows_directory),
                "WINDIR": str(windows_directory),
            }
        )
        environment["USERPROFILE"] = str(neutral_home)
    if installer_kind == "pipx":
        pipx_home, pipx_bin = _manager_home_from_prefix("pipx")
        environment.update(
            {
                "PIPX_HOME": str(pipx_home),
                "PIPX_BIN_DIR": str(pipx_bin),
                "PIPX_DEFAULT_BACKEND": "pip",
                "PIPX_DEFAULT_PYTHON": str(python),
                "PIPX_FETCH_PYTHON": "never",
            }
        )
    elif installer_kind == "uv":
        uv_home, uv_bin = _manager_home_from_prefix("uv")
        environment.update(
            {
                "UV_TOOL_DIR": str(uv_home),
                "UV_TOOL_BIN_DIR": str(uv_bin),
                "UV_NO_CONFIG": "1",
                "UV_PYTHON_DOWNLOADS": "never",
            }
        )
    if proxy_mode == "explicit":
        if not isinstance(proxy_url, str) or not proxy_url.strip():
            raise UpdateSubprocessError("update_source_invalid")
        environment["HTTP_PROXY"] = proxy_url.strip()
        environment["HTTPS_PROXY"] = proxy_url.strip()
    elif proxy_mode == "system":
        for scheme, value in platform_system_proxies().items():
            environment[f"{scheme.upper()}_PROXY"] = value
    elif proxy_mode != "none":
        raise UpdateSubprocessError("update_source_invalid")
    if ca_bundle_path is not None:
        bundle = Path(ca_bundle_path).expanduser()
        if not bundle.is_absolute() or not bundle.is_file():
            raise UpdateSubprocessError("update_source_invalid")
        resolved_bundle = bundle.resolve(strict=True)
        environment["PIP_CERT"] = str(resolved_bundle)
        environment["REQUESTS_CA_BUNDLE"] = str(resolved_bundle)
        environment["SSL_CERT_FILE"] = str(resolved_bundle)
    return environment


def _trusted_python_import_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    seen: set[Path] = set()
    try:
        configured_paths = sysconfig.get_paths()
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        raise UpdateSubprocessError("update_python_untrusted") from error
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_dir() or resolved in seen:
            continue
        seen.add(resolved)
        paths.append(resolved)
    if not paths:
        raise UpdateSubprocessError("update_python_untrusted")
    return tuple(paths)


def _manager_home_from_prefix(installer_kind: str) -> tuple[Path, Path]:
    prefix = Path(sys.prefix).expanduser().resolve()
    marker = "venvs" if installer_kind == "pipx" else "tools"
    marker_index = next(
        (
            index
            for index in range(len(prefix.parts) - 1, -1, -1)
            if _manager_component_matches(Path(*prefix.parts[: index + 1]), marker)
        ),
        None,
    )
    if marker_index is None or marker_index + 1 >= len(prefix.parts):
        raise UpdateSubprocessError("update_installer_untrusted")
    package_root = Path(*prefix.parts[: marker_index + 2])
    if not any(_manager_component_matches(package_root, expected_name) for expected_name in ("hol-guard", "hol_guard")):
        raise UpdateSubprocessError("update_installer_untrusted")
    marker_root = Path(*prefix.parts[: marker_index + 1])
    local_root = marker_root.parent
    manager_home = marker_root.parent if installer_kind == "pipx" else marker_root
    if os.name == "nt":
        try:
            bin_dir = trusted_windows_user_profile() / ".local" / "bin"
        except OSError as error:
            raise UpdateSubprocessError("update_installer_untrusted") from error
        return manager_home, bin_dir
    if (
        os.name != "nt"
        and _manager_component_matches(local_root, "pipx")
        and _manager_component_matches(local_root.parent, "Application Support")
    ):
        try:
            import pwd

            user_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
        except (ImportError, KeyError, OSError, RuntimeError) as error:
            raise UpdateSubprocessError("update_installer_untrusted") from error
        return manager_home, user_home / ".local" / "bin"
    if os.name != "nt" and _manager_path_matches(marker_root, Path("/opt/pipx/venvs")):
        return manager_home, Path("/usr/local/bin")
    manager_root_matches = any(
        _manager_component_matches(local_root, expected_name) for expected_name in ("pipx", "uv")
    )
    if manager_root_matches and _manager_component_matches(local_root.parent, "share"):
        bin_dir = local_root.parent.parent / "bin"
    elif manager_root_matches:
        bin_dir = local_root.parent / "bin"
    else:
        raise UpdateSubprocessError("update_installer_untrusted")
    return manager_home, bin_dir


def _manager_component_matches(path: Path, expected_name: str) -> bool:
    """Match manager layout names without aliasing distinct POSIX paths."""

    if path.name == expected_name:
        return True
    if path.name.casefold() != expected_name.casefold():
        return False
    if os.name == "nt":
        return True
    try:
        return path.samefile(path.with_name(expected_name))
    except OSError:
        return False


def _manager_path_matches(path: Path, expected_path: Path) -> bool:
    """Match a fixed manager root only when casing aliases the same object."""

    if path == expected_path:
        return True
    if str(path).casefold() != str(expected_path).casefold():
        return False
    if os.name == "nt":
        return True
    try:
        return path.samefile(expected_path)
    except OSError:
        return False


def _append_pip_source(command: list[str], index_url: str) -> list[str]:
    if "install" not in command:
        raise UpdateSubprocessError("update_installer_command_invalid")
    return [*command, "--index-url", index_url]


def _uv_execution_command(executable: str, args: list[str], *, python: str, index_url: str) -> list[str]:
    if len(args) < 2 or args[0] != "tool" or args[1] not in {"install", "upgrade"}:
        raise UpdateSubprocessError("update_installer_command_invalid")
    return [
        executable,
        "--no-config",
        "--no-progress",
        "--no-python-downloads",
        "tool",
        args[1],
        "--python",
        python,
        "--no-sources",
        "--default-index",
        index_url,
        *args[2:],
    ]


def _pipx_execution_command(executable: str, args: list[str], *, python: str, index_url: str) -> list[str]:
    if not args:
        raise UpdateSubprocessError("update_installer_command_invalid")
    if args[0] in {"install", "upgrade"}:
        return [
            executable,
            args[0],
            "--index-url",
            index_url,
            "--python",
            python,
            *args[1:],
        ]
    raise UpdateSubprocessError("update_installer_command_invalid")


def _run_bounded_process(
    command: list[str],
    *,
    input_text: str | None,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
    allow_windows_job_breakaway: bool = False,
) -> _BoundedProcessResult:
    """Run a child while retaining at most ``output_limit_bytes`` per stream."""

    input_bytes = input_text.encode("utf-8") if input_text is not None else None
    try:
        spawned = _spawn_bounded_process(
            command,
            input_enabled=input_bytes is not None,
            cwd=cwd,
            environment=environment,
            allow_windows_job_breakaway=allow_windows_job_breakaway,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise UpdateSubprocessError("update_installer_failed", str(error)) from error
    process = spawned.process
    windows_job = spawned.windows_job
    overflow = threading.Event()
    stdout_capture = _BoundedStreamCapture()
    stderr_capture = _BoundedStreamCapture()
    reader_threads: tuple[threading.Thread, ...] = ()
    input_thread: threading.Thread | None = None
    input_thread_started = False
    started_reader_threads: list[threading.Thread] = []
    primary_error: BaseException | None = None
    returncode: int | None = None
    cleanup_errors: tuple[BaseException, ...] = ()
    terminate_tree = windows_job is not None
    deadline = time.monotonic() + timeout_seconds
    try:
        if process.stdout is None or process.stderr is None:
            raise UpdateSubprocessError("update_installer_failed")
        reader_threads = (
            threading.Thread(
                target=_capture_bounded_stream,
                args=(process.stdout, stdout_capture, output_limit_bytes, overflow),
                name="guard-update-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=_capture_bounded_stream,
                args=(process.stderr, stderr_capture, output_limit_bytes, overflow),
                name="guard-update-stderr",
                daemon=True,
            ),
        )
        for thread in reader_threads:
            thread.start()
            started_reader_threads.append(thread)
        if input_bytes is not None:
            if process.stdin is None:
                raise UpdateSubprocessError("update_installer_failed")
            input_thread = threading.Thread(
                target=_write_process_input,
                args=(process.stdin, input_bytes),
                name="guard-update-stdin",
                daemon=True,
            )
            input_thread.start()
            input_thread_started = True
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_tree = True
                raise UpdateSubprocessError("update_installer_timeout")
            if overflow.wait(min(_PROCESS_MONITOR_INTERVAL_SECONDS, remaining)):
                terminate_tree = True
                break
        if process.poll() is not None and any(thread.is_alive() for thread in reader_threads):
            _join_threads(reader_threads, _PROCESS_TERMINATE_GRACE_SECONDS)
            if any(thread.is_alive() for thread in reader_threads):
                # A descendant inherited a pipe after the direct child exited.
                terminate_tree = True
    except BaseException as error:
        primary_error = error
        terminate_tree = True
    finally:
        # A Windows Job may still contain descendants after the direct child exits,
        # so terminate and close it on every path. The direct Popen is explicitly
        # waited here as well: closing the Job is not a substitute for reaping it.
        returncode, cleanup_errors = _terminate_process_group(
            process,
            windows_job=windows_job,
            terminate_tree=terminate_tree,
        )
        started_readers = tuple(started_reader_threads)
        _join_threads(started_readers, _STREAM_THREAD_JOIN_SECONDS)
        if input_thread is not None and input_thread_started:
            if input_thread.is_alive() and process.stdin is not None:
                with contextlib.suppress(OSError, ValueError):
                    process.stdin.close()
            input_thread.join(timeout=_STREAM_THREAD_JOIN_SECONDS)
        _close_process_streams(process)
        if any(thread.is_alive() for thread in started_readers):
            _join_threads(started_readers, _PROCESS_TERMINATE_GRACE_SECONDS)

    stream_error = stdout_capture.error or stderr_capture.error
    if primary_error is None and stream_error is not None and not overflow.is_set():
        primary_error = UpdateSubprocessError("update_installer_failed", str(stream_error))
    if primary_error is None and any(thread.is_alive() for thread in reader_threads):
        primary_error = UpdateSubprocessError("update_installer_failed", "subprocess output stream did not close")
    if cleanup_errors:
        cleanup_detail = "; ".join(str(error) or type(error).__name__ for error in cleanup_errors)
        containment_error = UpdateSubprocessError(
            "update_installer_failed",
            f"updater process containment cleanup failed: {cleanup_detail}",
        )
        if primary_error is not None:
            raise containment_error from primary_error
        raise containment_error
    if primary_error is not None:
        raise primary_error.with_traceback(primary_error.__traceback__)
    if returncode is None:
        raise UpdateSubprocessError("update_installer_failed", "direct updater process was not reaped")
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(stdout_capture.data),
        stderr=bytes(stderr_capture.data),
        stdout_limited=stdout_capture.limited,
        stderr_limited=stderr_capture.limited,
    )


def _spawn_bounded_process(
    command: list[str],
    *,
    input_enabled: bool,
    cwd: Path,
    environment: Mapping[str, str],
    allow_windows_job_breakaway: bool = False,
) -> _SpawnedProcess:
    stdin = subprocess.PIPE if input_enabled else subprocess.DEVNULL
    if os.name == "nt":
        windows_job = _create_windows_process_job(allow_breakaway=allow_windows_job_breakaway)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd),
                env=dict(environment),
                bufsize=0,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | _WINDOWS_CREATE_SUSPENDED,
            )
            _assign_and_resume_windows_process(process, windows_job)
            return _SpawnedProcess(process=process, windows_job=windows_job)
        except BaseException as error:
            if not _cleanup_failed_windows_process(process, windows_job):
                raise OSError("failed Windows updater process could not be reaped") from error
            raise
    return _SpawnedProcess(
        process=subprocess.Popen(
            command,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=dict(environment),
            bufsize=0,
            start_new_session=True,
        ),
        windows_job=None,
    )


def _windows_kernel32():  # type: ignore[no-untyped-def]
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("windows_job_api_unavailable")
    return win_dll("kernel32", use_last_error=True)


def _create_windows_process_job(*, allow_breakaway: bool) -> _WindowsProcessJob:
    kernel32 = _windows_kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_information.restype = wintypes.BOOL

    raw_handle = create_job(None, None)
    if raw_handle is None:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    job = _WindowsProcessJob(handle=int(raw_handle))
    try:
        limits = _WindowsJobObjectExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = _WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if allow_breakaway:
            limits.basic_limit_information.limit_flags |= _WINDOWS_JOB_OBJECT_LIMIT_BREAKAWAY_OK
        if not set_information(
            wintypes.HANDLE(job.handle),
            _WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
        return job
    except BaseException as error:
        close_error = _close_windows_process_job(job)
        if close_error is not None:
            raise OSError(f"failed to close unconfigured Windows updater Job handle: {close_error}") from error
        raise


def _assign_and_resume_windows_process(
    process: subprocess.Popen[bytes],
    windows_job: _WindowsProcessJob,
) -> None:
    kernel32 = _windows_kernel32()
    assign_process = kernel32.AssignProcessToJobObject
    assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign_process.restype = wintypes.BOOL
    is_process_in_job = kernel32.IsProcessInJob
    is_process_in_job.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    is_process_in_job.restype = wintypes.BOOL

    process_handle = _windows_process_handle(process)
    if not assign_process(wintypes.HANDLE(windows_job.handle), wintypes.HANDLE(process_handle)):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    assigned = wintypes.BOOL()
    if (
        not is_process_in_job(
            wintypes.HANDLE(process_handle),
            wintypes.HANDLE(windows_job.handle),
            ctypes.byref(assigned),
        )
        or not assigned.value
    ):
        raise OSError(ctypes.get_last_error(), "IsProcessInJob failed")
    _resume_windows_process_primary_thread(process.pid)


def _windows_process_handle(process: subprocess.Popen[bytes]) -> int:
    raw_handle = getattr(process, "_handle", None)
    if not isinstance(raw_handle, int) or raw_handle <= 0:
        raise OSError("Windows process handle is unavailable")
    return raw_handle


def _resume_windows_process_primary_thread(process_id: int) -> None:
    kernel32 = _windows_kernel32()
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    thread_first = kernel32.Thread32First
    thread_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WindowsThreadEntry32)]
    thread_first.restype = wintypes.BOOL
    thread_next = kernel32.Thread32Next
    thread_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WindowsThreadEntry32)]
    thread_next.restype = wintypes.BOOL
    open_thread = kernel32.OpenThread
    open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_thread.restype = wintypes.HANDLE
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = [wintypes.HANDLE]
    resume_thread.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(_WINDOWS_TH32CS_SNAPTHREAD, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot in {None, invalid_handle}:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    thread_ids: list[int] = []
    enumeration_error = 0
    try:
        entry = _WindowsThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        ctypes.set_last_error(0)
        has_entry = bool(thread_first(snapshot, ctypes.byref(entry)))
        first_failed = not has_entry
        first_error = ctypes.get_last_error() if first_failed else 0
        while has_entry:
            if int(entry.th32OwnerProcessID) == process_id:
                thread_ids.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            ctypes.set_last_error(0)
            has_entry = bool(thread_next(snapshot, ctypes.byref(entry)))
            if not has_entry:
                enumeration_error = ctypes.get_last_error()
    finally:
        _ = close_handle(snapshot)
    if first_failed:
        raise OSError(first_error, "Thread32First failed")
    if enumeration_error != _WINDOWS_ERROR_NO_MORE_FILES:
        raise OSError(enumeration_error, "Thread32Next failed")
    if len(thread_ids) != 1:
        raise OSError("suspended Windows process primary thread is ambiguous")

    thread_handle = open_thread(_WINDOWS_THREAD_SUSPEND_RESUME, False, thread_ids[0])
    if not thread_handle:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_suspend_count = int(resume_thread(thread_handle))
    finally:
        _ = close_handle(thread_handle)
    if previous_suspend_count == _WINDOWS_RESUME_THREAD_FAILED:
        raise OSError(ctypes.get_last_error(), "ResumeThread failed")
    if previous_suspend_count != 1:
        raise OSError("suspended Windows process had an unexpected suspend count")


def _cleanup_failed_windows_process(
    process: subprocess.Popen[bytes] | None,
    windows_job: _WindowsProcessJob,
) -> bool:
    with contextlib.suppress(OSError):
        windows_job.terminate()
    if process is not None:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            _ = process.wait(timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
    close_error = _close_windows_process_job(windows_job)
    if process is not None:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                _ = process.wait(timeout=_STREAM_THREAD_JOIN_SECONDS)
        _close_process_streams(process)
        return close_error is None and process.poll() is not None
    return close_error is None


def _close_windows_process_job(windows_job: _WindowsProcessJob) -> OSError | None:
    try:
        windows_job.close()
        return None
    except OSError:
        with contextlib.suppress(OSError):
            windows_job.terminate()
        try:
            windows_job.close()
            return None
        except OSError as error:
            return error


def _capture_bounded_stream(
    stream: BinaryIO,
    capture: _BoundedStreamCapture,
    limit: int,
    overflow: threading.Event,
) -> None:
    try:
        while True:
            remaining = limit - len(capture.data)
            read_size = min(64 * 1024, remaining) if remaining > 0 else 1
            chunk = stream.read(read_size)
            if not chunk:
                return
            if remaining <= 0:
                capture.limited = True
                overflow.set()
                return
            capture.data.extend(chunk)
    except (OSError, ValueError) as error:
        capture.error = error
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _write_process_input(stream: BinaryIO, data: bytes) -> None:
    try:
        _ = stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    windows_job: _WindowsProcessJob | None = None,
    terminate_tree: bool = True,
) -> tuple[int | None, tuple[BaseException, ...]]:
    """Terminate the process tree, close its Job, and explicitly reap Popen."""

    cleanup_errors: list[BaseException] = []
    if windows_job is not None:
        try:
            windows_job.terminate()
        except OSError as error:
            cleanup_errors.append(error)
    elif terminate_tree and os.name == "nt":
        ctrl_break_event = getattr(signal, "CTRL_BREAK_EVENT", None)
        try:
            if not isinstance(ctrl_break_event, int):
                raise OSError
            os.kill(process.pid, ctrl_break_event)
        except OSError:
            with contextlib.suppress(OSError):
                process.terminate()
    elif terminate_tree:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGTERM)

    returncode = _wait_for_direct_process(process, timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
    if terminate_tree and os.name != "nt":
        # The direct child may have exited while a descendant in its process
        # group ignored SIGTERM, so escalate the group independently of Popen.
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
    if returncode is None:
        with contextlib.suppress(OSError):
            process.kill()
        returncode = _wait_for_direct_process(process, timeout=_PROCESS_TERMINATE_GRACE_SECONDS)

    if windows_job is not None:
        close_error = _close_windows_process_job(windows_job)
        if close_error is not None:
            cleanup_errors.append(close_error)

    # Job close can be the operation that finally kills a process when explicit
    # Job termination failed, so make one last bounded wait before declaring the
    # direct child unreaped.
    if returncode is None:
        returncode = _wait_for_direct_process(process, timeout=_STREAM_THREAD_JOIN_SECONDS)
    if returncode is None:
        with contextlib.suppress(OSError):
            process.kill()
        returncode = _wait_for_direct_process(process, timeout=_STREAM_THREAD_JOIN_SECONDS)
    if returncode is None:
        cleanup_errors.append(OSError("direct updater process could not be reaped"))
    return returncode, tuple(cleanup_errors)


def _wait_for_direct_process(process: subprocess.Popen[bytes], *, timeout: float) -> int | None:
    try:
        return process.wait(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _join_threads(threads: tuple[threading.Thread, ...], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            stream.close()


def _single_json_object(result: TrustedProcessResult, *, failure_reason: str) -> dict[str, object]:
    if result.returncode != 0 or result.output_limited or result.stderr or not result.stdout:
        raise UpdateSubprocessError(failure_reason)
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise UpdateSubprocessError(failure_reason)
    try:
        parsed: object = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise UpdateSubprocessError(failure_reason) from error
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise UpdateSubprocessError(failure_reason)
    return {str(key): value for key, value in parsed.items()}


def _bounded_redacted_text(
    value: object,
    limit: int,
    *,
    sensitive_values: tuple[str, ...] = (),
) -> tuple[str, bool]:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value or "")
    for sensitive_value in sensitive_values:
        text = text.replace(sensitive_value, "[redacted-update-source]")
    redacted = redact_sensitive_text(text.strip())
    encoded = redacted.encode("utf-8", errors="replace")
    limited = len(encoded) > limit
    if limited:
        encoded = encoded[:limit]
        redacted = encoded.decode("utf-8", errors="ignore")
    return redacted, limited


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        _ = path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


__all__ = [
    "ExecutableIdentity",
    "InstalledDistribution",
    "TrustedProcessResult",
    "TrustedUpdateContext",
    "UpdateSource",
    "UpdateSubprocessError",
    "build_trusted_update_context",
]
