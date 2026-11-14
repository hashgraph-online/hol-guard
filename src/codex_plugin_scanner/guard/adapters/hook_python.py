"""Attest the already-running Guard Python for persisted harness hooks.

The OpenCode integration never discovers a second interpreter.  It sends the
native runtime where the running Guard's package and distributions live; the
runtime derives every trusted import path from those facts, probes the
resolved executable with site initialization disabled and accepts its output
only when it exactly matches that record.  See `hook_python_attest.rs`.
"""

from __future__ import annotations

import importlib.metadata
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import codex_plugin_scanner

from ...version import __version__
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from ..stable_guard_cli import guard_cli_launcher
from .base import HarnessContext

_EXPECTED_ENTRY_POINT: Final = "codex_plugin_scanner.cli:main"
_PREPARATION_PROBE: ContextVar[tuple[int, Path] | None] = ContextVar("guard_preparation_probe", default=None)
_PROBE_INHERITED_ENV_KEYS: Final = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
)


@dataclass(frozen=True, slots=True)
class HookPythonFileMetadata:
    """Filesystem fields persisted in the generated TypeScript plugin."""

    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class HookPythonExecutableIdentity:
    """Stable invocation and canonical-target identity for Guard Python."""

    invocation_path: Path
    invocation_type: str
    invocation_link_target: str | None
    invocation_stat: HookPythonFileMetadata
    target_path: Path
    target_stat: HookPythonFileMetadata
    target_sha256: str


@dataclass(frozen=True, slots=True)
class HookPythonAttestation:
    """Exact parent-derived identity confirmed by the isolated child."""

    identity: HookPythonExecutableIdentity
    package_file: Path
    package_root: Path
    cryptography_file: Path
    import_roots: tuple[Path, ...]
    hol_distribution_root: Path | None
    cryptography_distribution_root: Path
    version: str
    entry_point: str

    @property
    def executable(self) -> Path:
        return self.identity.invocation_path


@contextmanager
def disposable_guard_hook_probe() -> Iterator[None]:
    """Keep attestation writes in an owned temporary directory during preparation.

    Every invocation still attests the running executable and package identity.
    The scope supplies only the neutral child working directory, never authority
    or cached attestation, and cannot be reused by an inherited child process.
    """

    with tempfile.TemporaryDirectory(prefix="hol-guard-hook-probe-") as directory:
        token = _PREPARATION_PROBE.set((os.getpid(), Path(directory).resolve(strict=True)))
        try:
            yield
        finally:
            _PREPARATION_PROBE.reset(token)


def _attestation_probe(context: HarnessContext) -> dict[str, str]:
    """Where the probe runs: the preparation scope, or the native runtime makes
    `runtime/python-probe` under the Guard home.  Either must be private."""

    scoped = _PREPARATION_PROBE.get()
    if scoped is None:
        return {"guard_home": str(context.guard_home.expanduser().absolute())}
    pid, path = scoped
    if pid != os.getpid():
        raise RuntimeError("guard_hook_python_neutral_cwd_unavailable")
    return {"scoped": str(path)}


_TEXT_KEYS: Final = ("invocation_path", "invocation_type", "target_path", "target_sha256")
_IDENTITY_KEYS: Final = frozenset((*_TEXT_KEYS, "invocation_link_target", "invocation_stat", "target_stat"))
_STAT_KEYS: Final = ("device", "inode", "mode", "size", "mtime_ns")
_IDENTITY_ERRORS: Final = frozenset(
    f"guard_hook_python_interpreter_{kind}" for kind in ("unavailable", "untrusted", "changed")
)
_ATTEST_ERRORS: Final = (
    _IDENTITY_ERRORS
    | frozenset(
        f"guard_hook_python_probe_{kind}"
        for kind in ("timeout", "output_limit", "capture_incomplete", "rejected", "output_invalid", "identity_mismatch")
    )
    | frozenset(
        f"guard_hook_python_{kind}"
        for kind in (
            "neutral_cwd_unavailable",
            "active_package_unavailable",
            "package_root_mismatch",
            "cryptography_distribution_unavailable",
            "cryptography_unavailable",
            "cryptography_distribution_mismatch",
            "hol_guard_distribution_unavailable",
            "hol_guard_distribution_mismatch",
        )
    )
)
_EXPECTED_PATH_KEYS: Final = ("package_file", "package_root", "cryptography_file", "cryptography_distribution_root")
_EXPECTED_KEYS: Final = frozenset(
    (*_EXPECTED_PATH_KEYS, "import_roots", "hol_distribution_root", "version", "entry_point")
)
# Hashing a frozen Guard CLI reads tens of megabytes; attesting also runs the
# interpreter for up to 15 seconds.
_IDENTITY_TIMEOUT_SECONDS: Final = 30.0
_ATTEST_TIMEOUT_SECONDS: Final = 60.0


def _file_metadata(value: object) -> HookPythonFileMetadata:
    if not isinstance(value, dict):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    fields = cast(dict[str, object], value)
    numbers = [fields.get(key) for key in _STAT_KEYS]
    if set(fields) != set(_STAT_KEYS) or not all(
        isinstance(number, int) and not isinstance(number, bool) for number in numbers
    ):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    device, inode, mode, size, mtime_ns = cast(list[int], numbers)
    return HookPythonFileMetadata(device=device, inode=inode, mode=mode, size=size, mtime_ns=mtime_ns)


def _executable_identity(path: Path) -> HookPythonExecutableIdentity:
    """Read the executable's identity natively; see `hook_python_identity.rs`."""

    invocation = path.expanduser().absolute()
    request: dict[str, object] = {"op": "executable", "path": str(invocation)}
    answer = _native_answer(request, frozenset({"identity"}), _IDENTITY_ERRORS, _IDENTITY_TIMEOUT_SECONDS)
    return _native_identity(answer["identity"], invocation)


def _native_answer(
    request: dict[str, object],
    keys: frozenset[str],
    errors: frozenset[str],
    timeout_seconds: float,
) -> dict[str, object]:
    try:
        answer = native_runner_authority("hook_python_identity", request, timeout_seconds=timeout_seconds)
    except NativeRunnerAuthorityError as error:
        raise RuntimeError("guard_hook_python_interpreter_unavailable") from error
    error = answer.get("error")
    if set(answer) == {"error"} and error in errors:
        raise RuntimeError(cast(str, error))
    if set(answer) != keys:
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    return answer


def _native_identity(identity: object, invocation: Path) -> HookPythonExecutableIdentity:
    if not isinstance(identity, dict):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    fields = cast(dict[str, object], identity)
    link_target = fields.get("invocation_link_target")
    texts = [fields.get(key) for key in _TEXT_KEYS]
    if (
        set(fields) != _IDENTITY_KEYS
        or not all(isinstance(text, str) for text in texts)
        or fields["invocation_path"] != str(invocation)
        or fields["invocation_type"] not in {"file", "symlink"}
        or not (link_target is None or isinstance(link_target, str))
    ):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    return HookPythonExecutableIdentity(
        invocation_path=invocation,
        invocation_type=cast(str, fields["invocation_type"]),
        invocation_link_target=cast("str | None", link_target),
        invocation_stat=_file_metadata(fields["invocation_stat"]),
        target_path=Path(cast(str, fields["target_path"])),
        target_stat=_file_metadata(fields["target_stat"]),
        target_sha256=cast(str, fields["target_sha256"]),
    )


def _identity_is_unchanged(identity: HookPythonExecutableIdentity) -> bool:
    try:
        return _executable_identity(identity.invocation_path) == identity
    except RuntimeError:
        return False


def _distribution(name: str) -> importlib.metadata.Distribution | None:
    try:
        return importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _distribution_location(distribution: importlib.metadata.Distribution | None) -> str | None:
    if distribution is None:
        return None
    try:
        return str(Path(str(distribution.locate_file(""))).absolute())
    except (OSError, RuntimeError):
        return None


def _parent_facts(expected_package_root: Path | None) -> dict[str, object]:
    """What only the running Python can read; the native runtime decides
    whether it agrees.  See `hook_python_expect.rs`."""

    package_file = getattr(codex_plugin_scanner, "__file__", None)
    if not isinstance(package_file, str) or not package_file:
        raise RuntimeError("guard_hook_python_active_package_unavailable")
    hol: dict[str, object] | None = None
    hol_distribution = _distribution("hol-guard")
    if hol_distribution is not None:
        hol_root = _distribution_location(hol_distribution)
        if hol_root is None:
            raise RuntimeError("guard_hook_python_hol_guard_distribution_unavailable")
        entry_points = {
            item.name: item.value for item in hol_distribution.entry_points if item.group == "console_scripts"
        }
        hol = {
            "root": hol_root,
            "version": str(hol_distribution.version),
            "entry_point": entry_points.get("hol-guard"),
            "direct_url": hol_distribution.read_text("direct_url.json") or None,
        }
    return {
        "package_file": str(Path(package_file).absolute()),
        "package_root": None if expected_package_root is None else str(expected_package_root.absolute()),
        "version": __version__,
        "cryptography_root": _distribution_location(_distribution("cryptography")),
        "hol": hol,
    }


def _attest_python(
    python: Path,
    *,
    probe: dict[str, str],
    expected_package_root: Path | None = None,
) -> HookPythonAttestation:
    current = Path(sys.executable).absolute()
    if python.expanduser().absolute() != current:
        raise RuntimeError("guard_hook_python_not_running_interpreter")
    request: dict[str, object] = {
        "op": "attest",
        "python": str(current),
        "inherited": {key: os.environ[key] for key in _PROBE_INHERITED_ENV_KEYS if key in os.environ},
        "probe": probe,
        "facts": _parent_facts(expected_package_root),
    }
    answer = _native_answer(request, frozenset({"identity", "expected"}), _ATTEST_ERRORS, _ATTEST_TIMEOUT_SECONDS)
    identity = _native_identity(answer["identity"], current)
    expected = answer["expected"]
    if not isinstance(expected, dict):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    fields = cast(dict[str, object], expected)
    roots = fields.get("import_roots")
    hol_root = fields.get("hol_distribution_root")
    if (
        set(fields) != _EXPECTED_KEYS
        or not all(isinstance(fields[key], str) for key in _EXPECTED_PATH_KEYS)
        or not isinstance(roots, list)
        or not all(isinstance(root, str) for root in cast(list[object], roots))
        or not (hol_root is None or isinstance(hol_root, str))
        or fields["version"] != __version__
        or fields["entry_point"] != _EXPECTED_ENTRY_POINT
    ):
        raise RuntimeError("guard_hook_python_interpreter_unavailable")
    return HookPythonAttestation(
        identity=identity,
        package_file=Path(cast(str, fields["package_file"])),
        package_root=Path(cast(str, fields["package_root"])),
        cryptography_file=Path(cast(str, fields["cryptography_file"])),
        import_roots=tuple(Path(root) for root in cast(list[str], roots)),
        hol_distribution_root=None if hol_root is None else Path(cast(str, hol_root)),
        cryptography_distribution_root=Path(cast(str, fields["cryptography_distribution_root"])),
        version=__version__,
        entry_point=_EXPECTED_ENTRY_POINT,
    )


def attest_guard_hook_python(context: HarnessContext) -> HookPythonAttestation:
    """Attest only the interpreter already running this Guard process."""

    return _attest_python(Path(sys.executable).absolute(), probe=_attestation_probe(context))


def resolve_guard_hook_python(context: HarnessContext) -> Path:
    """Return the invocation path for the attested running Guard Python."""

    if bool(getattr(sys, "frozen", False)):
        return _executable_identity(Path(guard_cli_launcher()).absolute()).invocation_path
    try:
        return attest_guard_hook_python(context).executable
    except RuntimeError as error:
        message = (
            "Guard could not attest its running Python interpreter. Reinstall hol-guard with pipx or uv, "
            "then re-run `hol-guard install opencode`."
        )
        raise RuntimeError(message) from error


def guard_cli_command(context: HarnessContext, args: list[str]) -> list[str]:
    """Bind Guard CLI arguments to the durable active runtime."""

    executable = str(resolve_guard_hook_python(context))
    if not bool(getattr(sys, "frozen", False)):
        return [executable, *args]
    if args[:3] != ["-m", "codex_plugin_scanner.cli", "guard"]:
        raise RuntimeError("Frozen Guard CLI arguments do not match the managed launch contract.")
    return [executable, *args[3:]]


__all__ = [
    "HookPythonAttestation",
    "HookPythonExecutableIdentity",
    "HookPythonFileMetadata",
    "attest_guard_hook_python",
    "disposable_guard_hook_probe",
    "guard_cli_command",
    "resolve_guard_hook_python",
]
