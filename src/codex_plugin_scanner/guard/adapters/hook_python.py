"""Attest the already-running Guard Python for persisted harness hooks.

The OpenCode integration never discovers a second interpreter.  It resolves
the Python that is already running Guard, derives every trusted import path in
the parent, and probes the resolved executable with site initialization
disabled.  Child output is accepted only when it exactly matches the complete
parent-derived record.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import codex_plugin_scanner

from ...version import __version__
from .base import HarnessContext
from .hook_python_probe_code import PROBE_CODE as _PROBE_CODE
from .hook_python_subprocess import run_probe as _run_probe

_WORKTREE_MARKERS = ("/.worktrees/", "/worktrees/")
_WORKTREE_SEGMENT_PREFIXES = ("hol-guard-wt-",)
_PROBE_SCHEMA: Final = 2
_EXPECTED_ENTRY_POINT: Final = "codex_plugin_scanner.cli:main"
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

    @property
    def executable_target(self) -> Path:
        return self.identity.target_path


@dataclass(frozen=True, slots=True)
class _ParentExpectation:
    package_file: Path
    package_root: Path
    cryptography_file: Path
    import_roots: tuple[Path, ...]
    hol_distribution_root: Path | None
    cryptography_distribution_root: Path

    def probe_record(self, target: Path) -> dict[str, object]:
        return {
            "schema": _PROBE_SCHEMA,
            "resolved_executable": str(target),
            "package_file": str(self.package_file),
            "package_root": str(self.package_root),
            "cryptography_file": str(self.cryptography_file),
            "import_roots": [str(root) for root in self.import_roots],
            "hol_distribution_root": (
                str(self.hol_distribution_root) if self.hol_distribution_root is not None else None
            ),
            "cryptography_distribution_root": str(self.cryptography_distribution_root),
            "version": __version__,
            "entry_point": _EXPECTED_ENTRY_POINT,
        }


def _path_looks_like_worktree(path: Path) -> bool:
    text = str(path.resolve()).replace("\\", "/")
    if any(marker in text for marker in _WORKTREE_MARKERS):
        return True
    return any(segment.startswith(prefix) for segment in text.split("/") for prefix in _WORKTREE_SEGMENT_PREFIXES)


def filter_worktree_path_entries(entries: list[str]) -> list[str]:
    """Return stable, unique path entries for legacy callers."""

    filtered: list[str] = []
    for entry in entries:
        trimmed = entry.strip()
        if not trimmed or _path_looks_like_worktree(Path(trimmed)):
            continue
        if trimmed not in filtered:
            filtered.append(trimmed)
    return filtered


def _guard_hook_python_candidates(context: HarnessContext) -> list[Path]:
    """Compatibility seam returning only the Python already running Guard."""

    del context
    return [Path(sys.executable).absolute()]


def _probe_environment(neutral_cwd: Path) -> dict[str, str]:
    env = {key: os.environ[key] for key in _PROBE_INHERITED_ENV_KEYS if key in os.environ}
    env.update(
        {
            "HOME": str(neutral_cwd),
            "USERPROFILE": str(neutral_cwd),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
    )
    return env


def _private_probe_cwd(context: HarnessContext) -> Path:
    context.guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    guard_home = context.guard_home.resolve(strict=True)
    if not _path_is_owned_directory(guard_home) or (
        os.name != "nt" and stat.S_IMODE(guard_home.stat().st_mode) & 0o022 != 0
    ):
        raise RuntimeError("guard_hook_python_neutral_cwd_unavailable")
    runtime_dir = guard_home / "runtime"
    probe_dir = runtime_dir / "python-probe"
    for directory in (runtime_dir, probe_dir):
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not _path_is_owned_directory(directory):
            raise RuntimeError("guard_hook_python_neutral_cwd_unavailable")
        try:
            directory.chmod(0o700)
        except OSError:
            if os.name != "nt":
                raise RuntimeError("guard_hook_python_neutral_cwd_unavailable") from None
        if not _path_is_owned_private_directory(directory):
            raise RuntimeError("guard_hook_python_neutral_cwd_unavailable")
    return probe_dir.resolve(strict=True)


def _path_is_owned_private_directory(path: Path) -> bool:
    return _path_is_owned_directory(path) and (os.name == "nt" or stat.S_IMODE(path.stat().st_mode) & 0o077 == 0)


def _path_is_owned_directory(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    getuid = getattr(os, "getuid", None)
    return stat.S_ISDIR(metadata.st_mode) and (getuid is None or metadata.st_uid == getuid())


def _active_package_paths() -> tuple[Path, Path]:
    package_file = getattr(codex_plugin_scanner, "__file__", None)
    if not isinstance(package_file, str) or not package_file:
        raise RuntimeError("guard_hook_python_active_package_unavailable")
    resolved_file = Path(package_file).resolve(strict=True)
    package_root = resolved_file.parent.parent
    if not package_root.is_dir():
        raise RuntimeError("guard_hook_python_active_package_unavailable")
    return resolved_file, package_root


def _active_package_root() -> Path:
    return _active_package_paths()[1]


def _file_metadata(value: os.stat_result) -> HookPythonFileMetadata:
    return HookPythonFileMetadata(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _executable_identity(path: Path) -> HookPythonExecutableIdentity:
    invocation = path.expanduser().absolute()
    try:
        invocation_before = invocation.lstat()
        target = invocation.resolve(strict=True)
        target_before = target.stat()
        link_target = os.readlink(invocation) if stat.S_ISLNK(invocation_before.st_mode) else None
    except (OSError, RuntimeError) as error:
        raise RuntimeError("guard_hook_python_interpreter_unavailable") from error
    if stat.S_ISLNK(invocation_before.st_mode):
        invocation_type = "symlink"
    elif stat.S_ISREG(invocation_before.st_mode):
        invocation_type = "file"
    else:
        raise RuntimeError("guard_hook_python_interpreter_untrusted")
    if not stat.S_ISREG(target_before.st_mode) or not os.access(invocation, os.X_OK):
        raise RuntimeError("guard_hook_python_interpreter_untrusted")
    try:
        target_sha256 = _file_sha256(target)
        invocation_after = invocation.lstat()
        target_after_path = invocation.resolve(strict=True)
        target_after = target_after_path.stat()
    except (OSError, RuntimeError) as error:
        raise RuntimeError("guard_hook_python_interpreter_changed") from error
    if (
        _file_metadata(invocation_before) != _file_metadata(invocation_after)
        or target_after_path != target
        or _file_metadata(target_before) != _file_metadata(target_after)
    ):
        raise RuntimeError("guard_hook_python_interpreter_changed")
    return HookPythonExecutableIdentity(
        invocation_path=invocation,
        invocation_type=invocation_type,
        invocation_link_target=link_target,
        invocation_stat=_file_metadata(invocation_before),
        target_path=target,
        target_stat=_file_metadata(target_before),
        target_sha256=target_sha256,
    )


def _identity_is_unchanged(identity: HookPythonExecutableIdentity) -> bool:
    try:
        return _executable_identity(identity.invocation_path) == identity
    except RuntimeError:
        return False


def _distribution_root(name: str) -> Path:
    try:
        distribution = importlib.metadata.distribution(name)
        root = Path(str(distribution.locate_file(""))).resolve(strict=True)
    except (importlib.metadata.PackageNotFoundError, OSError, RuntimeError) as error:
        raise RuntimeError(f"guard_hook_python_{name.replace('-', '_')}_distribution_unavailable") from error
    if not root.is_dir():
        raise RuntimeError(f"guard_hook_python_{name.replace('-', '_')}_distribution_unavailable")
    return root


def _is_explicit_editable_source_root(package_root: Path) -> bool:
    return (
        package_root.name == "src"
        and (package_root / "codex_plugin_scanner" / "__init__.py").is_file()
        and (package_root.parent / "pyproject.toml").is_file()
    )


def _editable_distribution_source_root(
    distribution: importlib.metadata.Distribution,
) -> Path | None:
    raw_direct_url = distribution.read_text("direct_url.json")
    if not raw_direct_url:
        return None
    try:
        value: object = json.loads(raw_direct_url)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    direct_url = cast(dict[str, object], value)
    directory_info = direct_url.get("dir_info")
    url = direct_url.get("url")
    if not isinstance(directory_info, dict) or directory_info.get("editable") is not True or not isinstance(url, str):
        return None
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        return Path(urllib.request.url2pathname(urllib.parse.unquote(parsed.path))).resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _parent_expectation() -> _ParentExpectation:
    package_file, package_root = _active_package_paths()
    cryptography_distribution_root = _distribution_root("cryptography")
    try:
        crypto_file = (cryptography_distribution_root / "cryptography" / "__init__.py").resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("guard_hook_python_cryptography_unavailable") from error
    if not crypto_file.is_file() or not _path_within(crypto_file, cryptography_distribution_root):
        raise RuntimeError("guard_hook_python_cryptography_distribution_mismatch")
    try:
        hol_distribution = importlib.metadata.distribution("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        if not _is_explicit_editable_source_root(package_root):
            raise RuntimeError("guard_hook_python_hol_guard_distribution_unavailable") from None
        hol_distribution_root = None
    else:
        try:
            hol_distribution_root = Path(str(hol_distribution.locate_file(""))).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RuntimeError("guard_hook_python_hol_guard_distribution_unavailable") from error
        entry_points = {
            item.name: item.value for item in hol_distribution.entry_points if item.group == "console_scripts"
        }
        if hol_distribution.version != __version__ or entry_points.get("hol-guard") != _EXPECTED_ENTRY_POINT:
            raise RuntimeError("guard_hook_python_hol_guard_distribution_mismatch")
        if not _path_within(package_file, hol_distribution_root):
            editable_root = _editable_distribution_source_root(hol_distribution)
            if (
                editable_root is None
                or package_root != editable_root / "src"
                or not _is_explicit_editable_source_root(package_root)
            ):
                raise RuntimeError("guard_hook_python_hol_guard_distribution_mismatch")
    import_roots: list[Path] = []
    for root in (package_root, hol_distribution_root, cryptography_distribution_root):
        if root is not None and root not in import_roots:
            import_roots.append(root)
    return _ParentExpectation(
        package_file=package_file,
        package_root=package_root,
        cryptography_file=crypto_file,
        import_roots=tuple(import_roots),
        hol_distribution_root=hol_distribution_root,
        cryptography_distribution_root=cryptography_distribution_root,
    )


def _attest_python(
    python: Path,
    *,
    neutral_cwd: Path,
    expected_package_root: Path | None = None,
) -> HookPythonAttestation:
    current = Path(sys.executable).absolute()
    if python.expanduser().absolute() != current:
        raise RuntimeError("guard_hook_python_not_running_interpreter")
    identity = _executable_identity(current)
    expectation = _parent_expectation()
    if expected_package_root is not None and expected_package_root.resolve(strict=True) != expectation.package_root:
        raise RuntimeError("guard_hook_python_package_root_mismatch")
    expected_record = expectation.probe_record(identity.target_path)
    result = _run_probe(
        [
            str(identity.target_path),
            "-I",
            "-S",
            "-s",
            "-c",
            _PROBE_CODE,
            json.dumps(expected_record, sort_keys=True, separators=(",", ":")),
        ],
        cwd=neutral_cwd,
        env=_probe_environment(neutral_cwd),
    )
    if result.timed_out:
        raise RuntimeError("guard_hook_python_probe_timeout")
    if result.output_overflow:
        raise RuntimeError("guard_hook_python_probe_output_limit")
    if result.capture_incomplete:
        raise RuntimeError("guard_hook_python_probe_capture_incomplete")
    if result.returncode != 0:
        raise RuntimeError("guard_hook_python_probe_rejected")
    if not _identity_is_unchanged(identity):
        raise RuntimeError("guard_hook_python_interpreter_changed")
    try:
        text = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("guard_hook_python_probe_output_invalid") from error
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise RuntimeError("guard_hook_python_probe_output_invalid")
    try:
        payload = cast(object, json.loads(lines[0]))
    except json.JSONDecodeError as error:
        raise RuntimeError("guard_hook_python_probe_output_invalid") from error
    if not isinstance(payload, dict) or cast(dict[str, object], payload) != expected_record:
        raise RuntimeError("guard_hook_python_probe_identity_mismatch")
    return HookPythonAttestation(
        identity=identity,
        package_file=expectation.package_file,
        package_root=expectation.package_root,
        cryptography_file=expectation.cryptography_file,
        import_roots=expectation.import_roots,
        hol_distribution_root=expectation.hol_distribution_root,
        cryptography_distribution_root=expectation.cryptography_distribution_root,
        version=__version__,
        entry_point=_EXPECTED_ENTRY_POINT,
    )


def _path_within(path: Path, root: Path) -> bool:
    try:
        _ = path.relative_to(root)
    except ValueError:
        return False
    return True


def attest_guard_hook_python(context: HarnessContext) -> HookPythonAttestation:
    """Attest only the interpreter already running this Guard process."""

    return _attest_python(
        Path(sys.executable).absolute(),
        neutral_cwd=_private_probe_cwd(context),
        expected_package_root=_active_package_root(),
    )


def resolve_guard_hook_python(context: HarnessContext) -> Path:
    """Return the invocation path for the attested running Guard Python."""

    try:
        return attest_guard_hook_python(context).executable
    except RuntimeError as error:
        message = (
            "Guard could not attest its running Python interpreter. Reinstall hol-guard with pipx or uv, "
            "then re-run `hol-guard install opencode`."
        )
        raise RuntimeError(message) from error


def package_root_from_python(python: Path, context: HarnessContext) -> str:
    """Return the active Guard root after re-attesting the running Python."""

    return str(
        _attest_python(
            python,
            neutral_cwd=_private_probe_cwd(context),
            expected_package_root=_active_package_root(),
        ).package_root
    )


__all__ = [
    "HookPythonAttestation",
    "HookPythonExecutableIdentity",
    "HookPythonFileMetadata",
    "attest_guard_hook_python",
    "filter_worktree_path_entries",
    "package_root_from_python",
    "resolve_guard_hook_python",
]
