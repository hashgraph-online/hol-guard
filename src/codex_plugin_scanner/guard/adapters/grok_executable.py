"""Trusted Grok executable discovery and registration."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .base import HarnessContext

_REGISTRATION_SCHEMA_VERSION = 1
_REGISTRATION_FILE = "trusted-executable.json"
_GROK_EXECUTABLE_NAMES = ("grok",)
_GROK_WINDOWS_EXECUTABLE_NAMES = ("grok.exe", "grok.cmd", "grok.bat", "grok.com")
_UNSAFE_LAUNCH_ENVIRONMENT_KEYS = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GIT_EXEC_PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
    }
)
_UNSAFE_LAUNCH_ENVIRONMENT_PREFIXES = ("DYLD_",)

GrokExecutableSource = Literal["automatic", "explicit", "registration"]


@dataclass(frozen=True, slots=True)
class TrustedGrokExecutable:
    """An absolute Grok launcher whose path and content were locally verified."""

    path: Path
    content_sha256: str
    source: GrokExecutableSource


@dataclass(frozen=True, slots=True)
class GrokExecutableResolution:
    """Trusted executable resolution or a non-sensitive rejection reason."""

    executable: TrustedGrokExecutable | None
    error: str | None = None


def grok_executable_names(*, windows: bool | None = None) -> tuple[str, ...]:
    """Return platform-specific Grok command names, including Windows shims."""

    is_windows = os.name == "nt" if windows is None else windows
    return _GROK_WINDOWS_EXECUTABLE_NAMES if is_windows else _GROK_EXECUTABLE_NAMES


def resolve_trusted_grok_executable(context: HarnessContext) -> GrokExecutableResolution:
    """Resolve Grok without accepting workspace or relative PATH executables."""

    explicit = context.executable_overrides.get("grok")
    if isinstance(explicit, str) and explicit.strip():
        return _resolve_candidate(
            explicit.strip(),
            context=context,
            source="explicit",
            require_automatic_root=False,
        )

    registered = _registered_executable(context)
    if registered.executable is not None:
        return registered
    if registered.error is not None:
        return registered

    candidate = _which_grok()
    if candidate is None:
        return GrokExecutableResolution(None, "Grok executable was not found in a trusted installation location.")
    return _resolve_candidate(
        candidate,
        context=context,
        source="automatic",
        require_automatic_root=True,
    )


def register_trusted_grok_executable(
    context: HarnessContext,
    executable: TrustedGrokExecutable,
) -> TrustedGrokExecutable:
    """Persist an explicitly selected executable and bind it to its content hash."""

    refreshed = _resolve_candidate(
        str(executable.path),
        context=context,
        source="explicit",
        require_automatic_root=False,
    )
    if refreshed.executable is None:
        raise FileNotFoundError(refreshed.error or "The selected Grok executable is no longer trusted.")

    trusted = refreshed.executable
    state_dir = _registration_path(context).parent
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        state_dir.chmod(0o700)
    payload = {
        "schemaVersion": _REGISTRATION_SCHEMA_VERSION,
        "path": str(trusted.path),
        "sha256": trusted.content_sha256,
        "registeredAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=state_dir,
            prefix=f".{_REGISTRATION_FILE}.",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path = Path(temporary_name)
        if os.name != "nt":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, _registration_path(context))
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return TrustedGrokExecutable(
        path=trusted.path,
        content_sha256=trusted.content_sha256,
        source="registration",
    )


def sanitized_grok_launch_environment(
    context: HarnessContext,
    inherited: Mapping[str, str],
) -> dict[str, str]:
    """Remove code-loader variables and unsafe PATH entries for the Grok process."""

    environment = {
        key: value
        for key, value in inherited.items()
        if key not in _UNSAFE_LAUNCH_ENVIRONMENT_KEYS
        and not any(key.startswith(prefix) for prefix in _UNSAFE_LAUNCH_ENVIRONMENT_PREFIXES)
    }
    environment["PATH"] = _sanitized_path(context, inherited.get("PATH"))
    grok_home = environment.get("GROK_HOME")
    if grok_home and _path_is_blocked(_expand_path(grok_home, context.home_dir), context):
        environment.pop("GROK_HOME", None)
    return environment


def _which_grok() -> str | None:
    for name in grok_executable_names():
        candidate = shutil.which(name)
        if candidate is not None:
            return candidate
    return None


def _resolve_candidate(
    value: str,
    *,
    context: HarnessContext,
    source: GrokExecutableSource,
    require_automatic_root: bool,
) -> GrokExecutableResolution:
    candidate = _expand_path(value, context.home_dir)
    if not candidate.is_absolute():
        return GrokExecutableResolution(None, "Grok executable paths must be absolute.")
    if _path_is_blocked(candidate, context):
        return GrokExecutableResolution(None, "Grok executable paths cannot come from the workspace or Guard cwd.")
    if require_automatic_root and _automatic_install_root(candidate, context.home_dir) is None:
        return GrokExecutableResolution(
            None,
            "Grok was found on PATH outside a trusted installation root; select it once with --grok-executable.",
        )
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return GrokExecutableResolution(None, "The selected Grok executable cannot be resolved.")
    if _path_is_blocked(resolved, context):
        return GrokExecutableResolution(None, "Grok executable symlink targets cannot be inside the workspace.")
    if not _valid_executable_name(candidate.name) or not _valid_executable_name(resolved.name, allow_target_name=True):
        return GrokExecutableResolution(None, "The selected file is not a Grok executable.")
    security_error = _executable_security_error(candidate, resolved)
    if security_error is not None:
        return GrokExecutableResolution(None, security_error)
    try:
        content_sha256 = _file_sha256(resolved)
    except OSError:
        return GrokExecutableResolution(None, "The selected Grok executable could not be hashed.")
    return GrokExecutableResolution(TrustedGrokExecutable(path=resolved, content_sha256=content_sha256, source=source))


def _registered_executable(context: HarnessContext) -> GrokExecutableResolution:
    path = _registration_path(context)
    if not path.exists():
        return GrokExecutableResolution(None)
    state_error = _secure_registration_file_error(path)
    if state_error is not None:
        return GrokExecutableResolution(None, state_error)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return GrokExecutableResolution(None, "The saved Grok executable registration is unreadable.")
    if not isinstance(payload, dict) or payload.get("schemaVersion") != _REGISTRATION_SCHEMA_VERSION:
        return GrokExecutableResolution(None, "The saved Grok executable registration has an unsupported format.")
    registered_path = payload.get("path")
    registered_hash = payload.get("sha256")
    if not isinstance(registered_path, str) or not isinstance(registered_hash, str):
        return GrokExecutableResolution(None, "The saved Grok executable registration is incomplete.")
    resolution = _resolve_candidate(
        registered_path,
        context=context,
        source="registration",
        require_automatic_root=False,
    )
    executable = resolution.executable
    if executable is None:
        return resolution
    if not hmac.compare_digest(executable.content_sha256, registered_hash):
        return GrokExecutableResolution(
            None,
            "The registered Grok executable changed; select the updated file again with --grok-executable.",
        )
    return resolution


def _registration_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "grok" / _REGISTRATION_FILE


def _secure_registration_file_error(path: Path) -> str | None:
    try:
        path_stat = path.stat()
    except OSError:
        return "The saved Grok executable registration cannot be inspected."
    if not stat.S_ISREG(path_stat.st_mode):
        return "The saved Grok executable registration is not a regular file."
    if os.name != "nt" and (path_stat.st_uid not in {0, os.getuid()} or path_stat.st_mode & 0o022):
        return "The saved Grok executable registration has unsafe ownership or permissions."
    return None


def _expand_path(value: str, home_dir: Path) -> Path:
    if value == "~":
        return home_dir
    if value.startswith(f"~{os.sep}") or value.startswith("~/"):
        return home_dir / value[2:]
    return Path(value)


def _path_is_blocked(path: Path, context: HarnessContext) -> bool:
    roots = [context.workspace_dir, context.guard_home]
    cwd = Path.cwd()
    try:
        resolved_cwd = cwd.resolve(strict=False)
        resolved_home = context.home_dir.resolve(strict=False)
    except (OSError, RuntimeError):
        resolved_cwd = cwd
        resolved_home = context.home_dir
    if resolved_cwd != Path(resolved_cwd.anchor) and not resolved_home.is_relative_to(resolved_cwd):
        roots.append(resolved_cwd)
    for root in roots:
        if root is None:
            continue
        try:
            if path.resolve(strict=False).is_relative_to(root.resolve(strict=False)):
                return True
        except (OSError, RuntimeError):
            if path == root:
                return True
    return False


def _valid_executable_name(name: str, *, allow_target_name: bool = False) -> bool:
    normalized = name.lower()
    if normalized in _GROK_EXECUTABLE_NAMES or normalized in _GROK_WINDOWS_EXECUTABLE_NAMES:
        return True
    # Package-manager launchers commonly symlink a trusted ``grok`` entry to a
    # versioned JavaScript or native target. The trusted entry name, root,
    # permissions, and final target content are still verified.
    return allow_target_name and bool(normalized)


def _executable_security_error(candidate: Path, resolved: Path) -> str | None:
    try:
        target_stat = resolved.stat()
    except OSError:
        return "The selected Grok executable cannot be inspected."
    if not stat.S_ISREG(target_stat.st_mode):
        return "The selected Grok executable is not a regular file."
    if os.name != "nt" and target_stat.st_mode & 0o111 == 0:
        return "The selected Grok executable is not executable."
    if not os.access(resolved, os.X_OK):
        return "The selected Grok executable is not executable."
    if os.name == "nt":
        return None
    if target_stat.st_uid not in {0, os.getuid()}:
        return "The selected Grok executable has an unexpected owner."
    if target_stat.st_mode & 0o022:
        return "The selected Grok executable is writable by another local account."
    if not _directory_chain_is_secure(candidate.parent):
        return "The Grok installation path has unsafe ownership or permissions."
    if not _directory_chain_is_secure(resolved.parent):
        return "The Grok executable target path has unsafe ownership or permissions."
    return None


def _directory_chain(path: Path) -> tuple[Path, ...]:
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return tuple(chain)


def _directory_chain_is_secure(path: Path) -> bool:
    for directory in _directory_chain(path):
        try:
            directory_stat = directory.stat()
        except OSError:
            return False
        if directory_stat.st_uid not in {0, os.getuid()} or directory_stat.st_mode & 0o022:
            return False
    return True


def _automatic_install_root(candidate: Path, home_dir: Path) -> Path | None:
    fixed_roots = (
        Path("/usr/bin"),
        Path("/usr/local/bin"),
        Path("/opt/homebrew/bin"),
        Path("/opt/local/bin"),
        home_dir / ".local" / "bin",
        home_dir / "bin",
        home_dir / ".npm-global" / "bin",
        home_dir / ".bun" / "bin",
        home_dir / ".volta" / "bin",
        home_dir / ".asdf" / "shims",
        home_dir / ".local" / "share" / "pnpm",
        home_dir / "Library" / "pnpm",
    )
    for root in fixed_roots:
        if candidate.is_relative_to(root):
            return root
    try:
        relative = candidate.relative_to(home_dir)
    except ValueError:
        return _windows_automatic_install_root(candidate)
    parts = relative.parts
    dynamic_prefixes = (
        (".nvm", "versions", "node"),
        (".fnm", "node-versions"),
        (".local", "share", "mise", "installs", "node"),
        (".proto", "tools", "node"),
    )
    if candidate.parent.name == "bin" and any(parts[: len(prefix)] == prefix for prefix in dynamic_prefixes):
        return candidate.parent
    return _windows_automatic_install_root(candidate)


def _windows_automatic_install_root(candidate: Path) -> Path | None:
    if os.name != "nt":
        return None
    for environment_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        value = os.environ.get(environment_name)
        if not value:
            continue
        root = Path(value)
        if candidate.is_relative_to(root):
            return root
    return None


def _sanitized_path(context: HarnessContext, value: str | None) -> str:
    raw_value = value or os.defpath
    retained: list[str] = []
    for entry in raw_value.split(os.pathsep):
        if not entry.strip():
            continue
        candidate = _expand_path(entry.strip(), context.home_dir)
        if not candidate.is_absolute() or _path_is_blocked(candidate, context):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_dir() or _path_is_blocked(resolved, context):
            continue
        if os.name != "nt" and not _directory_chain_is_secure(resolved):
            continue
        normalized = str(resolved)
        if normalized not in retained:
            retained.append(normalized)
    if retained:
        return os.pathsep.join(retained)
    return os.defpath


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "GrokExecutableResolution",
    "TrustedGrokExecutable",
    "grok_executable_names",
    "register_trusted_grok_executable",
    "resolve_trusted_grok_executable",
    "sanitized_grok_launch_environment",
]
