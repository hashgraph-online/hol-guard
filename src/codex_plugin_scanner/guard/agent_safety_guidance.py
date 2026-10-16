"""Install concise agent guidance that reduces avoidable Guard reviews."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import final

_AGENTS_RELATIVE_PATH = Path(".codex") / "AGENTS.md"
_SAFETY_RELATIVE_PATH = Path(".hol-support") / "SAFETY.md"
_MANAGED_BEGIN = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->"
_MANAGED_END = "<!-- END HOL GUARD SAFETY GUIDANCE -->"
_MANAGED_BLOCK = f"""\
{_MANAGED_BEGIN}
## HOL Guard

- Before planning shell, Git, package, filesystem, or remote actions, read `~/.hol-support/SAFETY.md`.
- Follow that guide to avoid unnecessary approval prompts without bypassing HOL Guard.
{_MANAGED_END}
"""
_SAFETY_GUIDANCE_BODY = (
    files("codex_plugin_scanner.guard").joinpath("agent-safety-guidance.md").read_text(encoding="utf-8")
)
_SAFETY_GUIDANCE = f"<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n{_SAFETY_GUIDANCE_BODY}"
_LEGACY_SAFETY_GUIDANCE_DIGESTS = frozenset(
    {
        # Guidance before the self-approval section: unprefixed, then v2-prefixed.
        "8dfc18925c07e425e6ac5e5c4b5aba27d15e9bba4472409cf57411085f6389ed",
        "5276fa1bb1460b07d4ce2c42f732931b06744d11ad28fd9422dc2ff24be1eeda",
        # Guidance that let an agent decide for itself that a secret read was authorized.
        "5211684ae7093b4e0363e176ab38c3d5f2e83a88f557381cffb220b37fb36652",
        # Guidance before it named the script-free npm install Guard lets continue.
        "2726e5000e64235af716c767a45912d389fc522ce16748139ab309f9ffe53075",
    }
)
_MANAGED_PATTERN = re.compile(rf"(?ms)^{re.escape(_MANAGED_BEGIN)}\n.*?^{re.escape(_MANAGED_END)}\n?")


def _is_known_safety_guidance(content: str) -> bool:
    if content == _SAFETY_GUIDANCE:
        return True
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return digest in _LEGACY_SAFETY_GUIDANCE_DIGESTS


@dataclass(frozen=True, slots=True)
class _FileState:
    device: int
    inode: int
    size: int
    modified_ns: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class _PathDirectory:
    path: Path
    device: int
    inode: int


def install_agent_safety_guidance(home_dir: Path) -> dict[str, object]:
    """Install the Guard-owned guide and its managed global AGENTS.md pointer."""

    agents_path = home_dir / _AGENTS_RELATIVE_PATH
    safety_path = home_dir / _SAFETY_RELATIVE_PATH
    agents_changed = False
    safety_changed = False
    try:
        with _OpenedParent(agents_path) as agents_parent, _OpenedParent(safety_path) as safety_parent:
            existing_agents, agents_mode, agents_state = _read_regular_at(agents_parent, agents_path.name)
            updated_agents = _upsert_managed_block(existing_agents or "")
            existing_safety, safety_mode, safety_state = _read_regular_at(safety_parent, safety_path.name)
            if existing_safety is not None and not _is_known_safety_guidance(existing_safety):
                raise ValueError("Guard refused to trust an unmanaged SAFETY.md file")
            if existing_safety != _SAFETY_GUIDANCE:
                _write_text_at(safety_parent, safety_path.name, _SAFETY_GUIDANCE, safety_mode, safety_state)
                safety_changed = True
            if updated_agents != existing_agents:
                _write_text_at(agents_parent, agents_path.name, updated_agents, agents_mode, agents_state)
                agents_changed = True
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(
            _failure_message(
                "install",
                error,
                agents_changed=agents_changed,
                safety_changed=safety_changed,
            )
        ) from error
    return _success_payload("installed", agents_changed=agents_changed, safety_changed=safety_changed)


def uninstall_agent_safety_guidance(home_dir: Path) -> dict[str, object]:
    """Remove only Guard-managed guidance after the last harness uninstall."""

    agents_path = home_dir / _AGENTS_RELATIVE_PATH
    safety_path = home_dir / _SAFETY_RELATIVE_PATH
    agents_changed = False
    safety_changed = False
    try:
        if agents_path.parent.exists():
            with _OpenedParent(agents_path) as agents_parent:
                existing_agents, agents_mode, agents_state = _read_regular_at(agents_parent, agents_path.name)
                if existing_agents is not None:
                    updated_agents = _remove_managed_block(existing_agents)
                    if updated_agents != existing_agents:
                        _replace_or_unlink(
                            agents_parent,
                            agents_path.name,
                            updated_agents,
                            agents_mode,
                            agents_state,
                        )
                        agents_changed = True
        if safety_path.parent.exists():
            with _OpenedParent(safety_path) as safety_parent:
                existing_safety, _, safety_state = _read_regular_at(safety_parent, safety_path.name)
                if existing_safety is not None and _is_known_safety_guidance(existing_safety):
                    _unlink_at(safety_parent, safety_path.name, safety_state)
                    safety_changed = True
                elif existing_safety is not None:
                    raise ValueError("Guard refused to remove an unmanaged SAFETY.md file")
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(
            _failure_message(
                "remove",
                error,
                agents_changed=agents_changed,
                safety_changed=safety_changed,
            )
        ) from error
    return _success_payload("removed", agents_changed=agents_changed, safety_changed=safety_changed)


@final
class _OpenedParent:
    def __init__(self, path: Path) -> None:
        self._path = path.parent
        self._descriptor = -1

    def __enter__(self) -> int | _PathDirectory:
        required_dir_fd = (os.open, os.rename, os.unlink)
        if _is_reparse_path(self._path) or (self._path.exists() and not self._path.is_dir()):
            raise ValueError(f"Guard refused to use a non-directory support path: {self._path.name}")
        self._path.mkdir(parents=True, exist_ok=True)
        if any(operation not in os.supports_dir_fd for operation in required_dir_fd):
            metadata = self._path.stat(follow_symlinks=False)
            return _PathDirectory(self._path, metadata.st_dev, metadata.st_ino)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._descriptor = os.open(self._path, flags)
        return self._descriptor

    def __exit__(self, *_args: object) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)


def _read_regular_at(directory: int | _PathDirectory, name: str) -> tuple[str | None, int, _FileState | None]:
    if isinstance(directory, _PathDirectory):
        _assert_directory(directory)
        path = directory.path / name
        if _is_reparse_path(path) or (path.exists() and not path.is_file()):
            raise ValueError(f"Guard refused to replace a non-regular support file: {name}")
        if not path.exists():
            return None, 0o644, None
        raw = path.read_bytes()
        metadata = path.stat(follow_symlinks=False)
        return raw.decode("utf-8"), stat.S_IMODE(metadata.st_mode), _file_state(metadata, raw)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except FileNotFoundError:
        return None, 0o644, None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Guard refused to replace a non-regular support file: {name}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read()
            return raw.decode("utf-8"), stat.S_IMODE(metadata.st_mode), _file_state(metadata, raw)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_text_at(
    directory: int | _PathDirectory,
    name: str,
    text: str,
    mode: int,
    expected: _FileState | None,
) -> None:
    temporary_name = f".{name}.guard-{secrets.token_hex(8)}.tmp"
    raw = text.encode("utf-8")
    if isinstance(directory, _PathDirectory):
        _assert_directory(directory)
        temporary_path = directory.path / temporary_name
        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                _ = handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), mode)
                else:
                    os.chmod(temporary_path, mode)
            _assert_unchanged(directory, name, expected)
            _assert_directory(directory)
            os.replace(temporary_path, directory.path / name)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            _ = handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
        _assert_unchanged(directory, name, expected)
        os.rename(temporary_name, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=directory)


def _replace_or_unlink(
    directory: int | _PathDirectory,
    name: str,
    text: str,
    mode: int,
    expected: _FileState | None,
) -> None:
    if text:
        _write_text_at(directory, name, text, mode, expected)
    else:
        _unlink_at(directory, name, expected)


def _unlink_at(directory: int | _PathDirectory, name: str, expected: _FileState | None) -> None:
    _assert_unchanged(directory, name, expected)
    if isinstance(directory, _PathDirectory):
        _assert_directory(directory)
        (directory.path / name).unlink()
    else:
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)


def _assert_unchanged(directory: int | _PathDirectory, name: str, expected: _FileState | None) -> None:
    _, _, current = _read_regular_at(directory, name)
    if current != expected:
        raise OSError(f"Guard support file changed during update: {name}")


def _assert_directory(directory: _PathDirectory) -> None:
    if _is_reparse_path(directory.path) or not directory.path.is_dir():
        raise OSError(f"Guard support directory changed during update: {directory.path.name}")
    metadata = directory.path.stat(follow_symlinks=False)
    if (metadata.st_dev, metadata.st_ino) != (directory.device, directory.inode):
        raise OSError(f"Guard support directory changed during update: {directory.path.name}")


def _is_reparse_path(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    file_attributes: object = getattr(metadata, "st_file_attributes", 0)
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (isinstance(file_attributes, int) and bool(file_attributes & reparse_point)) or path.is_symlink()


def _file_state(metadata: os.stat_result, raw: bytes) -> _FileState:
    return _FileState(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        digest=hashlib.sha256(raw).digest(),
    )


def _upsert_managed_block(existing: str) -> str:
    matches = tuple(_MANAGED_PATTERN.finditer(existing))
    if (
        len(matches) > 1
        or existing.count(_MANAGED_BEGIN) != len(matches)
        or existing.count(_MANAGED_END) != len(matches)
    ):
        raise ValueError("Guard found an incomplete managed safety guidance block")
    if matches:
        return _MANAGED_PATTERN.sub(_MANAGED_BLOCK, existing)
    return f"{existing}\n{_MANAGED_BLOCK}" if existing else _MANAGED_BLOCK


def _remove_managed_block(existing: str) -> str:
    matches = tuple(_MANAGED_PATTERN.finditer(existing))
    if (
        len(matches) > 1
        or existing.count(_MANAGED_BEGIN) != len(matches)
        or existing.count(_MANAGED_END) != len(matches)
    ):
        raise ValueError("Guard found an incomplete managed safety guidance block")
    if not matches:
        return existing
    match = matches[0]
    before = existing[: match.start()]
    after = existing[match.end() :]
    if not after and before.endswith("\n"):
        before = before[:-1]
    return f"{before}{after}"


def _success_payload(status: str, *, agents_changed: bool, safety_changed: bool) -> dict[str, object]:
    return {
        "status": status,
        "changed": agents_changed or safety_changed,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }


def _failure_message(
    action: str,
    error: Exception,
    *,
    agents_changed: bool,
    safety_changed: bool,
) -> str:
    partial = f"agents_changed={str(agents_changed).lower()}, safety_changed={str(safety_changed).lower()}"
    return f"Guard could not {action} agent safety guidance ({partial}): {error}"


__all__ = ["install_agent_safety_guidance", "uninstall_agent_safety_guidance"]
