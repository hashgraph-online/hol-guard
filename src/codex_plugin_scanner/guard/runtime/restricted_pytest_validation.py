"""Native restricted-launch validation and shared lexical path predicates."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import cast

from ..native_restricted_pytest import restricted_native
from .restricted_pytest_model import RestrictedPytestBackend


def _normalized_command(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(restricted_native("normalized_command", {"command": [str(item) for item in command]}, list))


def _resolve_workspace(workspace: Path) -> Path:
    return Path(restricted_native("resolve_workspace", {"path": workspace}, str))


def _resolve_cwd(cwd: Path, *, workspace: Path) -> Path:
    return Path(restricted_native("resolve_cwd", {"path": cwd, "workspace": workspace}, str))


def _resolve_executable(value: str, *, cwd: Path) -> Path:
    expanded = str(Path(value).expanduser()) if value.startswith("~") else value
    return Path(restricted_native("resolve_executable", {"value": expanded, "cwd": cwd}, str))


def _locate_executable(value: str, *, cwd: Path) -> Path:
    expanded = str(Path(value).expanduser()) if value.startswith("~") else value
    return Path(restricted_native("locate_executable", {"value": expanded, "cwd": cwd}, str))


def _select_backend(*, platform: str, backend_executable: Path | None) -> tuple[RestrictedPytestBackend, Path]:
    result = restricted_native("select_backend", {"platform": platform, "backend_executable": backend_executable}, list)
    if len(result) != 2 or result[0] not in {"macos-seatbelt", "linux-bubblewrap"}:
        raise ValueError("Invalid native restricted backend reply")
    return cast(RestrictedPytestBackend, result[0]), Path(result[1])


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        _ = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True
