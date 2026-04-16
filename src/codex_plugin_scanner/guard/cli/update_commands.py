"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path


def run_guard_update(*, dry_run: bool) -> tuple[dict[str, object], int]:
    current_version = _current_version()
    installer = _installer_kind()
    command = _update_command(installer)
    payload: dict[str, object] = {
        "current_version": current_version,
        "installer": installer,
        "command": command,
        "dry_run": dry_run,
    }
    direct_url = _direct_url_payload()
    if direct_url is not None:
        payload["direct_url"] = direct_url
        is_editable = bool(direct_url.get("dir_info", {}).get("editable"))
        payload["editable_install"] = is_editable
        if is_editable:
            payload["status"] = "skipped"
            payload["error"] = (
                "Automatic update is disabled for editable installs. Re-run your local install workflow instead."
            )
            return payload, 0
    if dry_run:
        payload["status"] = "planned"
        return payload, 0
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        payload["status"] = "failed"
        payload["error"] = str(error)
        return payload, 1
    payload["status"] = "updated" if result.returncode == 0 else "failed"
    payload["stdout"] = result.stdout.strip()
    payload["stderr"] = result.stderr.strip()
    payload["return_code"] = result.returncode
    importlib.invalidate_caches()
    payload["resulting_version"] = _current_version_from_subprocess()
    return payload, 0 if result.returncode == 0 else 1


def _current_version() -> str:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _installer_kind() -> str:
    prefix_path = Path(sys.prefix).resolve()
    if (prefix_path / "pipx_metadata.json").exists():
        return "pipx"
    if "/pipx/venvs/" in prefix_path.as_posix().lower():
        return "pipx"
    return "pip"


def _update_command(installer: str) -> list[str]:
    if installer == "pipx":
        return ["pipx", "upgrade", "hol-guard"]
    return [sys.executable, "-m", "pip", "install", "--upgrade", "hol-guard"]


def _direct_url_payload() -> dict[str, object] | None:
    try:
        distribution = importlib.metadata.distribution("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return None
    raw_payload = distribution.read_text("direct_url.json")
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _current_version_from_subprocess() -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-c", 'import importlib.metadata; print(importlib.metadata.version("hol-guard"))'],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        return _current_version()
    if result.returncode != 0:
        return _current_version()
    version = result.stdout.strip()
    return version or _current_version()


__all__ = ["run_guard_update"]
