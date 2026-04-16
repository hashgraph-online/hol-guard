"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

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
        payload["editable_install"] = bool(direct_url.get("dir_info", {}).get("editable"))
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
    except FileNotFoundError as error:
        payload["status"] = "failed"
        payload["error"] = str(error)
        return payload, 1
    payload["status"] = "updated" if result.returncode == 0 else "failed"
    payload["stdout"] = result.stdout.strip()
    payload["stderr"] = result.stderr.strip()
    payload["return_code"] = result.returncode
    payload["resulting_version"] = _current_version()
    return payload, 0 if result.returncode == 0 else 1


def _current_version() -> str:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _installer_kind() -> str:
    prefix = Path(sys.prefix).resolve().as_posix()
    if "/pipx/venvs/" in prefix:
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


__all__ = ["run_guard_update"]
