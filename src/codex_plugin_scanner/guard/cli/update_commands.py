"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path

_ALREADY_CURRENT_HINTS = (
    "already at latest version",
    "already up-to-date",
)


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
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for editable installs. Re-run your local install workflow instead."
            )
            return payload, 0
    if dry_run:
        payload["status"] = "planned"
        payload["changed"] = False
        payload["message"] = "Review the planned installer command before updating."
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
        payload["changed"] = False
        payload["error"] = str(error)
        return payload, 1
    payload["stdout"] = _normalize_output_text(result.stdout)
    payload["stderr"] = _normalize_output_text(result.stderr)
    payload["return_code"] = result.returncode
    importlib.invalidate_caches()
    payload["resulting_version"] = _current_version_from_subprocess()
    if result.returncode != 0:
        payload["status"] = "failed"
        payload["changed"] = False
        payload["message"] = "HOL Guard update failed."
        return payload, 1
    payload["status"] = _success_status(payload)
    payload["changed"] = payload["status"] == "updated"
    payload["message"] = _success_message(
        status=str(payload["status"]),
        current_version=current_version,
        resulting_version=str(payload.get("resulting_version") or ""),
    )
    notes = _success_notes(payload)
    if notes:
        payload["notes"] = notes
    return payload, 0


def _normalize_output_text(value: str) -> str:
    return value.strip()


def _output_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _success_status(payload: dict[str, object]) -> str:
    current_version = str(payload.get("current_version") or "").strip()
    resulting_version = str(payload.get("resulting_version") or "").strip()
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return "updated"
    output_text = str(payload.get("stdout") or "").lower()
    if any(hint in output_text for hint in _ALREADY_CURRENT_HINTS):
        return "current"
    if "requirement already satisfied: hol-guard" in output_text or "hol-guard is already installed" in output_text:
        return "current"
    return "updated"


def _success_message(*, status: str, current_version: str, resulting_version: str) -> str:
    if status == "current":
        return "HOL Guard is already current."
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return f"Updated HOL Guard from {current_version} to {resulting_version}."
    return "HOL Guard update completed successfully."


def _success_notes(payload: dict[str, object]) -> list[str]:
    if str(payload.get("status") or "") not in {"current", "updated"}:
        return []
    return _output_lines(str(payload.get("stderr") or ""))


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
