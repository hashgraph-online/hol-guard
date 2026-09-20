"""Messages and status reconciliation for installed Guard updates."""

from __future__ import annotations

from pathlib import Path


def _normalize_output_text(value: str) -> str:
    return _update.redact_sensitive_text(value.strip())


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _payload_notes(payload: dict[str, object]) -> list[str]:
    return _update._string_list(payload.get("notes"))


def _append_payload_note(payload: dict[str, object], note: str | None) -> None:
    if note is None or not note.strip():
        return
    payload["notes"] = [*_update._payload_notes(payload), note]


def _shell_command(command: list[str]) -> str:
    if _update.os.name == "nt":
        return _update.subprocess.list2cmdline(command)
    return _update.shlex.join(command)


def _output_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _success_status(payload: dict[str, object]) -> str:
    current_version = str(payload.get("current_version") or "").strip()
    resulting_version = str(payload.get("resulting_version") or "").strip()
    versions_known = (
        bool(current_version)
        and bool(resulting_version)
        and current_version not in {"", "unknown"}
        and resulting_version not in {"", "unknown"}
    )
    is_local_wheel = str(payload.get("upgrade_source") or "") == "local_wheel"
    versions_differ = versions_known and current_version != resulting_version
    versions_equal = versions_known and current_version == resulting_version
    still_behind_pypi = (not is_local_wheel) and _update._is_stale_install(payload)

    if versions_differ:
        # Partial upgrades that remain behind PyPI stay "stale".
        return "stale" if still_behind_pypi else "updated"
    if still_behind_pypi:
        # Same resulting version while PyPI has a newer release (pin / no-op upgrade).
        return "stale"
    if versions_equal:
        # Same version after install is "current" unless this was an explicit repair/reinstall.
        if payload.get("recovery_reinstall") is True or payload.get("recovery_source_install") is True:
            return "updated"
        return "current"
    output_text = str(payload.get("stdout") or "").lower() + "\n" + str(payload.get("stderr") or "").lower()
    if any(hint in output_text for hint in _update._ALREADY_CURRENT_HINTS):
        return "current"
    if "requirement already satisfied: hol-guard" in output_text or "hol-guard is already installed" in output_text:
        return "current"
    return "updated"


def _is_stale_install(payload: dict[str, object]) -> bool:
    version_check = payload.get("version_check")
    return isinstance(version_check, dict) and version_check.get("update_available") is True


def _version_changed(current_version: str, resulting_version: str) -> bool:
    return (
        bool(current_version)
        and bool(resulting_version)
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    )


def _merge_version_checks(
    initial_version_check: object,
    post_version_check: object,
    resulting_version: str,
) -> dict[str, object]:
    if isinstance(post_version_check, dict) and post_version_check.get("update_available") is not None:
        return post_version_check
    if isinstance(initial_version_check, dict):
        merged = dict(initial_version_check)
        latest_version = merged.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip() and resulting_version not in {"", "unknown"}:
            try:
                if _update.Version(resulting_version) >= _update.Version(latest_version.strip()):
                    merged["update_available"] = False
                    merged["status"] = "current"
                    merged["current_version"] = resulting_version
            except _update.InvalidVersion:
                pass
        return merged
    if isinstance(post_version_check, dict):
        return post_version_check
    return {
        "source": "pypi",
        "status": "unavailable",
        "current_version": None,
        "latest_version": None,
        "update_available": None,
    }


def _stale_retry_command(payload: dict[str, object]) -> str:
    if str(payload.get("upgrade_source") or "") == "local_wheel":
        return ""
    version_check = payload.get("version_check")
    if isinstance(version_check, dict) and version_check.get("update_available") is True:
        return _update._shell_command(["hol-guard", "update"])
    retry_command = payload.get("retry_command")
    if isinstance(retry_command, str) and retry_command.strip():
        return retry_command.strip()
    command = payload.get("command")
    if isinstance(command, list) and command:
        return _update._shell_command(command)
    return ""


def _safe_update_retry_command(wheel_path: Path | None, *, include_alpha: bool = False) -> str:
    command = ["hol-guard", "update"]
    if include_alpha:
        command.append("--alpha")
    if wheel_path is not None:
        command.extend(["--wheel", str(wheel_path)])
    return _update._shell_command(command)


def _success_message(
    *,
    status: str,
    current_version: str,
    resulting_version: str,
    version_check: object = None,
    retry_command: str = "",
) -> str:
    if status == "blocked":
        return "HOL Guard update is blocked by incompatible package dependencies."
    if status == "stale":
        latest_version = None
        if isinstance(version_check, dict):
            latest = version_check.get("latest_version")
            if isinstance(latest, str) and latest.strip():
                latest_version = latest.strip()
        installed_version = resulting_version or current_version
        if latest_version and installed_version not in {"", "unknown"}:
            message = f"HOL Guard {installed_version} is behind PyPI {latest_version} after the update attempt."
        else:
            message = "HOL Guard is behind the latest PyPI release."
        if retry_command:
            return f"{message} Run: {retry_command}"
        return message
    if status == "current":
        return _update.already_current_update_message(version_check if isinstance(version_check, dict) else None)
    if status == "updated" and current_version == resulting_version:
        return "HOL Guard source was repaired successfully."
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return f"Updated HOL Guard from {current_version} to {resulting_version}."
    return "HOL Guard update completed successfully."


def _planned_update_message(
    *,
    version_check: dict[str, object],
    use_pypi: bool,
    wheel_path: Path | None = None,
) -> str:
    if wheel_path is not None:
        return "Review the planned local wheel install command before updating."
    if use_pypi:
        if version_check.get("update_available") is True:
            latest_version = version_check.get("latest_version")
            if isinstance(latest_version, str) and latest_version.strip():
                return f"Review the planned PyPI install command to update to {latest_version.strip()}."
        return "Review the planned PyPI install command to repair the install source."
    return "Review the planned installer command before updating."


def _success_notes(payload: dict[str, object]) -> list[str]:
    if str(payload.get("status") or "") not in {"current", "updated"}:
        return []
    return _update._output_lines(str(payload.get("stderr") or ""))


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
