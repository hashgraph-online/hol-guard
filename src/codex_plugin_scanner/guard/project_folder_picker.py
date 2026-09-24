"""Open a local folder dialog for workspace audit selection."""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

_PICKER_LOCK = threading.Lock()
_PICKER_TIMEOUT_SECONDS = 180
_PROMPT = "Choose the project folder Guard should audit"


class ProjectFolderPickerBusyError(RuntimeError):
    """A folder dialog is already open."""


class ProjectFolderPickerUnavailableError(RuntimeError):
    """This machine has no usable folder dialog."""


def project_folder_picker_command(
    platform_name: str,
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[str, ...] | None:
    if platform_name == "darwin":
        return (
            "/usr/bin/osascript",
            "-e",
            f'POSIX path of (choose folder with prompt "{_PROMPT}")',
        )
    if platform_name == "win32":
        script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog; "
            f"$dialog.Description = '{_PROMPT}'; "
            "if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { "
            "Write-Output $dialog.SelectedPath }"
        )
        return ("powershell", "-NoProfile", "-STA", "-Command", script)
    zenity = which("zenity")
    if zenity:
        return (zenity, "--file-selection", "--directory", f"--title={_PROMPT}")
    kdialog = which("kdialog")
    if kdialog:
        return (kdialog, "--getexistingdirectory", ".", _PROMPT)
    return None


_LINUX_DIALOG_FAILURE_MARKERS = (
    "cannot open display",
    "failed to open display",
)


def _linux_dialog_stderr_is_cancel_noise(stderr: str) -> bool:
    lowered = stderr.lower()
    return not any(marker in lowered for marker in _LINUX_DIALOG_FAILURE_MARKERS)


def interpret_project_folder_picker_result(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    treat_exit_one_as_cancel: bool = False,
) -> str | None:
    selected = stdout.strip()
    if returncode == 0:
        return selected or None
    if treat_exit_one_as_cancel and returncode == 1 and not selected and _linux_dialog_stderr_is_cancel_noise(stderr):
        return None
    lowered = stderr.lower()
    if "user canceled" in lowered or "user cancelled" in lowered or "(-128)" in lowered or not stderr.strip():
        return None
    raise ProjectFolderPickerUnavailableError()


def choose_project_folder(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    platform_name: str | None = None,
) -> str | None:
    if not _PICKER_LOCK.acquire(blocking=False):
        raise ProjectFolderPickerBusyError()
    try:
        command = project_folder_picker_command(platform_name or sys.platform)
        if command is None:
            raise ProjectFolderPickerUnavailableError()
        run = runner or subprocess.run
        try:
            completed = run(
                list(command),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_PICKER_TIMEOUT_SECONDS,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ProjectFolderPickerUnavailableError() from error
        tool_name = Path(command[0]).name.lower()
        return interpret_project_folder_picker_result(
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            treat_exit_one_as_cancel=tool_name in {"zenity", "kdialog"},
        )
    finally:
        _PICKER_LOCK.release()
