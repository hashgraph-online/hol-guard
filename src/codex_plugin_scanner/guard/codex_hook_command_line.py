"""Parse Guard-managed Codex hook command lines.

Codex hands a hook command to the session's shell: ``$SHELL -c`` on POSIX. On
Windows it uses the session shell when it knows it, usually
``powershell.exe -NoProfile -Command``, and otherwise ``%COMSPEC% /C`` (falling
back to ``cmd.exe``). A Windows hook command must therefore parse the same way
in PowerShell and in ``cmd.exe``. Neither accepts POSIX single-quote quoting,
Windows PowerShell 5.1 drops embedded double quotes when it passes arguments to
a native program, and no quoting form means the same thing in both shells.

Windows commands therefore use plain tokens only: the bridge config travels as
unpadded base64url text, and a path that would need quoting (for example one
under ``C:\\Program Files``) is replaced by its 8.3 short name when that name is
itself a plain token. Parsing maps such a short name back to the long path, so
integrity checks keep comparing the long argv. When a volume has no short
names, the command falls back to PowerShell's call operator with single-quoted
literals. That fallback only launches under a PowerShell session shell; a
``cmd.exe`` hook shell cannot run it.

The native runtime renders and splits these command lines, and looks up each
path's 8.3 short form and each short name's long form itself; this module only
names the hook command syntax this host targets.
"""

from __future__ import annotations

import os


def hook_commands_use_windows_syntax(windows: bool | None = None) -> bool:
    """Return whether hook commands target the Windows shells on this host."""

    return os.name == "nt" if windows is None else windows


__all__ = ["hook_commands_use_windows_syntax"]
