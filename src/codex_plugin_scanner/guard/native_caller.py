"""The identity of the Guard process that asks the native runtime.

The resident cannot see which interpreter or package sent a request, so every
``harness_adapter`` request carries these facts once, in its context. The
native runtime derives each launcher, hook argv and package path from them.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Set once a frozen Guard installs its launch contract
#: (``install_frozen_codex_runtime``): it is then its own interpreter.
_frozen_contract = False


def install_frozen_contract() -> None:
    """Report this process as a frozen Guard from now on."""
    global _frozen_contract
    _frozen_contract = True


def hook_python() -> str:
    """The interpreter a hook relaunches: a frozen Guard by its resolved bytes
    (the hook manifest authenticates exactly those), else this interpreter."""
    from .frozen_runtime_commands import is_frozen_guard_runtime

    executable = Path(sys.executable).expanduser()
    if _frozen_contract or is_frozen_guard_runtime():
        return str(executable.resolve(strict=True))
    return str(executable.absolute())


def caller_identity() -> dict[str, object]:
    """This process's interpreter, frozen state, launchers, package root and version."""
    from ..version import __version__
    from .frozen_runtime_commands import is_frozen_guard_runtime
    from .stable_guard_cli import (
        frozen_cli_path_is_runnable,
        frozen_launcher_is_prune_safe,
        guard_cli_launcher,
        prune_safe_cli_executable,
        resolve_frozen_guard_cli,
    )

    executable = Path(sys.executable).expanduser()
    frozen = _frozen_contract or is_frozen_guard_runtime()
    absolute = str(executable.absolute())
    frozen_launcher = resolve_frozen_guard_cli() if frozen else None
    return {
        "executable": absolute,
        "executable_resolved": str(executable.resolve(strict=frozen)),
        "frozen": frozen,
        "launcher": guard_cli_launcher(),
        "frozen_launcher": frozen_launcher,
        "launcher_prune_safe": frozen_launcher is not None and frozen_launcher_is_prune_safe(frozen_launcher),
        "launcher_runnable": frozen_launcher is not None and frozen_cli_path_is_runnable(Path(frozen_launcher)),
        "cli_executable": prune_safe_cli_executable(absolute) if frozen else absolute,
        "package_root": str(Path(__file__).resolve().parents[2]),
        "version": __version__,
    }
