"""The identity of the Guard process that asks the native runtime.

The resident cannot see which interpreter or package sent a request, so every
``harness_adapter`` request carries these facts once, in its context. The
native runtime derives each launcher, hook argv and package path from them.
"""

from __future__ import annotations

import functools
import importlib.metadata
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


def _native_runtime() -> dict[str, object] | None:
    """The validated native runtime the native side launches hooks and MCP
    relays through: its path, size, digest and features, or None."""
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    identity = status.identity
    if not status.available or not status.compatible or identity is None or status.capabilities is None:
        return None
    return {
        "path": str(identity.path),
        "size": identity.size,
        "sha256": identity.sha256,
        "features": sorted(status.capabilities.features),
    }


def _distribution_location(distribution: importlib.metadata.Distribution | None) -> str | None:
    if distribution is None:
        return None
    try:
        return str(Path(str(distribution.locate_file(""))).absolute())
    except (OSError, RuntimeError):
        return None


def _distribution(name: str) -> importlib.metadata.Distribution | None:
    try:
        return importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None


@functools.lru_cache(maxsize=1)
def _attest_facts() -> dict[str, object]:
    """Where this interpreter's package and distributions live, which only
    the running Python can read. The native runtime runs the interpreter
    isolated and accepts it only when its imports agree with these facts."""
    import codex_plugin_scanner

    from ..version import __version__

    package_file = getattr(codex_plugin_scanner, "__file__", None)
    if not isinstance(package_file, str) or not package_file:
        return {"error": "guard_hook_python_active_package_unavailable"}
    hol: dict[str, object] | None = None
    hol_distribution = _distribution("hol-guard")
    if hol_distribution is not None:
        hol_root = _distribution_location(hol_distribution)
        if hol_root is None:
            return {"error": "guard_hook_python_hol_guard_distribution_unavailable"}
        entry_points = {
            item.name: item.value for item in hol_distribution.entry_points if item.group == "console_scripts"
        }
        hol = {
            "root": hol_root,
            "version": str(hol_distribution.version),
            "entry_point": entry_points.get("hol-guard"),
            "direct_url": hol_distribution.read_text("direct_url.json") or None,
        }
    return {
        "package_file": str(Path(package_file).absolute()),
        "package_root": None,
        "version": __version__,
        "cryptography_root": _distribution_location(_distribution("cryptography")),
        "hol": hol,
    }


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
        "native_runtime": _native_runtime(),
        "attest_facts": None if frozen else _attest_facts(),
    }
