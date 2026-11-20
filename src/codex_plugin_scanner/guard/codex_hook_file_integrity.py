"""Live file and interpreter attestation for Guard-managed Codex hooks.

Authenticated manifests establish the expected hook identity. The native
``codex_hook_file_integrity`` kind describes trusted local files for those
manifests and verifies that the live filesystem still matches the
authenticated identity exactly. This module carries the caller's deadline and
the one fact only this interpreter knows: its own package roots.
"""

from __future__ import annotations

import math
import os
import sys
import sysconfig
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path


class CodexHookIntegrityError(RuntimeError):
    """One stable, non-secret integrity failure suitable for status output."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


_VALIDATION_DEADLINE: ContextVar[float | None] = ContextVar("codex_hook_validation_deadline", default=None)


def active_hook_validation_deadline() -> float | None:
    return _VALIDATION_DEADLINE.get()


def check_hook_validation_deadline() -> None:
    deadline = active_hook_validation_deadline()
    if deadline is not None and time.monotonic() >= deadline:
        raise CodexHookIntegrityError(
            "codex_hook_validation_deadline_expired",
            "Codex hook identity validation exhausted the operation deadline.",
        )


@contextmanager
def hook_validation_deadline(deadline: float | None) -> Iterator[None]:
    """Carry an I/O budget only; this scope grants no mutation authority.

    Nested legacy validators inherit the original budget. A narrower scope
    may shorten it, but cannot renew it. OS calls are checked on return; this
    does not claim to interrupt a stalled filesystem or identity service.
    """
    if deadline is not None and (isinstance(deadline, bool) or not math.isfinite(deadline)):
        raise CodexHookIntegrityError(
            "codex_hook_validation_deadline_invalid",
            "Codex hook validation budget is invalid.",
        )
    parent = active_hook_validation_deadline()
    effective = parent if deadline is None else deadline if parent is None else min(parent, deadline)
    token = _VALIDATION_DEADLINE.set(effective)
    try:
        check_hook_validation_deadline()
        yield
        check_hook_validation_deadline()
    finally:
        _VALIDATION_DEADLINE.reset(token)


def _python_package_roots() -> tuple[Path, ...]:
    """Return package roots belonging to the running Python installation.

    ``sysconfig`` supplies the authoritative purelib/platlib locations for the
    active interpreter.  The explicit prefix-derived candidates cover common
    POSIX venv and distro layouts, including Debian/Ubuntu ``dist-packages``,
    without trusting an arbitrary directory merely because it has a familiar
    basename.  ``site`` and the installed ``codex_plugin_scanner`` location cover
    pipx/venv layouts where the active purelib spelling differs from the path
    that imported the package.
    """

    roots: set[Path] = set()

    def add_root(value: str | Path | None) -> None:
        if value is None:
            return
        try:
            roots.add(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError):
            return

    try:
        configured_paths = sysconfig.get_paths()
    except (AttributeError, OSError, ValueError):
        configured_paths = {}
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if isinstance(value, str) and value:
            add_root(value)

    try:
        import site

        getsitepackages = getattr(site, "getsitepackages", None)
        if callable(getsitepackages):
            site_packages = getsitepackages()
            if isinstance(site_packages, (list, tuple)):
                for value in site_packages:
                    if isinstance(value, str) and value:
                        add_root(value)
        getusersitepackages = getattr(site, "getusersitepackages", None)
        if callable(getusersitepackages):
            user_site = getusersitepackages()
            if isinstance(user_site, str) and user_site:
                add_root(user_site)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        pass

    try:
        import codex_plugin_scanner

        package_file = getattr(codex_plugin_scanner, "__file__", None)
        if isinstance(package_file, str) and package_file:
            # site-packages/codex_plugin_scanner/__init__.py -> site-packages
            add_root(Path(package_file).expanduser().resolve(strict=False).parent.parent)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        pass

    version_dirs = {
        f"python{sys.version_info.major}",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
    }
    for prefix_value in {sys.prefix, sys.exec_prefix}:
        if not prefix_value:
            continue
        try:
            prefix = Path(prefix_value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        for lib_dir in ("lib", "lib64"):
            for version_dir in version_dirs:
                for package_dir in ("site-packages", "dist-packages"):
                    add_root(prefix / lib_dir / version_dir / package_dir)

    return tuple(sorted(roots, key=str))


_IO_REASON = "codex_hook_integrity_io_error"
_IO_MESSAGE = "Guard could not verify the Codex hook installation; run repair and inspect file permissions."
_TIMEOUT_SECONDS = 30.0


def _native(op: str, *, deadline_bound: bool = True, **fields: object) -> dict[str, object]:
    """One ``codex_hook_file_integrity`` op, refused as the runtime refuses it.

    The hook validation deadline bounds the call unless ``deadline_bound`` is
    false, for a verdict on a child that already ran under its own limits.
    """

    from .native_runner_authority import native_runner_authority

    if deadline_bound:
        check_hook_validation_deadline()
    request = {"op": op, "package_roots": [str(root) for root in _python_package_roots()], **fields}
    try:
        answer = native_runner_authority(
            "codex_hook_file_integrity",
            request,
            timeout_seconds=_TIMEOUT_SECONDS,
            deadline_monotonic=active_hook_validation_deadline() if deadline_bound else None,
        )
    except (OSError, ValueError) as exc:
        if deadline_bound:
            check_hook_validation_deadline()
        raise CodexHookIntegrityError(_IO_REASON, _IO_MESSAGE) from exc
    if deadline_bound:
        check_hook_validation_deadline()
    error = answer.get("error")
    if isinstance(error, dict):
        reason, message = error.get("reason"), error.get("message")
        if isinstance(reason, str) and isinstance(message, str):
            raise CodexHookIntegrityError(reason, message)
    if answer.get("ok") is not True or error is not None:
        raise CodexHookIntegrityError(_IO_REASON, _IO_MESSAGE)
    return answer


def _identity(answer: dict[str, object]) -> dict[str, object]:
    identity = answer.get("identity")
    if not isinstance(identity, dict):
        raise CodexHookIntegrityError(_IO_REASON, _IO_MESSAGE)
    return identity


def describe_regular_file(path: Path, *, role: str, executable_required: bool) -> dict[str, object]:
    return _identity(
        _native(
            "describe_regular",
            path=str(path.expanduser()),
            role=role,
            executable_required=executable_required,
        )
    )


def describe_executable_file(path: Path, *, role: str) -> dict[str, object]:
    """Describe an executable invocation and its canonical regular target.

    Virtual-environment interpreters are commonly symlinks. Executing only the
    resolved target can silently escape that environment, so the manifest binds
    both the absolute invocation path and the canonical target instead.
    """

    return _identity(_native("describe_executable", path=str(path.expanduser()), role=role))


def verify_regular_file_identity(identity: object) -> None:
    _native("verify_regular", identity=_wire(identity))


def verify_executable_file_identity(identity: object) -> None:
    _native("verify_executable", identity=_wire(identity))


def _wire(identity: object) -> object:
    """An identity as JSON carries it; anything else is refused as invalid."""

    return identity if isinstance(identity, dict) else None


def validate_regular_file(path: Path, *, role: str, executable_required: bool) -> os.stat_result:
    """The runtime's verdict on ``path``, with the metadata it judged.

    The runtime brackets its own check with the file's ``lstat``, so a file
    replaced while it judged is refused there; this returns the metadata the
    caller binds its descriptor to.
    """

    _native("validate", path=str(path), role=role, executable_required=executable_required)
    try:
        return path.lstat()
    except OSError as exc:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_missing",
            f"The Codex hook {role} is missing; repair the installation.",
        ) from exc


__all__ = [
    "CodexHookIntegrityError",
    "describe_executable_file",
    "describe_regular_file",
    "validate_regular_file",
    "verify_executable_file_identity",
    "verify_regular_file_identity",
]
