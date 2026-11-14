"""Recognize a Guard Codex handler this installation registered itself.

A managed handler carries the installation it serves inside its own command:
the native bridge launches with a JSON payload naming the Guard home it talks
to. Guard rewrites its registration whenever the launcher changes - a new
interpreter, a moved package, a reinstall after an upgrade - so the signed
manifest that proved the previous entry stops matching while the entry keeps
naming this Guard home.

Naming this home is not what makes the entry ours. Guard's command spelling is
public, so a handler that names this home proves only that someone knew where
Guard lives. What a stranger cannot do is put a program inside a root Guard
already controls. So an entry is claimed only when its program is the native
bridge under this Guard home, or the bridge script inside this install's own
package: an attacker able to plant either of those already controls Guard, and
refusing to replace it would buy nothing. The native ``codex_hook_owners``
kind decides containment, comparing files rather than spellings.

Everything else keeps its refusal, including a handler whose command is
exactly the one this installer would write. The common case is a Python
launcher: the program is an interpreter Guard does not own, anyone may invoke
it, and no inspection of the command can tell Guard's own earlier generation
from a stranger's imitation. Those are reported, not claimed.

Claiming is not adopting. A claimed slot is overwritten with a freshly
generated command and a new manifest; the bytes found there are never kept and
stamped as owned.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection, Mapping
from pathlib import Path
from typing import Any

from . import codex_hook_command_line as _command_line
from .codex_config import _Wire
from .codex_hook_command_line import hook_commands_use_windows_syntax
from .native_runner_authority import native_runner_authority

_KIND = "codex_hook_owners"
_TIMEOUT_SECONDS = 15.0


def install_package_root() -> Path:
    """The package directory of the running installation.

    The bridge script Guard writes into a handler lives under this directory,
    so a handler pointing inside it is pointing inside code this install owns.
    """

    return Path(__file__).resolve().parent.parent


def _cwd() -> str | None:
    try:
        return os.getcwd()
    except OSError:
        return None


def ask_hook_owners(op: str, *, windows: bool | None = None, **fields: object) -> dict[str, Any]:
    """One answer of the native ``codex_hook_owners`` kind.

    A Windows command naming an 8.3 short path is answered with the names it
    needs expanded; this host resolves them and asks again.
    """

    request: dict[str, object] = {"op": op, **short_path_fields(windows), **fields}
    return settle_short_paths(
        lambda: native_runner_authority(_KIND, request, timeout_seconds=_TIMEOUT_SECONDS), request, _KIND
    )


def short_path_fields(windows: bool | None = None) -> dict[str, object]:
    """The command syntax a native owner check splits with, before any name is expanded."""

    return {"windows": hook_commands_use_windows_syntax(windows), "long_paths": {}}


def settle_short_paths(ask: Callable[[], Mapping[str, Any]], request: dict[str, object], kind: str) -> dict[str, Any]:
    """Ask once, and again with each 8.3 short name the answer needs expanded."""

    for _ in range(2):
        answer = dict(ask())
        reply = answer.get("reply")
        if not isinstance(reply, Mapping):
            return answer
        expand = reply.get("expand")
        names = [str(name) for name in expand] if isinstance(expand, list) else []
        request["long_paths"] = {name: _command_line._long_path(name) or "" for name in names}
    raise RuntimeError(f"{kind} did not settle its short paths")


def answer_text(answer: Mapping[str, object], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise RuntimeError(f"codex_hook_owners answered without {key}")
    return value


def install_fields(guard_home: Path, package_root: Path | None) -> dict[str, Any]:
    """The install a handler must belong to, with the caller's working directory."""

    root = install_package_root() if package_root is None else package_root
    return {"cwd": _cwd(), "guard_home": str(guard_home), "package_root": str(root)}


def codex_hook_guard_home(command: str, *, windows: bool | None = None) -> Path | None:
    """The single Guard home a bridge launcher names, when it names exactly one.

    This reports what the command says, not who owns it: a launcher naming one
    home identifies an installation, but only
    :func:`codex_hook_binds_guard_home` decides whether this install may
    replace it. Returns ``None`` for a command that is not a bridge launcher
    Guard writes, and for one naming no Guard home or more than one, because
    none of those identify an installation at all.
    """

    home = ask_hook_owners("guard_home", windows=windows, command=command, cwd=_cwd()).get("home")
    return Path(home) if isinstance(home, str) else None


def codex_hook_binds_guard_home(
    command: str,
    guard_home: Path,
    *,
    package_root: Path | None = None,
    windows: bool | None = None,
) -> bool:
    """Whether this install may replace ``command`` as its own earlier generation.

    Both halves are required: the launcher names this Guard home and nothing
    else, and the program it runs sits inside a root this install controls.
    """

    answer = ask_hook_owners("binds", windows=windows, command=command, **install_fields(guard_home, package_root))
    return answer.get("binds") is True


def self_bound_hook_bindings(
    hooks: Mapping[str, object],
    *,
    guard_home: Path,
    package_root: Path | None = None,
    recorded_commands: Collection[str] = (),
    windows: bool | None = None,
) -> list[dict[str, object]]:
    """Exact bindings for the handlers an earlier generation of this install left behind.

    ``recorded_commands`` are the handler commands the authenticated manifest
    says this install wrote into this configuration. A handler running one of
    them, which nonetheless failed to match its recorded entry, is not a stale
    generation: Guard knows it wrote exactly that command, so what differs is
    the rest of the entry, and something outside Guard edited it. Guard holds
    that back rather than claiming it, because quietly rewriting the slot would
    repair the edit and leave the person who owns the machine never told their
    Codex configuration had been changed. A stale generation looks different -
    an upgrade, a moved virtualenv or a reinstall changes the launcher itself,
    so its command is not one the manifest recorded, and containment decides it
    as usual.
    """

    wire = _Wire(hooks)
    answer = ask_hook_owners(
        "self",
        windows=windows,
        hooks=wire.text(hooks),
        recorded=list(recorded_commands),
        **install_fields(guard_home, package_root),
    )
    return wire.decode(answer_text(answer, "bindings"))


__all__ = [
    "answer_text",
    "ask_hook_owners",
    "codex_hook_binds_guard_home",
    "codex_hook_guard_home",
    "install_fields",
    "install_package_root",
    "self_bound_hook_bindings",
    "settle_short_paths",
    "short_path_fields",
]
