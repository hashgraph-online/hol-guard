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
refusing to replace it would buy nothing. See
:mod:`.codex_hook_owned_paths` for the containment rule that decides this.

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

import json
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from urllib.parse import parse_qsl

from .codex_hook_bridge_runtime import decode_bridge_config_argument
from .codex_hook_command_line import hook_command_tokens, hook_token_name
from .codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND
from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_owned_paths import path_is_inside

_GUARD_HOME_OPTION = "--guard-home"
_GUARD_HOME_QUERY_KEY = "guard-home"
_DAEMON_STATE_NAME = "daemon-state.json"
_BRIDGE_SCRIPT_NAME = "codex_daemon_hook_bridge.py"
_ISOLATED_FLAG = "-I"
_BRIDGE_LAUNCH_TOKENS = 4
_NATIVE_LAUNCH_TOKENS = 6
_BRIDGE_SCRIPT_INDEX = 2


def install_package_root() -> Path:
    """The package directory of the running installation.

    The bridge script Guard writes into a handler lives under this directory,
    so a handler pointing inside it is pointing inside code this install owns.
    """

    return Path(__file__).resolve().parent.parent


def _resolved(value: str) -> Path | None:
    text = value.strip()
    if not text:
        return None
    try:
        return Path(text).resolve(strict=False)
    except (OSError, ValueError):
        return None


def _option_guard_home(tokens: Sequence[str]) -> set[Path]:
    homes: set[Path] = set()
    for index, token in enumerate(tokens):
        if token == _GUARD_HOME_OPTION and index + 1 < len(tokens):
            candidate = _resolved(tokens[index + 1])
        elif token.startswith(f"{_GUARD_HOME_OPTION}="):
            candidate = _resolved(token.split("=", 1)[1])
        else:
            continue
        if candidate is not None:
            homes.add(candidate)
    return homes


def _payload_guard_home(payload: Mapping[str, object]) -> set[Path]:
    """Every Guard home the native bridge payload names, from each field that names one."""

    homes: set[Path] = set()
    query = payload.get("query")
    if isinstance(query, str):
        for key, value in parse_qsl(query, keep_blank_values=False):
            if key == _GUARD_HOME_QUERY_KEY and (candidate := _resolved(value)) is not None:
                homes.add(candidate)
    state_path = payload.get("state_path")
    if (
        isinstance(state_path, str)
        and (candidate := _resolved(state_path)) is not None
        and candidate.name == _DAEMON_STATE_NAME
    ):
        homes.add(candidate.parent)
    for key in ("fallback_command", "start_command"):
        command = payload.get(key)
        if isinstance(command, list):
            homes |= _option_guard_home([item for item in command if isinstance(item, str)])
    return homes


def _bridge_launch_tokens(tokens: Sequence[str]) -> list[str] | None:
    """The interpreter argv of a bridge launcher, once its native wrapper is stripped."""

    if len(tokens) == _NATIVE_LAUNCH_TOKENS and tokens[1] == NATIVE_CODEX_HOOK_COMMAND:
        return list(tokens[2:])
    if len(tokens) == _BRIDGE_LAUNCH_TOKENS:
        return list(tokens)
    return None


def _bridge_payload(tokens: Sequence[str], *, windows: bool | None) -> Mapping[str, object] | None:
    """The configuration a bridge launcher Guard wrote carries, or ``None``.

    The launcher is one interpreter, the isolation flag, the bridge script and
    exactly one config operand. A command carrying anything else is not a
    launcher this installer emitted.
    """

    launch = _bridge_launch_tokens(tokens)
    if launch is None or launch[1] != _ISOLATED_FLAG:
        return None
    if hook_token_name(launch[_BRIDGE_SCRIPT_INDEX], windows=windows) != _BRIDGE_SCRIPT_NAME:
        return None
    try:
        decoded = json.loads(decode_bridge_config_argument(launch[3]))
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _program_is_owned(tokens: Sequence[str], *, guard_home: Path, package_root: Path) -> bool:
    """Whether the program this handler runs sits in a root Guard controls.

    Two roots qualify. The native bridge is written under the Guard home, and
    stays there across an interpreter change or a moved virtualenv, which is
    the case a reinstall has to repair. The bridge script is written inside
    this install's own package. Nothing else counts, so a Guard-shaped command
    launched by an ordinary interpreter is reported rather than claimed.
    """

    if path_is_inside(tokens[0], guard_home):
        return True
    launch = _bridge_launch_tokens(tokens)
    return launch is not None and path_is_inside(launch[_BRIDGE_SCRIPT_INDEX], package_root)


def codex_hook_guard_home(command: str, *, windows: bool | None = None) -> Path | None:
    """The single Guard home a bridge launcher names, when it names exactly one.

    This reports what the command says, not who owns it: a launcher naming one
    home identifies an installation, but only
    :func:`codex_hook_binds_guard_home` decides whether this install may
    replace it. Returns ``None`` for a command that is not a bridge launcher
    Guard writes, and for one naming no Guard home or more than one, because
    none of those identify an installation at all.
    """

    tokens = hook_command_tokens(command, windows=windows)
    if not tokens:
        return None
    payload = _bridge_payload(tokens, windows=windows)
    if payload is None:
        return None
    homes = _payload_guard_home(payload)
    if len(homes) != 1:
        return None
    return next(iter(homes))


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

    bound = codex_hook_guard_home(command, windows=windows)
    if bound is None:
        return False
    try:
        if bound != guard_home.resolve(strict=False):
            return False
    except (OSError, ValueError):
        return False
    return _program_is_owned(
        hook_command_tokens(command, windows=windows),
        guard_home=guard_home,
        package_root=install_package_root() if package_root is None else package_root,
    )


def _handler_command(handler: Mapping[str, object]) -> str | None:
    """The handler's command, when it has one spelled as a string."""

    command = handler.get("command")
    return command if isinstance(command, str) else None


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

    root = install_package_root() if package_root is None else package_root
    recorded = frozenset(recorded_commands)
    bindings: list[dict[str, object]] = []
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, Mapping):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                # The group is the handler, so removing the handler removes
                # the group, and the exact group is what identifies it.
                if _handler_command(group) not in recorded and _binds(
                    group, guard_home, package_root=root, windows=windows
                ):
                    bindings.append({"event": event_name, "group": dict(group), "handler": dict(group)})
                continue
            for handler in handlers:
                if (
                    not isinstance(handler, Mapping)
                    or _handler_command(handler) in recorded
                    or not _binds(handler, guard_home, package_root=root, windows=windows)
                ):
                    continue
                # The group is named by its matcher alone: a group that also
                # holds a handler this install cannot speak for must lose only
                # the handler it owns, never the whole group.
                bindings.append(
                    {
                        "event": event_name,
                        "group": {"matcher": group.get("matcher")},
                        "handler": dict(handler),
                    }
                )
    return bindings


def _binds(entry: Mapping[str, object], guard_home: Path, *, package_root: Path, windows: bool | None) -> bool:
    command = entry.get("command")
    return isinstance(command, str) and codex_hook_binds_guard_home(
        command, guard_home, package_root=package_root, windows=windows
    )


__all__ = [
    "codex_hook_binds_guard_home",
    "codex_hook_guard_home",
    "install_package_root",
    "self_bound_hook_bindings",
]
