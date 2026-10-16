"""Prove that `hol-guard install <harness>` really registers Guard's hooks.

The qualification lane calls ``apply_managed_install`` as a library and accepts
its own ``active: true`` as the answer. That is the structural blind spot this
module closes: here the lane runs the shipped ``install`` command as a
subprocess and then reads the harness's own configuration file, against
``installed_contract.json`` rather than against a product contract, so a build
that registers nothing fails even if it reports success.
"""

from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Any

import tomllib

from .installed_runtime import InstalledRuntime, isolated_environment, json_payload, run_guard

CONTRACT_PATH = Path(__file__).with_name("installed_contract.json")

#: Marks a hook handler as Guard's. The command may be the frozen executable,
#: the native bridge or the Python bridge, so the lane matches on the family
#: name rather than one spelling.
GUARD_COMMAND_MARKERS = ("hol-guard", "hol_guard", "guard-command", "codex_plugin_scanner")

#: The gate refuses non-interactively rather than letting the lane through.
#:
#: These are the gate's own error codes, not its prose. Guard prints an
#: advisory enrolment notice mentioning the approval password on hosts that
#: have no gate at all, and that notice says in so many words that it does not
#: block the command, so matching on wording turned every unrelated install
#: failure into "this host has a gate".
GATE_REASONS = ("approval_gate_required", "approval_gate_totp_required", "lifecycle_gate")


class GateBlockedError(RuntimeError):
    """Raised when the host's canonical approval gate owns the install path.

    ``lifecycle_authority_home`` redirects protection mutations to the OS
    account's canonical Guard home whenever that home has an enabled gate, and
    that home is resolved from ``pwd``, not from ``HOME``. There is deliberately
    no environment seam, so the lane refuses to run on such a host instead of
    reaching for one. CI runners have no enrolled gate and are unaffected.
    """


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def install_harness(
    runtime: InstalledRuntime,
    harness: str,
    *,
    home: Path,
    guard_home: Path,
    workspace: Path,
    timeout: float = 600.0,
) -> dict[str, Any]:
    """Run the shipped install command for ``harness`` into a lane-owned home."""

    environment = isolated_environment(home=home, guard_home=guard_home)
    completed = run_guard(
        runtime,
        [
            "install",
            harness,
            "--home",
            str(home),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--json",
        ],
        environment=environment,
        timeout=timeout,
        cwd=workspace,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0 and any(reason in combined for reason in GATE_REASONS):
        raise GateBlockedError(
            "the host's canonical approval gate owns `install`, so this lane cannot run here; "
            "run it on a machine with no enrolled gate (CI runners have none). "
            f"`install {harness}` exited {completed.returncode}: {combined.strip()[-400:]}"
        )
    return {
        "harness": harness,
        "exit_code": completed.returncode,
        "payload": json_payload(completed),
        "stderr_tail": (completed.stderr or "").strip()[-600:],
    }


def _is_guard_command(value: object) -> bool:
    return isinstance(value, str) and any(marker in value for marker in GUARD_COMMAND_MARKERS)


def _handler_is_guard(handler: object) -> bool:
    """Whether one hook handler runs Guard.

    A Claude handler is ``{"type": "command", "command": …, "args": [...]}``;
    the command may be the executable itself or a bridge whose Guard identity
    shows up in its arguments instead.
    """

    if _is_guard_command(handler):
        return True
    if not isinstance(handler, dict):
        return False
    if _is_guard_command(handler.get("command")):
        return True
    arguments = handler.get("args")
    return isinstance(arguments, list) and any(_is_guard_command(argument) for argument in arguments)


def guard_handlers(group: object) -> list[dict[str, Any]]:
    """Every Guard handler inside one hook event group."""

    found: list[dict[str, Any]] = []
    entries = group if isinstance(group, list) else [group]
    for entry in entries:
        handlers = entry.get("hooks") if isinstance(entry, dict) else None
        candidates = handlers if isinstance(handlers, list) else [entry]
        for handler in candidates:
            if _handler_is_guard(handler) and isinstance(handler, dict):
                found.append(handler)
    return found


def handler_argv(handler: dict[str, Any]) -> list[str]:
    """The exact argv a harness would run for one Guard hook handler.

    A handler records its command either as an argv list or as a single shell
    command line, which is what Codex writes and runs through a shell. Taking
    the string whole would make the entire quoted line one filename, so it is
    split the way the harness's own shell would split it.
    """

    command = handler.get("command")
    argv: list[str] = []
    if isinstance(command, list):
        argv.extend(str(part) for part in command)
    elif isinstance(command, str):
        try:
            argv.extend(shlex.split(command))
        except ValueError:
            # Unbalanced quoting: no argv the harness could run either, so
            # report nothing rather than a command line this lane invented.
            return []
    arguments = handler.get("args")
    if isinstance(arguments, list):
        argv.extend(str(argument) for argument in arguments)
    return argv


def runnable_handlers(handlers: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Split registered handlers into the ones this machine could run and the rest.

    A hook entry naming a command that is not on the machine is not proof that
    Guard is registered: the harness would call it and get nothing. The aged
    pass writes exactly such an entry, so counting it would let a reinstall
    that registered nothing pass on the strength of the lane's own fixture.
    """

    live: list[dict[str, Any]] = []
    dangling: list[str] = []
    for handler in handlers:
        argv = handler_argv(handler)
        if argv and not Path(argv[0]).exists() and shutil.which(argv[0]) is None:
            dangling.append(argv[0])
            continue
        live.append(handler)
    return live, dangling


def read_config(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def assess_claude(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Every required Claude hook event must carry at least one Guard handler."""

    config_path = home / expectation["config"]
    config = read_config(config_path)
    hooks = config.get(expectation["hooks_key"]) if isinstance(config, dict) else None
    hooks = hooks if isinstance(hooks, dict) else {}
    events: dict[str, int] = {}
    failures: list[str] = []
    dangling: dict[str, list[str]] = {}
    for event in expectation["required_events"]:
        handlers, missing = runnable_handlers(guard_handlers(hooks.get(event)))
        events[event] = len(handlers)
        if missing:
            dangling[event] = missing
        if not handlers:
            spelled = f" ({missing[0]} is not on this machine)" if missing else ""
            failures.append(f"{config_path}: hook event {event} carries no Guard handler{spelled}")
    return {
        "config": str(config_path),
        "config_present": config is not None,
        "events": events,
        "dangling": dangling,
        "failures": failures,
    }


def assess_codex(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Guard's Codex hooks live in ``config.toml``. ``hooks.json`` is history.

    A current install migrates ``~/.codex/hooks.json`` into ``config.toml`` and
    Codex runs the TOML. A handler that remains only in the JSON is not the
    configuration Codex executes, so it cannot satisfy registration. A missing
    JSON file is not a defect. The aged pass still reads it for leftovers.
    """

    primary = home / expectation["config"]
    candidates = [primary]
    alternate = expectation.get("alternate_config")
    if isinstance(alternate, str) and alternate:
        candidates.append(home / alternate)
    carriers: dict[str, int] = {}
    dangling: dict[str, list[str]] = {}
    legacy_only: list[str] = []
    for path in candidates:
        config = read_config(path)
        hooks = config.get(expectation["hooks_key"]) if isinstance(config, dict) else None
        if not isinstance(hooks, dict):
            continue
        count = 0
        for group in hooks.values():
            live, missing = runnable_handlers(guard_handlers(group))
            count += len(live)
            if missing:
                dangling.setdefault(str(path), []).extend(missing)
        if not count:
            continue
        if path == primary:
            carriers[str(path)] = count
        else:
            legacy_only.append(str(path))
    minimum = int(expectation.get("minimum_guard_entries", 1))
    total = sum(carriers.values())
    failures: list[str] = []
    if total < minimum:
        unreachable = sorted({command for commands in dangling.values() for command in commands})
        notes: list[str] = []
        if unreachable:
            notes.append(f"{', '.join(unreachable)} is registered but not on this machine")
        if legacy_only:
            notes.append(f"a leftover handler in {', '.join(legacy_only)} is not the file Codex runs")
        suffix = f"; {'; '.join(notes)}" if notes else ""
        failures.append(f"{primary}: {total} Guard hook entries, expected at least {minimum}{suffix}")
    return {
        "config": [str(path) for path in candidates],
        "carriers": carriers,
        "dangling": dangling,
        "entries": total,
        "failures": failures,
    }


def assess_files(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Harnesses whose registration is a set of installed files."""

    present: dict[str, bool] = {}
    failures: list[str] = []
    for relative in expectation["required_files"]:
        path = home / relative
        present[relative] = path.exists()
        if not path.exists():
            failures.append(f"{path}: Guard did not install this file")
    loaded = _assess_loaded_by(home, expectation.get("loaded_by"))
    failures.extend(loaded["failures"])
    return {
        "files": present,
        "loaded_by": loaded,
        "failures": failures,
        "replay_gap": expectation.get("replay_gap"),
    }


def _assess_loaded_by(home: Path, loaded_by: object) -> dict[str, Any]:
    """Check that the harness's settings actually load the file Guard installed.

    An installed extension the agent never loads protects nothing, and file
    existence alone cannot tell the two apart. Oh My Pi records the extensions
    it loads as a list of paths in its settings, so the lane reads that list
    and resolves each entry the way the agent would.
    """

    if not isinstance(loaded_by, dict):
        return {"checked": False, "failures": []}
    settings_path = home / str(loaded_by["config"])
    extension = (home / str(loaded_by["file"])).resolve()
    config = read_config(settings_path)
    listed = config.get(str(loaded_by["list_key"])) if isinstance(config, dict) else None
    entries = [item for item in listed if isinstance(item, str)] if isinstance(listed, list) else []
    resolved = [Path(item).expanduser() for item in entries]
    resolved = [item if item.is_absolute() else settings_path.parent / item for item in resolved]
    referenced = any(candidate.resolve() == extension for candidate in resolved)
    failures: list[str] = []
    if not referenced:
        failures.append(f"{settings_path}: {loaded_by['list_key']} does not load {extension}")
    return {
        "checked": True,
        "config": str(settings_path),
        "entries": entries,
        "referenced": referenced,
        "failures": failures,
    }


def assess_harness(home: Path, harness: str, expectation: dict[str, Any]) -> dict[str, Any]:
    if "required_events" in expectation:
        assessment = assess_claude(home, expectation)
    elif "required_files" in expectation:
        assessment = assess_files(home, expectation)
    else:
        assessment = assess_codex(home, expectation)
    assessment["harness"] = harness
    assessment["registered"] = not assessment["failures"]
    return assessment


__all__ = [
    "CONTRACT_PATH",
    "GateBlockedError",
    "assess_claude",
    "assess_codex",
    "assess_files",
    "assess_harness",
    "guard_handlers",
    "handler_argv",
    "install_harness",
    "load_contract",
    "read_config",
    "runnable_handlers",
]
