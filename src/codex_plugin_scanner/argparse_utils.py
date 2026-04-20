"""Shared argparse helpers for friendly CLI errors."""

from __future__ import annotations

import argparse
import difflib
import re
from pathlib import Path

_INVALID_CHOICE_PATTERN = re.compile(r"invalid choice: '([^']+)' \(choose from ([^)]+)\)")


class FriendlyArgumentParser(argparse.ArgumentParser):
    """Augment argparse errors with command recovery hints."""

    def error(self, message: str) -> None:
        message = _rewrite_invalid_choice_message(self, message)
        hint = _error_hint(message, self.prog)
        if hint:
            message = f"{message}\n{hint}"
        super().error(message)


def should_default_to_scan_target(token: str, *, known_commands: set[str]) -> bool:
    if not token or token.startswith("-") or token in known_commands:
        return False
    candidate = Path(token)
    if candidate.exists() or token in {".", ".."}:
        return True
    if "/" in token or "\\" in token:
        return True
    return not _looks_like_command_typo(token, known_commands)


def _error_hint(message: str, prog: str) -> str | None:
    invalid_choice = _invalid_choice_hint(message)
    if invalid_choice is not None:
        return invalid_choice
    if "the following arguments are required:" in message:
        if _is_guard_prog(prog):
            return f"Run `{_guard_help_command(prog)}` to inspect available Guard commands."
        return f"Run `{prog} --help` to inspect available commands."
    return None


def _invalid_choice_hint(message: str) -> str | None:
    match = _INVALID_CHOICE_PATTERN.search(message)
    if match is None:
        return None
    attempted = match.group(1)
    raw_choices = [item.strip("' ") for item in match.group(2).split(",")]
    choices = [item for item in raw_choices if item]
    closest = difflib.get_close_matches(attempted, choices, n=1, cutoff=0.55)
    if not closest:
        return None
    return f"Did you mean `{closest[0]}`?"


def _rewrite_invalid_choice_message(parser: argparse.ArgumentParser, message: str) -> str:
    match = _INVALID_CHOICE_PATTERN.search(message)
    if match is None:
        return message
    visible_choices = _visible_subparser_choices(parser)
    if not visible_choices:
        return message
    rewritten = f"invalid choice: '{match.group(1)}' (choose from {', '.join(visible_choices)})"
    return f"{message[: match.start()]}{rewritten}{message[match.end() :]}"


def _visible_subparser_choices(parser: argparse.ArgumentParser) -> list[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            visible_actions = getattr(action, "_choices_actions", [])
            if visible_actions:
                return [str(item.dest) for item in visible_actions]
            return list(action.choices)
    return []


def _guard_help_command(prog: str) -> str:
    if prog.endswith(" guard") or _is_guard_prog(prog):
        return f"{prog} --help"
    return f"{prog} guard --help"


def _looks_like_command_typo(token: str, known_commands: set[str]) -> bool:
    return bool(difflib.get_close_matches(token, sorted(known_commands), n=1, cutoff=0.55))


def _is_guard_prog(prog: str) -> bool:
    if prog.endswith(" guard"):
        return True
    first_token = prog.split()[0] if prog else ""
    normalized = Path(first_token).stem.lower()
    return normalized in {"hol-guard", "plugin-guard"}


__all__ = ["FriendlyArgumentParser", "should_default_to_scan_target"]
