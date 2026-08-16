"""Proof-gated classification for routine local directory creation."""

from __future__ import annotations

import shlex
from pathlib import Path

from ..secret_sensitivity import classify_secret_path

_DYNAMIC_PATH_MARKERS = ("$", "`", "*", "?", "[", "]", "{", "}", "\x00")
_SHELL_CONTROL_CHARACTERS = frozenset(";&|<>()\r\n")
_PROTECTED_DIRECTORY_NAMES = frozenset({".aws", ".codex", ".docker", ".git", ".gnupg", ".hol-guard", ".kube", ".ssh"})


def is_safe_routine_directory_creation(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Allow exact parents-only mkdir calls with bounded literal targets."""

    if "\n" in command_text or "\r" in command_text:
        return False
    try:
        lexer = shlex.shlex(command_text, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        parts = list(lexer)
    except ValueError:
        return False
    if len(parts) < 3 or parts[0] != "mkdir" or parts[1] not in {"-p", "--parents"}:
        return False
    targets = parts[2:]
    if any(
        target.startswith("-") or any(character in target for character in _SHELL_CONTROL_CHARACTERS)
        for target in targets
    ):
        return False
    if any(marker in target for target in targets for marker in _DYNAMIC_PATH_MARKERS):
        return False
    try:
        allowed_roots = tuple(root.resolve() for root in (cwd, home_dir) if root is not None)
        if not allowed_roots:
            return False
        for target in targets:
            if target == "~":
                if home_dir is None:
                    return False
                candidate = home_dir
            elif target.startswith("~/"):
                if home_dir is None:
                    return False
                candidate = home_dir / target[2:]
            elif target.startswith("~"):
                return False
            else:
                candidate = Path(target)
            if not candidate.is_absolute():
                if cwd is None or ".." in candidate.parts:
                    return False
                candidate = cwd / candidate
            resolved = candidate.resolve(strict=False)
            if not any(resolved.is_relative_to(root) for root in allowed_roots):
                return False
            if {part.casefold() for part in resolved.parts} & _PROTECTED_DIRECTORY_NAMES:
                return False
            if classify_secret_path(str(resolved), cwd=cwd, home_dir=home_dir) is not None:
                return False
    except (OSError, RuntimeError):
        return False
    return True


__all__ = ["is_safe_routine_directory_creation"]
