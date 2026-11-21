"""Python reference for the ZCode authority-block remediation.

The native bridge (``bounded_hook_bridge_remediation.rs``) owns this decision,
and the standalone hook script carries its own copy because it cannot import
either. This reference pins the two to each other in ``test_zcode_hooks.py``.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

# Reason text emitted by the native command control floor when the local
# authority is degraded, tampered, or pending recovery. ZCode sessions see
# this on every tool call until the control floor is restored, so the
# remediation command must travel with the message.
_AUTHORITY_BLOCK_REASON_MARKER = "native command extension policy"
_AUTHORITY_BLOCK_REMEDIATION = (
    " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor."
)


def _quote_home(home: str, windows: bool) -> str | None:
    """``home`` written the way the shell it is pasted into reads it.

    Returns ``None`` when no spelling reaches that store.

    POSIX quoting puts ``C:\\guards\\ci`` inside single quotes, which
    ``cmd.exe`` hands on as part of the path, so a Windows person pastes a
    command that repairs nothing. A Windows path that needs no quoting is left
    bare, because quotes a path does not need only invite editing, and one
    that merely needs holding together is double-quoted, which both shells
    read literally, backslashes included. A Windows path cannot hold a ``"``,
    so nothing inside has to be escaped.

    Double quotes are not literal to either shell, though. PowerShell expands
    ``$name`` inside them and reads a backtick as an escape, and ``cmd.exe``
    expands ``%VAR%`` and, with delayed expansion, ``!name!``. A Windows path
    may legally hold all four. Single quotes would hold them in PowerShell but
    become part of the path in ``cmd.exe``, so no one rendering reaches such a
    store, and naming it
    anyway would send the person to repair a path the shell rewrote while this
    install stays blocked. ``windows`` is passed rather than read from
    ``os.name``, so both renderings are reachable from a test on either
    platform.
    """

    if not windows:
        return shlex.quote(home)
    plain = home != "" and all(
        character.isascii() and (character.isalnum() or character in "_-.:\\/") for character in home
    )
    if plain:
        return home
    if any(character in home for character in "$%`!"):
        return None
    return f'"{home}"'


def _authority_block_remediation(guard_home: Path | None, windows: bool) -> str:
    """Return the remediation sentence, naming ``guard_home`` when it needs it.

    The block names the home the hook read its authority from. Someone who
    pastes the bare command into a shell pointing somewhere else recovers a
    different install while this one stays blocked, so the home travels with
    the command whenever it is not ``<home>/.hol-guard``, shell-quoted for the
    terminal it is pasted into. The default home is left out: the short
    command is the one almost everyone needs, and a path that adds nothing only
    invites editing. A home this process cannot resolve leaves the bare
    command, because a runtime that cannot tell the two apart has nothing to
    add. A home no shell spelling reaches keeps it too, rather than one the
    shell would rewrite into a different store.

    ``--guard-home`` is the flag that names a store and nothing else;
    ``--home`` reaches the same store but also moves the home directory, to a
    directory nobody lives in. It goes on ``command``, the parser that carries
    it; after ``recover-authority`` argparse hands it to the leaf, which takes
    no options and would reject the whole line.
    """

    if guard_home is None:
        return _AUTHORITY_BLOCK_REMEDIATION
    try:
        home_dir = Path.home()
    except RuntimeError:
        return _AUTHORITY_BLOCK_REMEDIATION
    if home_dir / ".hol-guard" == guard_home:
        return _AUTHORITY_BLOCK_REMEDIATION
    quoted = _quote_home(str(guard_home), windows)
    if quoted is None:
        return _AUTHORITY_BLOCK_REMEDIATION
    return _AUTHORITY_BLOCK_REMEDIATION.replace(
        "command controls recover-authority",
        f"command --guard-home {quoted} controls recover-authority",
    )


def zcode_authority_block_reason(reason: str, guard_home: Path | None = None) -> str:
    """Append the control-floor remediation hint to authority block reasons.

    ZCode surfaces the deny reason directly to the user; without the hint a
    degraded control floor reads as an unactionable brick on every tool call.
    ``guard_home`` is the home the hook read that floor from, which the hint
    names when the bare command would not find it.
    """

    text = reason if isinstance(reason, str) else ""
    if _AUTHORITY_BLOCK_REASON_MARKER in text and "hol-guard command controls" not in text:
        return text + _authority_block_remediation(guard_home, os.name == "nt")
    return text
