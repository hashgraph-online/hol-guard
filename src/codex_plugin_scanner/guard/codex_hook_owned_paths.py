"""Decide whether a program path lies inside a root this installation owns.

Claiming a Codex handler is not a judgement about how its command is spelled.
Guard's spelling is public: anyone can write it, which is why
``require_codex_hook_owner`` treats launcher syntax as conflict evidence and
never as proof. What is not public is where the program lives. A program
inside a root Guard already controls - the native bridge under this Guard
home, the bridge script inside this install's own package - could only have
been put there by someone who already controls Guard, and refusing to replace
it buys that attacker nothing they do not already have. A program anywhere
else may belong to an owner this install cannot speak for, however exactly it
imitates Guard, so it keeps its refusal.

Containment is therefore the whole security boundary, and it is decided on
resolved identity rather than on text: symlinks are followed on both sides, a
sibling root whose name merely starts the same is not inside, a program that
is not absolute names no file at all, and a program that does not exist is not
a claim but the missing-program case, which has its own message.
"""

from __future__ import annotations

from pathlib import Path


def path_is_inside(candidate: str, root: Path) -> bool:
    """Whether ``candidate`` resolves to a file under ``root``.

    Identity is compared with :meth:`Path.samefile`, not by comparing text, so
    a Windows handler spelled in a short ``PROGRA~1`` form or in different
    case still matches the root it is actually in, and ``…/guard-home-evil``
    still does not match ``…/guard-home``.
    """

    text = candidate.strip()
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        # A bare name is resolved through PATH at launch time, by whatever PATH
        # Codex happens to have. It names no file this check could own, and
        # resolving one here would be answering a different question.
        return False
    try:
        resolved = path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return False
    for parent in resolved.parents:
        try:
            if parent.samefile(resolved_root):
                return True
        except OSError:
            continue
    return False


__all__ = ["path_is_inside"]
