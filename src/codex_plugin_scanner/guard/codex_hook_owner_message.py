"""Everything a Codex ownership refusal has to tell the person reading it.

Guard refuses here only for a handler it genuinely cannot speak for: one
Guard's own ownership rule did not claim, which it will neither replace nor
delete. That rule has two halves - the handler names this Guard home, and its
program sits inside a root this install controls - and the refusal says so
rather than naming one half, because either can be the half that failed.

Nobody but the person at the keyboard can settle that, so the message has to
hand them the whole case - where the handler is, what it runs, that
Guard changed nothing, and the single edit that clears it - rather than
telling them to resolve an owner it declines to name.
"""

from __future__ import annotations


def _location(coordinate: str | None, source_path: str | None) -> str:
    if coordinate and source_path:
        return f" at {coordinate} in {source_path}"
    if coordinate:
        return f" at {coordinate}"
    if source_path:
        return f" in {source_path}"
    return ""


def _remedy(source_path: str | None) -> str:
    where = source_path or "your Codex hooks configuration"
    return f"Delete that handler from {where}, then run `hol-guard install codex`; existing hooks have been preserved."


def owner_conflict_message(
    command: str,
    *,
    missing: str | None,
    coordinate: str | None,
    source_path: str | None,
) -> str:
    """The refusal text, naming the dead program when there is one."""

    location = _location(coordinate, source_path)
    remedy = _remedy(source_path)
    if missing is not None:
        return (
            f"codex_hook_owner_conflict: A Codex Guard handler{location} runs {missing}, which no longer "
            "exists, so Codex is not protected. It has no verified ownership binding, so Guard will not "
            f"remove it. {remedy}"
        )
    return (
        f"codex_hook_owner_conflict: An existing Codex Guard handler{location} has no verified ownership "
        "binding, so Guard installed nothing and left your configuration exactly as it was. Guard replaces a "
        "handler only when it names this installation's Guard home and runs a program inside a root this "
        "install controls; this one does not, so Guard cannot prove it wrote it. The handler "
        f"is: {command}. If it is yours, keep it and nothing more is needed. {remedy}"
    )


__all__ = ["owner_conflict_message"]
