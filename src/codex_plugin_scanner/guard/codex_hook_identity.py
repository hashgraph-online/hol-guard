"""Canonical, serialization-independent identities for Codex hooks.

The canonical form and its digest live in the native runtime. A hook's
identity decides whether an approval the user already gave still covers the
hook in front of us, so a second implementation here would be a second answer
to that question: this module only names what is being identified and hands
the resident's answer back.

Callers that walk a whole source ask about every hook in it at once. The
resident accepts a batch, so a walk costs one round trip rather than one per
handler, and the per-question helpers below are the same questions asked one
at a time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .native_codex_hook_identity import (
    CodexHookDefinitionTooDeepError,
    CodexHookIdentityUnavailableError,
    native_codex_hook_identity,
)

CODEX_HOOK_IDENTITY_SCHEMA = "codex-hook-identity-v1"


@dataclass(frozen=True, slots=True)
class CodexHookGroupQuestion:
    """One matcher group, with the coordinates its identity is taken over."""

    source_scope: str
    source_hooks_enabled: bool
    event_name: str
    group: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CodexHookHandlerQuestion:
    """One handler, and the command whose tokenization is wanted alongside it."""

    source_scope: str
    source_hooks_enabled: bool
    event_name: str
    group: Mapping[str, object]
    handler: Mapping[str, object]
    command: str | None = None


@dataclass(frozen=True, slots=True)
class CodexHookHandlerIdentity:
    """Both answers one handler question carries back."""

    command_argv: tuple[str, ...] | None
    canonical_identity: str


def canonical_codex_hook_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
    handler: Mapping[str, object],
) -> str:
    """Return one format- and coordinate-independent handler identity."""

    return _digest_of(
        _answer(
            _handler_entry(
                CodexHookHandlerQuestion(
                    source_scope=source_scope,
                    source_hooks_enabled=source_hooks_enabled,
                    event_name=event_name,
                    group=group,
                    handler=handler,
                )
            )
        )
    )


def canonical_codex_hook_group_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> str:
    """Return a canonical identity for one complete matcher group."""

    return _digest_of(
        _answer(
            _group_entry(
                CodexHookGroupQuestion(
                    source_scope=source_scope,
                    source_hooks_enabled=source_hooks_enabled,
                    event_name=event_name,
                    group=group,
                ),
                "group",
            )
        )
    )


def canonical_codex_hook_conflict_keys(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> tuple[str, ...]:
    """Identify handler slots whose differing definitions must not be collapsed."""

    return _conflict_keys_of(
        _answer(
            _group_entry(
                CodexHookGroupQuestion(
                    source_scope=source_scope,
                    source_hooks_enabled=source_hooks_enabled,
                    event_name=event_name,
                    group=group,
                ),
                "conflict",
            )
        )
    )


def canonical_codex_command_argv(command: str | None) -> tuple[str, ...] | None:
    """Normalize only commands whose shell tokenization is provably uncomplicated."""

    return _argv_of(_answer(_argv_entry(command)))


def canonical_codex_hook_handler_identities(
    questions: Sequence[CodexHookHandlerQuestion],
) -> tuple[CodexHookHandlerIdentity, ...]:
    """Identify every handler, and tokenize its command, in one round trip."""

    if not questions:
        return ()
    entries: list[Mapping[str, object]] = []
    for question in questions:
        entries.append(_argv_entry(question.command))
        entries.append(_handler_entry(question))
    answers = native_codex_hook_identity(entries)
    if len(answers) != len(entries):
        raise CodexHookIdentityUnavailableError
    return tuple(
        CodexHookHandlerIdentity(
            command_argv=_argv_of(answers[position]),
            canonical_identity=_digest_of(answers[position + 1]),
        )
        for position in range(0, len(answers), 2)
    )


def canonical_codex_hook_group_identities(
    questions: Sequence[CodexHookGroupQuestion],
) -> tuple[str, ...]:
    """Identify every matcher group in one round trip."""

    return tuple(_digest_of(answer) for answer in _group_answers(questions, "group"))


def canonical_codex_hook_group_conflict_keys(
    questions: Sequence[CodexHookGroupQuestion],
) -> tuple[tuple[str, ...], ...]:
    """Read every matcher group's conflict keys in one round trip."""

    return tuple(_conflict_keys_of(answer) for answer in _group_answers(questions, "conflict"))


def _group_answers(
    questions: Sequence[CodexHookGroupQuestion],
    kind: str,
) -> tuple[Mapping[str, object], ...]:
    """Ask one question of the same kind about every group."""

    if not questions:
        return ()
    answers = native_codex_hook_identity([_group_entry(question, kind) for question in questions])
    if len(answers) != len(questions):
        raise CodexHookIdentityUnavailableError
    return tuple(answers)


def _handler_entry(question: CodexHookHandlerQuestion) -> dict[str, object]:
    return {
        "kind": "handler",
        "source_scope": question.source_scope,
        "source_hooks_enabled": question.source_hooks_enabled,
        "event_name": question.event_name,
        "group": question.group,
        "handler": question.handler,
    }


def _group_entry(question: CodexHookGroupQuestion, kind: str) -> dict[str, object]:
    return {
        "kind": kind,
        "source_scope": question.source_scope,
        "source_hooks_enabled": question.source_hooks_enabled,
        "event_name": question.event_name,
        "group": question.group,
    }


def _argv_entry(command: str | None) -> dict[str, object]:
    entry: dict[str, object] = {"kind": "argv"}
    if command is not None:
        entry["command"] = command
    return entry


def _digest_of(answer: Mapping[str, object]) -> str:
    """The one digest an entry asking for a single identity answers with."""

    digest = answer.get("digest")
    if not isinstance(digest, str) or not digest:
        raise CodexHookIdentityUnavailableError
    return digest


def _conflict_keys_of(answer: Mapping[str, object]) -> tuple[str, ...]:
    digests = answer.get("digests")
    if not isinstance(digests, list) or not all(isinstance(item, str) for item in digests):
        raise CodexHookIdentityUnavailableError
    return tuple(digests)


def _argv_of(answer: Mapping[str, object]) -> tuple[str, ...] | None:
    argv = answer.get("argv")
    if argv is None:
        return None
    if not isinstance(argv, list) or not all(isinstance(token, str) for token in argv):
        raise CodexHookIdentityUnavailableError
    return tuple(argv)


def _answer(entry: Mapping[str, object]) -> dict[str, object]:
    """Ask the resident about one entry and return its answer."""

    return native_codex_hook_identity([entry])[0]


__all__ = [
    "CODEX_HOOK_IDENTITY_SCHEMA",
    "CodexHookDefinitionTooDeepError",
    "CodexHookGroupQuestion",
    "CodexHookHandlerIdentity",
    "CodexHookHandlerQuestion",
    "CodexHookIdentityUnavailableError",
    "canonical_codex_command_argv",
    "canonical_codex_hook_conflict_keys",
    "canonical_codex_hook_group_conflict_keys",
    "canonical_codex_hook_group_identities",
    "canonical_codex_hook_group_identity",
    "canonical_codex_hook_handler_identities",
    "canonical_codex_hook_identity",
]
