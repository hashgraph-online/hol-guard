"""Canonical, serialization-independent identities for Codex hooks.

The canonical form and its digest live in the native runtime. A hook's
identity decides whether an approval the user already gave still covers the
hook in front of us, so a second implementation here would be a second answer
to that question: this module only names what is being identified and hands
the resident's answer back.

Callers that ask about many matcher groups ask about them at once. The
resident accepts a batch, so a walk costs one round trip rather than one per
group. A whole source's handlers are enumerated by the resident's inventory
answer instead (see ``codex_hook_inventory``).
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


def _group_entry(question: CodexHookGroupQuestion, kind: str) -> dict[str, object]:
    return {
        "kind": kind,
        "source_scope": question.source_scope,
        "source_hooks_enabled": question.source_hooks_enabled,
        "event_name": question.event_name,
        "group": question.group,
    }


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


__all__ = [
    "CODEX_HOOK_IDENTITY_SCHEMA",
    "CodexHookDefinitionTooDeepError",
    "CodexHookGroupQuestion",
    "CodexHookIdentityUnavailableError",
    "canonical_codex_hook_group_conflict_keys",
    "canonical_codex_hook_group_identities",
]
