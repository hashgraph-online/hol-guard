"""Connection-proof authentication helpers for daemon hook requests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

CHALLENGE_HOOK_PATHS = frozenset({"/v1/hooks/codex", "/v1/hooks/claude-code"})


class HeaderTokenValidator(Protocol):
    def __call__(self, *, payload: dict[str, object] | None = None) -> bool: ...


def challenge_auth(path: str, payload: dict[str, object], consume: Callable[[dict[str, object]], bool]) -> bool:
    return path in CHALLENGE_HOOK_PATHS and consume(payload)


def request_auth(
    requires_token: bool,
    challenge_authorized: bool,
    payload: dict[str, object],
    header_token_is_valid: HeaderTokenValidator,
) -> bool:
    return not requires_token or challenge_authorized or header_token_is_valid(payload=payload)
