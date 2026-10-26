"""Resident bridge for the ``codex_hook_identity`` op.

A Codex hook's identity is the digest that decides whether an approval the
user already gave still covers the hook in front of us. Deriving it here would
mean a second implementation of the canonical form, and two implementations
drift: the resident owns it, and this module only ships the definition across
and hands the digest back. An unavailable resident yields no identity at all
rather than a locally computed one.

A hook definition is read from TOML and JSON, so it carries scalars JSON
cannot name: datetimes, dates, times, non-finite floats, integers wider than
the resident's number type, and whatever else a config file holds. Each of
those is replaced with a token drawn from a per-request random prefix that is
verified to match no string in the payload, and the token's meaning travels in
a separate map. A config file therefore cannot spell a token itself, so
nothing it contains can pass as a substituted scalar.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

CODEX_HOOK_IDENTITY_FEATURE = "codex-hook-identity-v1"
_REQUEST_SCHEMA = "guard-codex-hook-identity-request.v1"
_RESULT_SCHEMA = "guard-codex-hook-identity-result.v1"
# The resident hashes a canonical form of each entry and nothing else: no
# filesystem, no network, no store. The floor is what a cold resident needs to
# answer at all; the per-entry share is what the hashing actually costs.
_TIMEOUT_FLOOR_SECONDS = 5.0
_TIMEOUT_PER_ENTRY_SECONDS = 0.02
_TIMEOUT_CEILING_SECONDS = 30.0
# Mirrors ``CODEX_HOOK_IDENTITY_MAX_ENTRIES`` and
# ``CODEX_HOOK_IDENTITY_MAX_BYTES``.
_MAX_ENTRIES = 512
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# The widest integers the resident's number type carries exactly. A Python int
# outside this range travels as a token instead of losing its low digits to a
# float on the way across.
_EXACT_INT_MIN = -(2**63)
_EXACT_INT_MAX = 2**64 - 1
# The resident's JSON parser refuses a value nested past 32 levels, counting
# every value and not only containers, with the transport frame at 0. Four
# levels sit above a definition -- the frame, the request object, its
# ``entries`` array and the entry object the definition hangs off -- so a
# definition's deepest value may sit 29 levels down, counting the definition
# mapping itself as the first. Measuring it here names the config file that is
# too deep instead of letting the resident refuse the whole frame and look
# unavailable.
_MAX_DEFINITION_DEPTH = 29


class CodexHookIdentityUnavailableError(RuntimeError):
    """The resident could not derive the Codex hook identity."""

    code = "native_codex_hook_identity_unavailable"


class CodexHookDefinitionTooDeepError(CodexHookIdentityUnavailableError):
    """A hook definition nests deeper than the resident will read.

    A subclass, so every caller keeps failing closed on it; the separate code
    says the config file is at fault rather than the Guard installation.
    """

    code = "native_codex_hook_definition_too_deep"


def native_codex_hook_identity(
    entries: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one identity answer per entry, in order.

    Each entry names a ``kind``: ``handler`` and ``group`` answer with
    ``digest``, ``conflict`` with ``digests``, and ``argv`` with ``argv``.

    Raises ``CodexHookIdentityUnavailableError`` when the resident cannot
    answer, so a caller fails closed rather than treating an unidentified hook
    as one the user has already approved.
    """

    if not entries:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise CodexHookIdentityUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise CodexHookIdentityUnavailableError
    answers: list[dict[str, object]] = []
    for start in range(0, len(entries), _MAX_ENTRIES):
        answers.extend(_identities_for_batch(entries[start : start + _MAX_ENTRIES], home))
    return answers


def _identities_for_batch(entries: Sequence[Mapping[str, object]], home: Path) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    tokens = _ScalarTokens(entries)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"codex-hook-identity-{uuid4().hex}",
        "entries": [_entry_wire(entry, tokens) for entry in entries],
        "scalar_tokens": tokens.meanings,
    }
    try:
        response = _resident_request(
            operation="codex_hook_identity",
            request=wire,
            guard_home=home,
            timeout_seconds=_batch_timeout_seconds(len(entries)),
            required_feature=CODEX_HOOK_IDENTITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CodexHookIdentityUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise CodexHookIdentityUnavailableError
    identities = payload.get("identities")
    if not isinstance(identities, list) or len(identities) != len(entries):
        raise CodexHookIdentityUnavailableError
    if not all(isinstance(item, dict) for item in identities):
        raise CodexHookIdentityUnavailableError
    return cast("list[dict[str, object]]", identities)


def _batch_timeout_seconds(entry_count: int) -> float:
    """The deadline one batch of this size is allowed."""

    return min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ENTRY_SECONDS * entry_count,
    )


def _entry_wire(entry: Mapping[str, object], tokens: _ScalarTokens) -> dict[str, object]:
    """Ship one entry: its coordinates plainly, its definition tokenized."""

    wire: dict[str, object] = {
        "kind": str(entry.get("kind", "")),
        "source_scope": str(entry.get("source_scope", "")),
        "source_hooks_enabled": bool(entry.get("source_hooks_enabled", False)),
        "event_name": str(entry.get("event_name", "")),
    }
    group = entry.get("group")
    if isinstance(group, Mapping):
        wire["group"] = tokens.wire(group)
    handler = entry.get("handler")
    if isinstance(handler, Mapping):
        wire["handler"] = tokens.wire(handler)
    command = entry.get("command")
    if isinstance(command, str):
        wire["command"] = command
    return wire


class _ScalarTokens:
    """Stand-ins for the scalars a JSON request cannot carry.

    The prefix is drawn at random and then checked against every string the
    payload already holds, so a token can only ever mean what this class put
    in ``meanings``.
    """

    def __init__(self, entries: Sequence[Mapping[str, object]]) -> None:
        present: set[str] = set()
        for entry in entries:
            _collect_strings(entry, present)
        prefix = uuid4().hex
        while any(text.startswith(prefix) for text in present):
            prefix = uuid4().hex
        self._prefix = prefix
        self.meanings: dict[str, object] = {}

    def wire(self, value: Mapping[str, object]) -> dict[str, object]:
        """The JSON form of one mapping, with its exotic scalars replaced."""

        return cast("dict[str, object]", self._wire_value(value, 1))

    def _token_for(self, meaning: dict[str, str]) -> str:
        token = f"{self._prefix}-{len(self.meanings)}"
        self.meanings[token] = meaning
        return token

    def _wire_value(self, value: object, depth: int) -> object:
        """Mirror ``_canonical_value``'s dispatch, deciding what JSON holds.

        Order matters: ``bool`` is an ``int``, ``datetime`` is a ``date``, and
        ``str``/``bytes`` are sequences, so each is settled before the test
        that would also match it. ``depth`` counts the containers entered so
        far, the definition itself included.
        """

        if depth > _MAX_DEFINITION_DEPTH:
            raise CodexHookDefinitionTooDeepError
        if value is None or isinstance(value, str | bool):
            return value
        if isinstance(value, int):
            if _EXACT_INT_MIN <= value <= _EXACT_INT_MAX:
                return value
            return self._token_for({"__int__": str(value)})
        if isinstance(value, float):
            if math.isfinite(value):
                return value
            return self._token_for({"type": "float", "value": repr(value)})
        if isinstance(value, Mapping):
            return self._wire_mapping(value, depth)
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            return [self._wire_value(item, depth + 1) for item in value]
        if isinstance(value, datetime | date | time):
            return self._token_for({"type": type(value).__name__, "value": value.isoformat()})
        return self._token_for({"type": type(value).__name__, "value": repr(value)})

    def _wire_mapping(self, value: Mapping[str, object], depth: int) -> dict[str, object]:
        """A mapping whose keys are already in their canonical spelling.

        A key a JSON object cannot name is rendered here exactly as
        ``_canonical_mapping`` rendered it, because the resident reads keys as
        the strings they arrive as. Insertion follows sorted order so that two
        keys collapsing onto one canonical spelling keep the same winner the
        Python source gave them.
        """

        items = sorted(
            ((key if isinstance(key, str) else f"<{type(key).__name__}>:{key!r}", item) for key, item in value.items()),
            key=lambda pair: pair[0],
        )
        return {key: self._wire_value(item, depth + 1) for key, item in items}


def _collect_strings(value: object, out: set[str]) -> None:
    """Every string the payload holds, as a key or as a value."""

    if isinstance(value, str):
        out.add(value)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                out.add(key)
            _collect_strings(item, out)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _collect_strings(item, out)
