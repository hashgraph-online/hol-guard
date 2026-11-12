#!/usr/bin/env python3
"""Record native-permission persist vectors from the retired Python decision.

A Claude-native approval used to be turned into a stored policy in Python:
``_persist_claude_native_permission_policy`` chose the stored hash (a
well-formed approval-context token, else the runtime exact-match key, else the
raw hash), the events to write and the policy action, and
``_persist_claude_native_permission_for_runtime_artifact`` chose whether a
policy was saved at all, which event to leave when the current policy stays
authoritative, and whether the inventory row counts as approved. The resident
decides all of that now (``native_permission_persist_plan`` in
``hook_decision_native_permission_persist.rs``); Python only executes the
store writes the plan names.

The ``_recorded_*`` functions below are that Python code as it stood at
4c96a78f2c, with its store replaced by a recording store and its two helper
modules (the exact-match key and context, and the token check) frozen in this
file, so the oracle never calls the code it checks:

    python3 scripts/ci/record_native_permission_persist_vectors.py

Each vector holds the resident's inputs (``inputs``), the entry point that
produced it, the store operations the old code performed in order (``ops``),
the plan those operations amount to (``plan``) and the old return value
(``returns``). The Rust ``hook_decision_native_permission_persist_tests``
replays ``inputs`` and compares ``plan``.

The stored hash is what a saved approval is looked up by, so it must not
change across an upgrade: the vectors pin it for well-formed tokens, for the
legacy exact-command key and for every malformed token.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/native_permission_persist_vectors.json.gz")
NOW = "2026-10-20T00:00:00+00:00"
APPROVAL_CONTEXT_TOKEN_PREFIX = "guard-approval-context:v1:"

# --- frozen: store_base exact-match key and context -------------------------

_SCOPED_HARNESS_FAMILIES = frozenset(
    {
        "file-read",
        "mcp",
        "mcp-tool",
        "package-request",
        "prompt",
        "prompt-env-read",
        "prompt-file",
        "tool-action",
    }
)
_SCOPED_RUNTIME_EXACT_FAMILIES = frozenset({"file-read", "mcp-tool", "package-request", "prompt", "tool-action"})
_RUNTIME_SCOPED_EXACT_MATCH_PREFIX = "runtime-exact:"


def _recorded_artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return artifact_id if family in _SCOPED_HARNESS_FAMILIES else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_HARNESS_FAMILIES:
        return None
    return f"family:{family}"


def _recorded_family_key_value(family_key: str) -> str:
    if family_key.startswith("family:"):
        return family_key.removeprefix("family:")
    return family_key


def _recorded_runtime_scoped_exact_match_key(
    artifact_id: str | None,
    runtime_exact_match_context: str | None = None,
) -> str | None:
    if artifact_id is None or not artifact_id.strip() or artifact_id.startswith("family:"):
        return None
    family_key = _recorded_artifact_family_key(artifact_id)
    if family_key is None or _recorded_family_key_value(family_key) not in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    if runtime_exact_match_context is None:
        digest = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()
    else:
        digest = hashlib.sha256(
            json.dumps(
                {
                    "artifact_id": artifact_id,
                    "context": runtime_exact_match_context,
                    "version": 2,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return f"{_RUNTIME_SCOPED_EXACT_MATCH_PREFIX}{digest}"


def _recorded_runtime_tool_action_exact_match_context(
    *,
    config_path: str | None,
    source_scope: str | None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
    permission_mode: str | None = None,
) -> str | None:
    if not config_path and not source_scope and not raw_command_text and not wrapper_chain and not permission_mode:
        return None
    payload: dict[str, object] = {
        "config_path": str(Path(config_path).expanduser()) if config_path else None,
        "source_scope": source_scope,
        "raw_command_text": raw_command_text,
        "wrapper_chain": [item for item in wrapper_chain or () if isinstance(item, str) and item],
        "permission_mode": permission_mode,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# --- frozen: the approval-context token grammar -----------------------------
#
# The old code asked the native authority whether a value was a well-formed v1
# token. The recorder models that authority's published grammar (a prefix, an
# unpadded URL-safe base64 JSON object of exactly six keys, a version of 1 and
# five lowercase 64-hex digests, at most 2048 bytes) and checks the model
# against the verdict every named case below declares by construction.

_TOKEN_MAX_BYTES = 2048
_TOKEN_HASH_FIELDS = ("identity", "content", "capabilities", "policy", "sandbox")
_URL_SAFE = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _recorded_token_is_well_formed(token: object) -> bool:
    if not isinstance(token, str) or not token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX):
        return False
    encoded = token[len(APPROVAL_CONTEXT_TOKEN_PREFIX) :]
    if len(token.encode("utf-8")) > _TOKEN_MAX_BYTES or not encoded or not _URL_SAFE.fullmatch(encoded):
        return False
    if len(encoded) % 4 == 1:
        return False
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(payload, dict) or len(payload) != 6:
        return False
    if payload.get("version") != 1:
        return False
    for field in _TOKEN_HASH_FIELDS:
        value = payload.get(field)
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            return False
    return True


# --- frozen: the retired persist decision ------------------------------------


class ApprovalGateError(Exception):
    """Stand-in for the store's gate refusal; the recording store never raises it."""


@dataclass(frozen=True)
class PolicyDecision:
    harness: str
    scope: str
    action: str
    artifact_id: str
    artifact_hash: str
    reason: str
    source: str


class RecordingStore:
    """Records the writes the persist functions make, in order."""

    def __init__(self) -> None:
        self.ops: list[dict[str, Any]] = []

    def add_event(self, name: str, payload: Mapping[str, object], now: str) -> None:
        self.ops.append({"op": "add_event", "name": name, "payload": json.loads(json.dumps(payload)), "now": now})

    def upsert_policy(self, decision: PolicyDecision, now: str) -> None:
        self.ops.append(
            {
                "op": "upsert_policy",
                "harness": decision.harness,
                "scope": decision.scope,
                "action": decision.action,
                "artifact_id": decision.artifact_id,
                "artifact_hash": decision.artifact_hash,
                "reason": decision.reason,
                "source": decision.source,
                "now": now,
            }
        )

    def record_inventory_artifact(
        self,
        *,
        artifact: Any,
        artifact_hash: str,
        policy_action: str,
        changed: bool,
        now: str,
        approved: bool,
    ) -> None:
        self.ops.append(
            {
                "op": "record_inventory",
                "artifact_id": artifact.artifact_id,
                "artifact_hash": artifact_hash,
                "policy_action": policy_action,
                "changed": changed,
                "now": now,
                "approved": approved,
            }
        )

    def remove_pending(self, session_id: str, artifact_id: str) -> None:
        self.ops.append({"op": "remove_pending", "session_id": session_id, "artifact_id": artifact_id})


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _recorded_persist_claude_native_permission_policy(
    *,
    store: RecordingStore,
    artifact_id: str,
    artifact_hash: str,
    artifact_type: str | None = None,
    config_path: str | None = None,
    source_scope: str | None = None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
    action: str,
    reason: str,
    now: str,
    source: str = "claude-native-approval",
) -> bool:
    exact_match_context = (
        _recorded_runtime_tool_action_exact_match_context(
            config_path=config_path,
            source_scope=source_scope,
            raw_command_text=raw_command_text,
            wrapper_chain=wrapper_chain,
        )
        if artifact_type == "tool_action_request"
        else None
    )
    exact_artifact_hash = (
        _recorded_runtime_scoped_exact_match_key(artifact_id, exact_match_context)
        if artifact_type == "tool_action_request"
        else None
    )
    # keep_prefixed_when_unavailable only matters while the authority is down,
    # which the new code answers by persisting nothing.
    stored_artifact_hash = (
        artifact_hash if _recorded_token_is_well_formed(artifact_hash) else exact_artifact_hash or artifact_hash
    )
    try:
        if artifact_type == "tool_action_request" and exact_artifact_hash is None:
            store.add_event(
                "claude/native_permission_exact_key_missing",
                {
                    "artifact_id": artifact_id,
                    "artifact_type": artifact_type,
                    "source": source,
                },
                now,
            )
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow" if action == "allow" else "block",
                artifact_id=artifact_id,
                artifact_hash=stored_artifact_hash,
                reason=reason,
                source=source,
            ),
            now,
        )
        store.add_event(
            "claude/native_permission_saved",
            {
                "artifact_id": artifact_id,
                "artifact_hash": stored_artifact_hash,
                "action": action,
                "reason": reason,
            },
            now,
        )
    except ApprovalGateError:
        return False
    return True


def _recorded_persist_claude_native_permission_for_runtime_artifact(
    *,
    store: RecordingStore,
    payload: dict[str, object],
    artifact: Any,
    artifact_hash: str,
    action: str,
    authoritative_action: str,
    reason: str,
) -> tuple[bool, bool]:
    now = NOW
    raw_command_text_value = artifact.metadata.get("raw_command_text")
    raw_command_text = raw_command_text_value if isinstance(raw_command_text_value, str) else None
    wrapper_chain_value = artifact.metadata.get("wrapper_chain")
    wrapper_chain = (
        wrapper_chain_value
        if isinstance(wrapper_chain_value, Sequence) and not isinstance(wrapper_chain_value, str)
        else None
    )
    saved_policy = False
    if authoritative_action == "allow":
        saved_policy = _recorded_persist_claude_native_permission_policy(
            store=store,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            artifact_type=artifact.artifact_type,
            config_path=artifact.config_path,
            source_scope=artifact.source_scope,
            raw_command_text=raw_command_text,
            wrapper_chain=wrapper_chain,
            action=action,
            reason=reason,
            now=now,
        )
        if not saved_policy:
            return True, False
    else:
        store.add_event(
            "claude/native_permission_current_policy_retained",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_hash": artifact_hash,
                "native_action": action,
                "authoritative_action": authoritative_action,
            },
            now,
        )
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_action=authoritative_action,
        changed=False,
        now=now,
        approved=authoritative_action in {"allow", "warn"},
    )
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        store.remove_pending(session_id, artifact.artifact_id)
    return True, saved_policy


# --- the vector space ---------------------------------------------------------

_DIGESTS = tuple(hashlib.sha256(f"persist-vector-{index}".encode()).hexdigest() for index in range(8))


def _token_text(fields: Mapping[str, object] | str, *, padded: bool = False) -> str:
    text = fields if isinstance(fields, str) else json.dumps(fields, separators=(",", ":"), sort_keys=True)
    encoded = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
    return APPROVAL_CONTEXT_TOKEN_PREFIX + (encoded if padded else encoded.rstrip("="))


def _good_fields(seed: int = 0) -> dict[str, object]:
    return {
        "version": 1,
        "identity": _DIGESTS[seed % 8],
        "content": _DIGESTS[(seed + 1) % 8],
        "capabilities": _DIGESTS[(seed + 2) % 8],
        "policy": _DIGESTS[(seed + 3) % 8],
        "sandbox": _DIGESTS[(seed + 4) % 8],
    }


def _with(fields: Mapping[str, object], **changes: object) -> dict[str, object]:
    return {**fields, **changes}


def _without(fields: Mapping[str, object], key: str) -> dict[str, object]:
    return {name: value for name, value in fields.items() if name != key}


def _oversized() -> str:
    # Valid JSON, six keys, one digest each, padded with whitespace past 2048 bytes.
    return _token_text(json.dumps(_good_fields(1)) + " " * 2000)


# (name, hash text, well-formed by construction)
TOKEN_CASES: tuple[tuple[str, str, bool], ...] = (
    ("good_0", _token_text(_good_fields(0)), True),
    ("good_3", _token_text(_good_fields(3)), True),
    ("good_spaced_json", _token_text(json.dumps(_good_fields(2), indent=1)), True),
    ("good_version_float", _token_text(json.dumps(_good_fields(4)).replace('"version": 1', '"version": 1.0')), True),
    ("good_version_true", _token_text(_with(_good_fields(5), version=True)), True),
    ("bad_uppercase_digest", _token_text(_with(_good_fields(0), content=_DIGESTS[0].upper())), False),
    ("bad_short_digest", _token_text(_with(_good_fields(0), policy=_DIGESTS[0][:63])), False),
    ("bad_long_digest", _token_text(_with(_good_fields(0), policy=_DIGESTS[0] + "0")), False),
    ("bad_non_hex_digest", _token_text(_with(_good_fields(0), sandbox="g" * 64)), False),
    ("bad_null_digest", _token_text(_with(_good_fields(0), sandbox=None)), False),
    ("bad_int_digest", _token_text(_with(_good_fields(0), sandbox=7)), False),
    ("bad_version_2", _token_text(_with(_good_fields(0), version=2)), False),
    ("bad_version_string", _token_text(_with(_good_fields(0), version="1")), False),
    ("bad_version_missing", _token_text(_without(_good_fields(0), "version")), False),
    ("bad_five_keys", _token_text(_without(_good_fields(0), "sandbox")), False),
    ("bad_extra_key", _token_text(_with(_good_fields(0), extra=_DIGESTS[1])), False),
    ("bad_not_json", _token_text("not json"), False),
    ("bad_json_array", _token_text("[1,2,3,4,5,6]"), False),
    ("bad_json_string", _token_text('"x"'), False),
    ("bad_padded", _token_text(_good_fields(0), padded=True) + "=", False),
    ("bad_prefix_only", APPROVAL_CONTEXT_TOKEN_PREFIX, False),
    ("bad_wrong_version_prefix", "guard-approval-context:v2:" + _token_text(_good_fields(0))[26:], False),
    ("bad_uppercase_prefix", "Guard-Approval-Context:v1:" + _token_text(_good_fields(0))[26:], False),
    ("bad_standard_alphabet", APPROVAL_CONTEXT_TOKEN_PREFIX + "ab+/cd==", False),
    ("bad_length_mod_four_one", APPROVAL_CONTEXT_TOKEN_PREFIX + "abcde", False),
    ("bad_trailing_newline", _token_text(_good_fields(0)) + "\n", False),
    ("bad_leading_space", " " + _token_text(_good_fields(0)), False),
    ("bad_oversized", _oversized(), False),
    (
        "bad_invalid_utf8",
        APPROVAL_CONTEXT_TOKEN_PREFIX + base64.urlsafe_b64encode(b"\xff\xfe\xfd").decode().rstrip("="),
        False,
    ),
)

# (name, hash text): values that are not tokens at all.
LEGACY_HASHES: tuple[tuple[str, str], ...] = (
    ("legacy_plain", "hash-native"),
    ("legacy_empty", ""),
    ("legacy_sha256", hashlib.sha256(b"legacy").hexdigest()),
    ("legacy_exact_key", _RUNTIME_SCOPED_EXACT_MATCH_PREFIX + hashlib.sha256(b"already-exact").hexdigest()),
    ("legacy_unicode", "hash-ünï-日本"),
    ("legacy_prefix_lookalike", "guard-approval-context:v0:abc"),
)

ARTIFACT_IDS: tuple[str, ...] = (
    "claude-code:runtime:tool-action:abc123",
    "claude-code:runtime:file-read:.env",
    "claude-code:runtime:mcp-tool:server:tool",
    "claude-code:runtime:package-request:npm:left-pad",
    "claude-code:runtime:prompt:secret",
    "claude-code:runtime:bash:dangerous",
    "claude-code:runtime:mcp:server",
    "family:tool-action",
    "family:bogus",
    "claude-code:runtime",
    "   ",
    "",
    "claude-code:runtime:Tool-Action:Upper",
    "claude-code:runtime: tool-action :padded",
    " claude-code:runtime:tool-action:leading",
    "claude-code:runtime:tool-action:café/日本",
)

# (config_path, source_scope, raw_command_text, wrapper_chain)
CONTEXTS: tuple[tuple[Any, Any, Any, Any], ...] = (
    (None, None, None, None),
    ("", "", "", []),
    ("", None, None, []),
    ("/repo/.claude/settings.json", "project", "git status", ["bash", "-lc"]),
    ("/repo/.claude/settings.json", None, None, None),
    (None, "project", None, None),
    (None, None, "git status", None),
    (None, None, None, ["bash"]),
    (None, None, None, [1, None]),
    (None, None, None, [""]),
    ("", "user", "", None),
    ("/repo/.claude/settings.json", "project", "", ["", "x"]),
    ("~/.claude/settings.json", "user", "ls", None),
    ("~", "user", None, None),
    ("~/", "user", None, None),
    ("~/x/../y", "user", "x", None),
    ("/repo//.claude/./settings.json", "project", "x", None),
    ("//double/lead", "project", "x", None),
    ("///triple", "project", "x", None),
    ("relative/path/", "project", "x", None),
    ("/repo/../x", "project", "x", None),
    ("/repo/", "project", "x", None),
    (".", "project", "x", None),
    ("./x", "project", "x", None),
    ("/repo/ünï/設定.json", "project", "echo 'héllo' > 日本.txt", ["café", ""]),
    ("/repo/with space/a b.json", "project", "ls  -la\n\ttab", ["env", "FOO=bar"]),
    ("/repo/a", "Project", 'quote " back \\ slash / \u2028 😀 \x00\x01\x1f\x7f', None),
    ("/repo/a", " project ", "x" * 3000, ["y" * 500, "z"]),
    ("/repo/.claude/settings.json", "project", "git status", "bash"),
    ("/repo/.claude/settings.json", "project", 123, None),
    ("/repo/.claude/settings.json", "project", "git status", {"a": 1}),
)
# Contexts whose values only the artifact metadata can carry, not the typed question path.
_RAW_ONLY = {28, 29, 30}
_TILDE = {12, 13, 14, 15}

# A few contexts for artifacts that never build an exact-match context.
_SIMPLE_CONTEXTS = (CONTEXTS[0], CONTEXTS[3], CONTEXTS[12])

ACTIONS = ("allow", "deny", "block", "review", "warn", "")
AUTHORITATIVE = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
REASONS = ("native approval", "Approved in Claude native approval prompt.", 'naïve ✓ reason "quoted"')
SOURCES = ("claude-native-approval", "claude-ask-user-question")
HOMES = ("/home/recorder", "/home/recorder/", "/")
TYPES = ("tool_action_request", "file_read_request", None)


@dataclass(frozen=True)
class Case:
    entry: str
    artifact_id: str
    artifact_hash: str
    artifact_type: str | None
    context: tuple[Any, Any, Any, Any]
    action: str
    reason: str
    source: str
    authoritative_action: str | None
    tilde_home: str | None

    def inputs(self) -> dict[str, Any]:
        config_path, source_scope, raw_command_text, wrapper_chain = self.context
        return {
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "artifact_type": self.artifact_type,
            "config_path": config_path,
            "source_scope": source_scope,
            "raw_command_text": raw_command_text,
            "wrapper_chain": wrapper_chain,
            "action": self.action,
            "reason": self.reason,
            "source": self.source,
            "authoritative_action": self.authoritative_action,
            "tilde_home": self.tilde_home,
        }


def _case(
    entry: str,
    artifact_id: str,
    artifact_hash: str,
    artifact_type: str | None,
    context: tuple[Any, Any, Any, Any],
    *,
    action: str = "allow",
    reason: str = REASONS[0],
    source: str = SOURCES[0],
    authoritative_action: str | None = None,
    tilde_home: str | None = HOMES[0],
) -> Case:
    if entry == "policy":
        authoritative_action = None
    else:
        source = SOURCES[0]
        authoritative_action = authoritative_action or "allow"
    return Case(
        entry,
        artifact_id,
        artifact_hash,
        artifact_type,
        context,
        action,
        reason,
        source,
        authoritative_action,
        tilde_home,
    )


def _entries(
    artifact_id: str,
    artifact_hash: str,
    artifact_type: str | None,
    context: tuple[Any, Any, Any, Any],
    **kwargs: Any,
) -> Iterator[Case]:
    raw_only = any(context is CONTEXTS[index] for index in _RAW_ONLY)
    if not raw_only:
        yield _case("policy", artifact_id, artifact_hash, artifact_type, context, **kwargs)
    yield _case("runtime_artifact", artifact_id, artifact_hash, artifact_type, context, **kwargs)


def cases() -> Iterator[Case]:
    legacy = LEGACY_HASHES[0][1]
    # Every identity and every context, with the legacy hash the exact key replaces.
    for artifact_id in ARTIFACT_IDS:
        for context in CONTEXTS:
            yield from _entries(artifact_id, legacy, "tool_action_request", context)
        for artifact_type in TYPES[1:]:
            for context in _SIMPLE_CONTEXTS:
                yield from _entries(artifact_id, legacy, artifact_type, context)
    # Every hash shape against the identities and contexts that do and do not key.
    hashes = [text for _, text, _ in TOKEN_CASES] + [text for _, text in LEGACY_HASHES]
    for artifact_hash in hashes:
        for artifact_id in (ARTIFACT_IDS[0], ARTIFACT_IDS[1], ARTIFACT_IDS[5], ARTIFACT_IDS[7], ARTIFACT_IDS[11]):
            for context in (CONTEXTS[0], CONTEXTS[3], CONTEXTS[12]):
                yield from _entries(artifact_id, artifact_hash, "tool_action_request", context)
        yield from _entries(ARTIFACT_IDS[0], artifact_hash, None, CONTEXTS[3])
    # Every native action against every authoritative action.
    for action in ACTIONS:
        for artifact_hash in (legacy, TOKEN_CASES[0][1]):
            for artifact_id in (ARTIFACT_IDS[0], ARTIFACT_IDS[5], ARTIFACT_IDS[1]):
                yield _case("policy", artifact_id, artifact_hash, "tool_action_request", CONTEXTS[3], action=action)
                for authoritative in AUTHORITATIVE:
                    yield _case(
                        "runtime_artifact",
                        artifact_id,
                        artifact_hash,
                        "tool_action_request",
                        CONTEXTS[3],
                        action=action,
                        authoritative_action=authoritative,
                    )
    # Reasons and sources are carried into the events verbatim.
    for reason in REASONS:
        for source in SOURCES:
            for artifact_id in (ARTIFACT_IDS[0], ARTIFACT_IDS[5]):
                yield _case(
                    "policy", artifact_id, legacy, "tool_action_request", CONTEXTS[3], reason=reason, source=source
                )
        for authoritative in AUTHORITATIVE:
            yield _case(
                "runtime_artifact",
                ARTIFACT_IDS[0],
                legacy,
                "tool_action_request",
                CONTEXTS[3],
                reason=reason,
                authoritative_action=authoritative,
            )
    # The home directory only matters to a tilde path; a missing one only to nothing else.
    for home in (*HOMES, None):
        for index, context in enumerate(CONTEXTS):
            if home is None and index in _TILDE:
                continue
            yield from _entries(ARTIFACT_IDS[0], legacy, "tool_action_request", context, tilde_home=home)


def _artifact(case: Case) -> SimpleNamespace:
    config_path, source_scope, raw_command_text, wrapper_chain = case.context
    return SimpleNamespace(
        artifact_id=case.artifact_id,
        artifact_type=case.artifact_type,
        config_path=config_path,
        source_scope=source_scope,
        metadata={"raw_command_text": raw_command_text, "wrapper_chain": wrapper_chain},
    )


def run_oracle(case: Case) -> tuple[list[dict[str, Any]], Any]:
    """Run the frozen Python for one case; returns the store operations and its result."""

    store = RecordingStore()
    previous = os.environ.get("HOME")
    if case.tilde_home is not None:
        os.environ["HOME"] = case.tilde_home
    try:
        if case.entry == "policy":
            config_path, source_scope, raw_command_text, wrapper_chain = case.context
            returns: Any = _recorded_persist_claude_native_permission_policy(
                store=store,
                artifact_id=case.artifact_id,
                artifact_hash=case.artifact_hash,
                artifact_type=case.artifact_type,
                config_path=config_path,
                source_scope=source_scope,
                raw_command_text=raw_command_text,
                wrapper_chain=wrapper_chain,
                action=case.action,
                reason=case.reason,
                now=NOW,
                source=case.source,
            )
        else:
            assert case.authoritative_action is not None
            observed, saved = _recorded_persist_claude_native_permission_for_runtime_artifact(
                store=store,
                payload={"session_id": "recorded-session"},
                artifact=_artifact(case),
                artifact_hash=case.artifact_hash,
                action=case.action,
                authoritative_action=case.authoritative_action,
                reason=case.reason,
            )
            returns = [observed, saved]
    finally:
        if previous is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous
    return store.ops, returns


def derive_plan(ops: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The plan the recorded operations amount to."""

    upsert = next((op for op in ops if op["op"] == "upsert_policy"), None)
    events: list[dict[str, Any]] = []
    seen_policy = False
    for op in ops:
        if op["op"] == "upsert_policy":
            seen_policy = True
        elif op["op"] == "add_event":
            events.append(
                {"name": op["name"], "payload": op["payload"], "before_policy": upsert is not None and not seen_policy}
            )
    inventory = next((op for op in ops if op["op"] == "record_inventory"), None)
    return {
        "stored_artifact_hash": upsert["artifact_hash"] if upsert is not None else None,
        "policy_action": upsert["action"] if upsert is not None else None,
        "events": events,
        "inventory_approved": bool(inventory["approved"]) if inventory is not None else False,
    }


def _path_dependent(case: Case) -> bool:
    return bool(case.context[0]) and case.artifact_type == "tool_action_request"


def record(case: Case) -> dict[str, Any]:
    ops, returns = run_oracle(case)
    return {
        "entry": case.entry,
        "flavor": "posix" if _path_dependent(case) else "any",
        "inputs": case.inputs(),
        "ops": ops,
        "plan": derive_plan(ops),
        "returns": returns,
    }


def check_token_model() -> None:
    for name, text, expected in TOKEN_CASES:
        actual = _recorded_token_is_well_formed(text)
        if actual != expected:
            raise SystemExit(f"token model disagrees with the declared verdict for {name}: {actual} != {expected}")
    for name, text in LEGACY_HASHES:
        if _recorded_token_is_well_formed(text):
            raise SystemExit(f"legacy hash {name} is a well-formed token")


def main() -> int:
    if os.name == "nt":
        raise SystemExit("record on a POSIX host: the path vectors are POSIX path semantics")
    check_token_model()
    vectors = [record(case) for case in cases()]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
