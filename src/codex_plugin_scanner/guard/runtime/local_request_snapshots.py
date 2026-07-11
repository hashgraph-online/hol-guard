"""Cloud-safe local approval request snapshots for command queue leases."""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone

from ..config import VALID_RECEIPT_REDACTION_LEVELS, load_guard_config
from ..redaction import redact_sensitive_text, redact_text
from ..review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
)
from ..store import GuardStore

LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT = 125
LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT = 25
LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT = 500
LOCAL_REQUEST_SNAPSHOT_MAX_BYTES = 900_000
LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS = 2_000
LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS = 20
LOCAL_REQUEST_TEXT_FIELD_MAX_CHARS = 256
LOCAL_REQUEST_COMMAND_FIELD_MAX_CHARS = 1_024
_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY = "guard_command_local_request_snapshot_cursor"


def local_request_snapshot_items(store: GuardStore) -> list[dict[str, object]]:
    pending_items, _ = _local_request_snapshot_items_for_status(
        store,
        status="pending",
        limit=100,
    )
    resolved_items, _ = _local_request_snapshot_items_for_status(
        store,
        status="resolved",
        limit=100,
    )
    return [*pending_items, *resolved_items]


def local_request_snapshot_payload(store: GuardStore) -> dict[str, object]:
    pending_items, pending_complete = _local_request_snapshot_items_for_status(
        store,
        status="pending",
        limit=LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
    )
    resolved_items, resolved_complete = _local_request_snapshot_items_for_status(
        store,
        status="resolved",
        limit=LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
    )
    request_max_bytes = _local_request_snapshot_request_max_bytes(
        pending_count=len(pending_items),
        resolved_count=len(resolved_items),
        max_bytes=LOCAL_REQUEST_SNAPSHOT_MAX_BYTES,
    )
    requests, pending_byte_complete, resolved_byte_complete = _local_request_snapshot_byte_capped_statuses(
        pending_items,
        resolved_items,
        max_bytes=request_max_bytes,
    )
    return {
        "requests": requests,
        "pendingComplete": pending_complete and pending_byte_complete,
        "resolvedComplete": resolved_complete and resolved_byte_complete,
        "pendingLimit": LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
        "resolvedLimit": LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
        "pendingCount": len(pending_items),
        "resolvedCount": len(resolved_items),
        "maxBytes": LOCAL_REQUEST_SNAPSHOT_MAX_BYTES,
    }


def _local_request_snapshot_request_max_bytes(
    *,
    pending_count: int,
    resolved_count: int,
    max_bytes: int,
) -> int:
    """Return the request-list budget after exact payload metadata overhead."""
    envelope = {
        "requests": [],
        "pendingComplete": False,
        "resolvedComplete": False,
        "pendingLimit": LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
        "resolvedLimit": LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
        "pendingCount": pending_count,
        "resolvedCount": resolved_count,
        "maxBytes": max_bytes,
    }
    envelope_bytes = len(json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    empty_requests_bytes = len(json.dumps({"requests": []}, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    metadata_bytes = max(0, envelope_bytes - empty_requests_bytes)
    return max(1, max_bytes - metadata_bytes)


def _local_request_snapshot_byte_capped_statuses(
    pending_items: list[dict[str, object]],
    resolved_items: list[dict[str, object]],
    *,
    max_bytes: int,
) -> tuple[list[dict[str, object]], bool, bool]:
    selected, pending_complete = _local_request_snapshot_byte_capped_items(
        pending_items,
        max_bytes=max_bytes,
    )
    if not pending_complete:
        return selected, False, False

    selected, resolved_complete = _local_request_snapshot_byte_capped_items(
        resolved_items,
        existing_items=selected,
        max_bytes=max_bytes,
    )
    return selected, True, resolved_complete


def _local_request_snapshot_byte_capped_items(
    items: list[dict[str, object]],
    *,
    max_bytes: int,
    existing_items: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], bool]:
    selected: list[dict[str, object]] = list(existing_items or [])
    initial_len = len(selected)
    for item in items:
        candidate = [*selected, item]
        candidate_bytes = len(
            json.dumps({"requests": candidate}, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )
        if candidate_bytes > max_bytes:
            if len(selected) == initial_len:
                compact_item = _compact_local_request_snapshot_item(item)
                compact_candidate = [*selected, compact_item]
                compact_bytes = len(
                    json.dumps({"requests": compact_candidate}, separators=(",", ":"), sort_keys=True).encode("utf-8"),
                )
                if compact_bytes <= max_bytes:
                    selected.append(compact_item)
            return selected, False
        selected.append(item)
    return selected, True


def _compact_local_request_snapshot_item(item: dict[str, object]) -> dict[str, object]:
    compact = {key: _compact_local_request_snapshot_value(value) for key, value in item.items()}
    compact_bytes = len(json.dumps(compact, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    if compact_bytes <= LOCAL_REQUEST_SNAPSHOT_MAX_BYTES:
        return compact

    safe_keys = (
        "localRequestId",
        "requestKind",
        "requestPayload",
        "localStatus",
        "firstSeenAt",
        "lastSeenAt",
        "resolvedAt",
        "status",
        "harness",
        "artifactId",
        "artifactName",
        "artifactType",
        "policyAction",
        "recommendedScope",
        "local_request_id",
        "rawCommandText",
        "raw_command_text",
        "commandText",
        "command_text",
        "reviewCommand",
        "actionEnvelope",
        "action_envelope_json",
        "envelopeRedacted",
        "envelope_redacted",
        "redactionEnabled",
        "redaction_enabled",
    )
    reduced = {key: compact[key] for key in safe_keys if key in compact}
    if reduced:
        return reduced
    return compact


def _compact_local_request_snapshot_value(value: object) -> object:
    if isinstance(value, str):
        if len(value) <= LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS:
            return value
        return f"{value[:LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS]}...[truncated]"
    if isinstance(value, list):
        return [_compact_local_request_snapshot_value(item) for item in value[:LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        return {str(key): _compact_local_request_snapshot_value(item) for key, item in value.items()}
    return value


def _local_request_snapshot_items_for_status(
    store: GuardStore,
    *,
    status: str,
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    items: list[dict[str, object]] = []
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError:
        oauth = None
    routing_base = _local_request_snapshot_routing_base(store, oauth)
    cursor_state = _local_request_snapshot_cursor_state(store)
    use_cursor = status != "pending"
    cursor = cursor_state.get(status) if use_cursor else None
    rows = store.list_approval_requests(
        status=status,
        limit=limit + 1,
        cursor=cursor if isinstance(cursor, str) and cursor else None,
    )
    if not rows and isinstance(cursor, str) and cursor:
        cursor = None
        rows = store.list_approval_requests(status=status, limit=limit + 1)
    cursor_supported = True
    if len(rows) > limit:
        rows, cursor_supported = _expand_cursorless_small_backlog(
            store,
            status=status,
            rows=rows,
            limit=limit,
        )
        if not cursor_supported:
            cursor = None
    page_limit = min(limit, len(rows))
    for item in rows[:page_limit]:
        request_id = item.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            continue
        created_at = str(item.get("created_at") or _now())
        last_seen_at = str(item.get("last_seen_at") or created_at)
        resolved_at = item.get("resolved_at")
        routing = _local_request_snapshot_routing_metadata(
            item,
            routing_base=routing_base,
            request_id=request_id,
            last_seen_at=last_seen_at,
        )
        claim = None
        if oauth is not None:
            try:
                claim = build_local_review_request_claim(
                    request_row=item,
                    oauth=oauth,
                    store=store,
                )
            except GuardReviewContractError:
                claim = None
        snapshot_item: dict[str, object] = {
            "claim": claim,
            "localRequestId": request_id,
            "requestKind": str(item.get("harness") or "guard-review"),
            "requestPayload": _cloud_safe_local_request_payload(
                item,
                redaction_level=redaction_level,
                routing_metadata=routing,
            ),
            "localStatus": str(item.get("status") or status),
            "firstSeenAt": created_at,
            "lastSeenAt": last_seen_at,
            "resolvedAt": str(resolved_at) if isinstance(resolved_at, str) and resolved_at else None,
        }
        snapshot_item.update(routing)
        items.append(snapshot_item)
    if cursor_supported and use_cursor:
        if len(rows) > limit:
            cursor_state[status] = _local_request_snapshot_next_cursor(rows, limit)
        else:
            cursor_state.pop(status, None)
        _save_local_request_snapshot_cursor_state(store, cursor_state)
    complete_limit = limit
    return items, cursor is None and len(rows) <= complete_limit


def _expand_cursorless_small_backlog(
    store: GuardStore,
    *,
    status: str,
    rows: list[dict[str, object]],
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    next_cursor = _local_request_snapshot_next_cursor(rows, limit)
    if next_cursor is None or not rows:
        return rows, True
    probe = store.list_approval_requests(status=status, limit=1, cursor=next_cursor)
    first_request_id = rows[0].get("request_id")
    probe_request_id = probe[0].get("request_id") if probe else None
    if not isinstance(first_request_id, str) or probe_request_id != first_request_id:
        return rows, True
    fallback_rows = store.list_approval_requests(
        status=status,
        limit=LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT + 1,
    )
    return fallback_rows, False


def _local_request_snapshot_cursor_state(store: GuardStore) -> dict[str, object]:
    value = store.get_sync_payload(_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY)
    return dict(value) if isinstance(value, dict) else {}


def _save_local_request_snapshot_cursor_state(
    store: GuardStore,
    state: dict[str, object],
) -> None:
    cleaned = {
        key: value
        for key, value in state.items()
        if key in {"pending", "resolved"} and isinstance(value, str) and value
    }
    store.set_sync_payload(_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY, cleaned, _now())


def _local_request_snapshot_next_cursor(
    rows: list[dict[str, object]],
    limit: int,
) -> str | None:
    if len(rows) <= limit:
        return None
    last_item = rows[limit - 1]
    payload = {
        "last_seen_at": str(last_item.get("last_seen_at") or last_item.get("created_at") or ""),
        "request_id": str(last_item.get("request_id") or ""),
    }
    if not payload["last_seen_at"] or not payload["request_id"]:
        return None
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    ).decode("ascii")
    return encoded.rstrip("=")


def _resolve_cloud_receipt_redaction_level(store: GuardStore) -> str:
    payload = store.get_sync_payload("cloud_receipt_redaction_level")
    if isinstance(payload, dict):
        level = payload.get("level")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    try:
        config = load_guard_config(store.guard_home)
        if config.receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
            return config.receipt_redaction_level
    except Exception:
        pass
    return "full"


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _first_optional_string(mapping: Mapping[str, object], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = _optional_string(mapping.get(key))
        if value is not None:
            return value
    return None


def _optional_payload_mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items() if isinstance(key, str)}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {
                "action_type": "unknown",
                "operation": "parse_action_envelope",
                "malformed": True,
                "reason": "invalid_action_envelope",
            }
        if isinstance(parsed, Mapping):
            return {str(key): item for key, item in parsed.items() if isinstance(key, str)}
        return {
            "action_type": "unknown",
            "operation": "parse_action_envelope",
            "malformed": True,
            "reason": "non_object_action_envelope",
        }
    return None


def _local_request_snapshot_routing_base(
    store: GuardStore,
    oauth: object | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {}
    if oauth is not None:
        for snake_key, camel_key, value in (
            ("workspace_id", "workspaceId", getattr(oauth, "workspace_id", None)),
            ("machine_installation_id", "machineInstallationId", getattr(oauth, "installation_id", None)),
            ("grant_id", "grantId", getattr(oauth, "grant_id", None)),
            ("runtime_grant_id", "runtimeGrantId", getattr(oauth, "runtime_id", None)),
        ):
            _set_dual_key(metadata, snake_key, camel_key, value)
        return metadata

    credentials = None
    try:
        credentials = store.get_oauth_local_credentials(allow_primary=False)
    except Exception:
        credentials = None
    if isinstance(credentials, Mapping):
        _set_dual_key(metadata, "workspace_id", "workspaceId", credentials.get("workspace_id"))
        _set_dual_key(metadata, "grant_id", "grantId", credentials.get("grant_id"))
        _set_dual_key(metadata, "runtime_grant_id", "runtimeGrantId", credentials.get("runtime_id"))
        _set_dual_key(
            metadata,
            "machine_installation_id",
            "machineInstallationId",
            credentials.get("machine_installation_id") or credentials.get("installation_id"),
        )
    if "machine_installation_id" not in metadata:
        with suppress(Exception):
            _set_dual_key(
                metadata,
                "machine_installation_id",
                "machineInstallationId",
                store.get_or_create_installation_id(),
            )
    return metadata


def _local_request_snapshot_routing_metadata(
    item: Mapping[str, object],
    *,
    routing_base: Mapping[str, object],
    request_id: str,
    last_seen_at: str,
) -> dict[str, object]:
    metadata = dict(routing_base)
    _set_dual_key(metadata, "local_request_id", "localRequestId", request_id)
    _set_dual_key(metadata, "harness_id", "harnessId", item.get("harness") or "guard-review")
    _set_dual_key(metadata, "request_last_seen_at", "requestLastSeenAt", last_seen_at)
    return metadata


_CLOUD_SPACED_SECRET_ARGUMENT_RE = re.compile(
    r'(?P<prefix>(?:^|\s)--?(?:[\w-]*(?:api[-_]?key|token|secret|password|credential|authorization|cookie)[\w-]*)\s+)(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE,
)

_SOURCE_SEARCH_COMMANDS = frozenset({"grep", "egrep", "fgrep", "rg"})
_SOURCE_SEARCH_OPTION_FLAGS_WITH_VALUES = frozenset(
    {
        "-A",
        "-B",
        "-C",
        "-f",
        "-g",
        "-m",
        "-t",
        "--after-context",
        "--before-context",
        "--color",
        "--context",
        "--exclude",
        "--exclude-dir",
        "--file",
        "--glob",
        "--iglob",
        "--include",
        "--max-count",
        "--type",
        "--type-add",
        "--type-not",
    }
)
_SOURCE_SEARCH_PATTERN_FLAGS = frozenset({"-e", "--regexp"})
_SOURCE_SEARCH_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        [\"']?
        (?:
            access[_-]?token
            |refresh[_-]?token
            |authorization[_-]?code
            |user[_-]?code
            |dpop[_-]?private[_-]?key(?:[_-]?(?:pem|ref))?
            |api[_-]?key
            |token
            |secret
            |password
            |credential
        )
        [\"']?
        \s*[:=]\s*
    )
    (?P<value>
        \"(?:\\.|[^\"])*\"
        |'(?:\\.|[^'])*'
        |[^\s,;)}\]]+
    )
    """
)
_SOURCE_SEARCH_CODE_VALUE_RE = re.compile(
    r"""(?ix)
    ^(?:
        \$\{?[A-Za-z_][A-Za-z0-9_]*\}?
        |(?:os\.(?:getenv|environ)|process\.env|getenv|env(?:iron)?\[|config(?:uration)?(?:\.|\[)|settings(?:\.|\[)|secrets?(?:\.|\[)|credentials?(?:\.|\[))
        |[A-Za-z_][A-Za-z0-9_.]*\([^\n]*\)
        |(?:none|null|undefined|true|false|value|variable|placeholder)
    )$
    """
)


@dataclass(frozen=True, slots=True)
class _ShellToken:
    value: str
    start: int
    end: int
    is_control: bool = False


def _cloud_scrub_text(value: str) -> str:
    protected_value, replacements = _protect_source_search_patterns(value)
    without_spaced_secret_arguments = _CLOUD_SPACED_SECRET_ARGUMENT_RE.sub(
        lambda match: f"{match.group('prefix')}[redacted]",
        protected_value,
    )
    scrubbed = redact_sensitive_text(redact_text(without_spaced_secret_arguments).text)
    for placeholder, replacement in replacements.items():
        scrubbed = scrubbed.replace(placeholder, replacement)
    return scrubbed


def _protect_source_search_patterns(value: str) -> tuple[str, dict[str, str]]:
    spans = _source_search_pattern_spans(value)
    if not spans:
        return value, {}

    parts: list[str] = []
    replacements: dict[str, str] = {}
    cursor = 0
    for index, (start, end) in enumerate(spans):
        if start < cursor:
            continue
        raw_token = value[start:end]
        safe_token = _safe_source_search_pattern_token(raw_token)
        placeholder = _source_search_placeholder(index, value)
        parts.append(value[cursor:start])
        parts.append(placeholder)
        replacements[placeholder] = safe_token
        cursor = end
    parts.append(value[cursor:])
    return "".join(parts), replacements


def _source_search_placeholder(index: int, value: str) -> str:
    nonce = 0
    while True:
        placeholder = f"__HOL_GUARD_SOURCE_SEARCH_PATTERN_{index}_{nonce}__"
        if placeholder not in value:
            return placeholder
        nonce += 1


def _safe_source_search_pattern_token(raw_token: str) -> str:
    try:
        parsed = shlex.split(raw_token, posix=True, comments=False)
    except ValueError:
        return raw_token
    if len(parsed) != 1:
        return raw_token

    original = parsed[0]
    safe = (
        _cloud_scrub_text(original)
        if _source_search_pattern_spans(original)
        else _scrub_source_search_pattern(original)
    )
    return raw_token if safe == original else shlex.quote(safe)


def _scrub_source_search_pattern(value: str) -> str:
    known_secret_safe = redact_text(value).text

    def redact_assignment(match: re.Match[str]) -> str:
        candidate = match.group("value")
        if _is_source_search_code_value(candidate):
            return match.group(0)
        return f"{match.group('prefix')}[redacted]"

    return _SOURCE_SEARCH_SECRET_ASSIGNMENT_RE.sub(redact_assignment, known_secret_safe)


def _is_source_search_code_value(value: str) -> bool:
    candidate = value.strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {"'", '"'}:
        candidate = candidate[1:-1].strip()
    lower_candidate = candidate.lower()
    if lower_candidate.startswith(
        (
            "os.getenv(",
            "os.environ",
            "process.env",
            "getenv(",
            "env[",
            "environment[",
            "config.",
            "config[",
            "configuration.",
            "configuration[",
            "settings.",
            "settings[",
            "secret.",
            "secret[",
            "secrets.",
            "secrets[",
            "credential.",
            "credential[",
            "credentials.",
            "credentials[",
        )
    ):
        return True
    return bool(_SOURCE_SEARCH_CODE_VALUE_RE.fullmatch(candidate))


def _source_search_pattern_spans(value: str) -> list[tuple[int, int]]:
    tokens = _shell_tokens(value)
    if tokens is None:
        return []

    spans: list[tuple[int, int]] = []
    segment_start = 0
    for index, token in enumerate((*tokens, _ShellToken(";", len(value), len(value), is_control=True))):
        if not token.is_control:
            continue
        spans.extend(_source_search_pattern_spans_for_segment(tokens, segment_start, index))
        segment_start = index + 1
    return spans


def _source_search_pattern_spans_for_segment(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> list[tuple[int, int]]:
    split_string_spans = [
        (tokens[index].start, tokens[index].end)
        for index in _source_search_split_string_token_indexes(tokens, start, end)
    ]
    command_index = _source_search_command_index(tokens, start, end)
    if command_index >= end:
        return split_string_spans

    command_name = _command_basename(tokens[command_index].value)
    argument_index = command_index + 1
    if command_name == "git":
        argument_index = _git_grep_argument_index(tokens, argument_index, end)
        if argument_index >= end:
            return split_string_spans
    elif command_name not in _SOURCE_SEARCH_COMMANDS:
        return split_string_spans

    return split_string_spans + [
        (tokens[index].start, tokens[index].end)
        for index in _source_search_pattern_token_indexes(tokens, argument_index, end)
    ]


def _source_search_split_string_token_indexes(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> list[int]:
    index = start
    while index < end:
        while index < end and _is_shell_environment_assignment(tokens[index].value):
            index += 1
        if index >= end:
            return []
        command_name = _command_basename(tokens[index].value)
        wrapper_index = _skip_transparent_source_search_wrapper(
            command_name,
            tokens,
            index + 1,
            end,
        )
        if wrapper_index is not None:
            index = wrapper_index
            continue
        if command_name != "env":
            return []
        return _env_split_string_token_indexes(tokens, index + 1, end)
    return []


def _env_split_string_token_indexes(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> list[int]:
    split_string_indexes: list[int] = []
    value_options = frozenset({"-C", "-S", "-u", "--chdir", "--split-string", "--unset"})
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return split_string_indexes
        clustered_split_string = _env_clustered_split_string_payload(value)
        if clustered_split_string is not None:
            if not clustered_split_string and index + 1 < end and _source_search_pattern_spans(tokens[index + 1].value):
                split_string_indexes.append(index + 1)
            index += 2 if not clustered_split_string else 1
            continue
        if value in value_options:
            if (
                value in {"-S", "--split-string"}
                and index + 1 < end
                and _source_search_pattern_spans(tokens[index + 1].value)
            ):
                split_string_indexes.append(index + 1)
            index += 2
            continue
        if value.startswith("--split-string="):
            split_string = value.removeprefix("--split-string=")
            if _source_search_pattern_spans(split_string):
                split_string_indexes.append(index)
            index += 1
            continue
        if value.startswith(("--chdir=", "--unset=")):
            index += 1
            continue
        if value.startswith("-") or _is_shell_environment_assignment(value):
            index += 1
            continue
        return split_string_indexes
    return split_string_indexes


def _env_clustered_split_string_payload(value: str) -> str | None:
    if not value.startswith("-") or value.startswith("--") or len(value) <= 2:
        return None
    split_index = value.find("S", 1)
    return None if split_index == -1 else value[split_index + 1 :]


def _source_search_command_index(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    index = start
    while index < end:
        while index < end and _is_shell_environment_assignment(tokens[index].value):
            index += 1
        if index >= end:
            return index
        command_name = _command_basename(tokens[index].value)
        wrapper_index = _skip_transparent_source_search_wrapper(
            command_name,
            tokens,
            index + 1,
            end,
        )
        if wrapper_index is not None:
            index = wrapper_index
            continue
        if command_name == "env":
            index = _skip_env_prefix_options(tokens, index + 1, end)
            continue
        return index
    return index


def _skip_command_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        if not value.startswith("-"):
            return index
        index += 1
    return index


def _skip_transparent_source_search_wrapper(
    command_name: str,
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int | None:
    if command_name in {"command", "nohup"}:
        return _skip_command_prefix_options(tokens, start, end)
    if command_name == "nice":
        return _skip_nice_prefix_options(tokens, start, end)
    if command_name == "stdbuf":
        return _skip_stdbuf_prefix_options(tokens, start, end)
    if command_name == "sudo":
        return _skip_sudo_prefix_options(tokens, start, end)
    if command_name == "time":
        return _skip_time_prefix_options(tokens, start, end)
    return None


def _skip_nice_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset({"-n", "--adjustment"})
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        clustered_split_string = _env_clustered_split_string_payload(value)
        if clustered_split_string is not None:
            index += 2 if not clustered_split_string else 1
            continue
        if value in value_options:
            index += 2
            continue
        if value.startswith("--adjustment=") or (value.startswith("-n") and value != "-n"):
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return index


def _skip_stdbuf_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset({"-e", "-i", "-o", "--error", "--input", "--output"})
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        if value in value_options:
            index += 2
            continue
        if value.startswith(("--error=", "--input=", "--output=")):
            index += 1
            continue
        if len(value) > 2 and value[:2] in {"-e", "-i", "-o"}:
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return index


def _skip_time_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset({"-f", "-o", "--format", "--output"})
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        if value in value_options:
            index += 2
            continue
        if value.startswith(("--format=", "--output=")):
            index += 1
            continue
        if len(value) > 2 and value[:2] in {"-f", "-o"}:
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return index


def _skip_env_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset({"-C", "-S", "-u", "--chdir", "--split-string", "--unset"})
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        if value in value_options:
            index += 2
            continue
        if value.startswith(("--chdir=", "--split-string=", "--unset=")):
            index += 1
            continue
        if value.startswith("-") or _is_shell_environment_assignment(value):
            index += 1
            continue
        return index
    return index


def _skip_sudo_prefix_options(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset(
        {
            "-C",
            "-D",
            "-g",
            "-p",
            "-r",
            "-t",
            "-u",
            "--chdir",
            "--close-from",
            "--group",
            "--host",
            "--other-user",
            "--preserve-env",
            "--prompt",
            "--role",
            "--type",
            "--user",
        }
    )
    index = start
    while index < end:
        value = tokens[index].value
        if value == "--":
            return index + 1
        if value in value_options:
            index += 2
            continue
        if value.startswith(
            (
                "--chdir=",
                "--close-from=",
                "--group=",
                "--host=",
                "--other-user=",
                "--preserve-env=",
                "--prompt=",
                "--role=",
                "--type=",
                "--user=",
            )
        ):
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return index


def _git_grep_argument_index(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> int:
    value_options = frozenset(
        {"-C", "-c", "--attr-source", "--config-env", "--exec-path", "--git-dir", "--namespace", "--work-tree"}
    )
    index = start
    while index < end:
        value = tokens[index].value
        if value == "grep":
            return index + 1
        if value == "--":
            return end
        if value in value_options:
            index += 2
            continue
        if value.startswith(
            ("--attr-source=", "--config-env=", "--exec-path=", "--git-dir=", "--namespace=", "--work-tree=")
        ):
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return end
    return end


def _source_search_pattern_token_indexes(
    tokens: Sequence[_ShellToken],
    start: int,
    end: int,
) -> list[int]:
    pattern_indexes: list[int] = []
    options_enabled = True
    index = start
    while index < end:
        value = tokens[index].value
        if options_enabled and value == "--":
            options_enabled = False
            index += 1
            continue
        if options_enabled and value in _SOURCE_SEARCH_PATTERN_FLAGS:
            if index + 1 >= end:
                return []
            pattern_indexes.append(index + 1)
            index += 2
            continue
        if options_enabled and _is_attached_source_search_pattern_option(value):
            pattern_indexes.append(index)
            index += 1
            continue
        if options_enabled and value in _SOURCE_SEARCH_OPTION_FLAGS_WITH_VALUES:
            if index + 1 >= end:
                return []
            index += 2
            continue
        if options_enabled and value.startswith("-"):
            index += 1
            continue
        if not pattern_indexes:
            pattern_indexes.append(index)
        return pattern_indexes
    return pattern_indexes


def _is_attached_source_search_pattern_option(value: str) -> bool:
    return value.startswith("--regexp=") or (value.startswith("-e") and len(value) > 2)


def _shell_tokens(value: str) -> list[_ShellToken] | None:
    tokens: list[_ShellToken] = []
    index = 0
    while index < len(value):
        while index < len(value) and value[index].isspace():
            index += 1
        if index >= len(value):
            break
        start = index
        character = value[index]
        if character in "|;&<>":
            index += 2 if index + 1 < len(value) and value[index : index + 2] in {"&&", "||", ">>", "<<"} else 1
            tokens.append(_ShellToken(value[start:index], start, index, is_control=True))
            continue

        quote: str | None = None
        while index < len(value):
            character = value[index]
            if quote is not None:
                if quote == '"' and character == "\\":
                    index += 2
                    continue
                if character == quote:
                    quote = None
                index += 1
                continue
            if character in {"'", '"'}:
                quote = character
                index += 1
                continue
            if character == "\\":
                index += 2
                continue
            if character.isspace() or character in "|;&<>":
                break
            index += 1
        if quote is not None:
            return None
        raw_token = value[start:index]
        try:
            parsed = shlex.split(raw_token, posix=True, comments=False)
        except ValueError:
            return None
        if len(parsed) != 1:
            return None
        tokens.append(_ShellToken(parsed[0], start, index))
    return tokens


def _is_shell_environment_assignment(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", value))


def _command_basename(value: str) -> str:
    return value.rsplit("/", maxsplit=1)[-1]


_SENSITIVE_CLOUD_FIELD_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)


def _is_sensitive_cloud_field(field_name: str | None) -> bool:
    if field_name is None:
        return False
    normalized = field_name.strip().lower().replace("-", "_")
    return any(marker in normalized for marker in _SENSITIVE_CLOUD_FIELD_MARKERS)


def _is_sensitive_cli_flag(value: str) -> bool:
    flag = value.strip().split("=", maxsplit=1)[0]
    return flag.startswith("-") and _is_sensitive_cloud_field(flag.lstrip("-"))


def _cloud_safe_local_request_payload(
    item: dict[str, object],
    *,
    redaction_level: str,
    routing_metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key in (
        "request_id",
        "status",
        "harness",
        "artifact_id",
        "artifact_name",
        "artifact_type",
        "artifact_hash",
        "artifact_label",
        "source_label",
        "trigger_summary",
        "why_now",
        "risk_headline",
        "risk_summary",
        "policy_action",
        "recommended_scope",
        "created_at",
        "last_seen_at",
        "queue_group_id",
        "review_kind",
        "risk_category",
        "capability_category",
        "publisher",
        "package_manager",
        "package_name",
        "resolution_action",
        "resolution_scope",
    ):
        value = item.get(key)
        if isinstance(value, str):
            payload[key] = _bounded_text(_cloud_scrub_text(value))
        elif isinstance(value, (int, float, bool)) or value is None:
            payload[key] = value

    if payload.get("status") == "expired":
        payload["status"] = "pending"

    if routing_metadata is not None:
        payload.update(routing_metadata)

    redaction_enabled = redaction_level != "none"
    payload["redaction_enabled"] = redaction_enabled
    payload["redactionEnabled"] = redaction_enabled

    envelope = _optional_payload_mapping(item.get("action_envelope_json"))
    envelope_reason = _first_optional_string(
        item,
        ("risk_summary", "why_now", "trigger_summary", "risk_headline", "policy_action"),
    )
    safe_envelope = _cloud_safe_action_envelope(
        envelope,
        redaction_level=redaction_level,
        reason=envelope_reason,
    )
    if safe_envelope is not None:
        payload["action_envelope_json"] = safe_envelope
        payload["actionEnvelope"] = safe_envelope
        if redaction_enabled:
            payload["envelope_redacted"] = safe_envelope
            payload["envelopeRedacted"] = safe_envelope

    command_text = _local_request_command_text(item, envelope)
    if redaction_enabled:
        payload["raw_command_text"] = None
        payload["command_text"] = None
        payload["rawCommandText"] = None
        payload["commandText"] = None
        return payload

    if command_text:
        scrubbed = _bounded_command(_cloud_scrub_text(command_text))
        payload["raw_command_text"] = scrubbed
        payload["rawCommandText"] = scrubbed
        payload["command_text"] = scrubbed
        payload["commandText"] = scrubbed
        payload_envelope = payload.get("action_envelope_json")
        if isinstance(payload_envelope, dict):
            payload_envelope["command"] = scrubbed
            action_envelope = payload.get("actionEnvelope")
            if isinstance(action_envelope, dict):
                action_envelope["command"] = scrubbed
    else:
        payload["raw_command_text"] = None
        payload["rawCommandText"] = None
        payload["command_text"] = None
        payload["commandText"] = None
    return payload


def _local_request_command_text(
    payload: dict[str, object],
    envelope: dict[str, object] | None,
) -> str | None:
    for key in ("raw_command_text", "rawCommandText", "command_text", "commandText"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if envelope is None:
        return None
    command = envelope.get("command")
    return command.strip() if isinstance(command, str) and command.strip() else None


def _cloud_safe_action_envelope(
    envelope: dict[str, object] | None,
    *,
    redaction_level: str,
    reason: str | None = None,
) -> dict[str, object] | None:
    if envelope is None:
        return None
    safe: dict[str, object] = {}
    for key in (
        "schema_version",
        "action_id",
        "harness",
        "event_name",
        "action_type",
        "workspace_hash",
        "tool_name",
        "mcp_server",
        "mcp_tool",
        "target_path_count",
        "network_host_count",
        "package_manager",
        "malformed",
        "reason",
    ):
        value = envelope.get(key)
        if isinstance(value, str):
            safe[key] = _bounded_text(value)
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value

    action_type = _first_optional_string(envelope, ("action_type", "actionType"))
    operation = _first_optional_string(envelope, ("operation",))
    if action_type is not None:
        _set_dual_key(safe, "action_type", "actionType", action_type)
    resolved_operation = operation or _operation_for_action_type(action_type)
    if resolved_operation is not None:
        safe["operation"] = _bounded_text(resolved_operation)
    _add_action_envelope_aliases(safe)

    redaction_enabled = redaction_level != "none"
    if redaction_enabled:
        target_class = _target_class_for_action_type(action_type, envelope)
        target_count = _target_count_for_envelope(envelope)
        _set_dual_key(safe, "target_class", "targetClass", target_class)
        _set_dual_key(safe, "target_count", "targetCount", target_count)
        redacted_reason = reason or _first_optional_string(envelope, ("reason", "pre_execution_result"))
        if redacted_reason is not None:
            safe["reason"] = _bounded_text(redacted_reason)
        return safe or None

    if redaction_level == "none":
        command = envelope.get("command")
        if isinstance(command, str) and command.strip():
            safe["command"] = _bounded_command(_cloud_scrub_text(command))
        for key in ("target_paths", "network_hosts", "package_name", "package_targets"):
            value = envelope.get(key)
            if isinstance(value, list):
                safe[key] = [_bounded_text(item) for item in value if isinstance(item, str)]
            elif isinstance(value, str):
                safe[key] = _bounded_text(value)
        _preserve_portal_action_contract_fields(safe, envelope)
        _add_action_envelope_aliases(safe)
    return safe or None


def _set_dual_key(
    payload: dict[str, object],
    snake_key: str,
    camel_key: str,
    value: object,
) -> None:
    if isinstance(value, str):
        if not value.strip():
            return
        normalized: object = _bounded_text(value.strip())
    elif isinstance(value, (int, float, bool)):
        normalized = value
    elif value is None:
        return
    else:
        normalized = _bounded_cloud_value(value)
    payload[snake_key] = normalized
    payload[camel_key] = normalized


def _bounded_cloud_value(value: object, *, field_name: str | None = None) -> object:
    if _is_sensitive_cloud_field(field_name):
        return "[redacted]"
    if isinstance(value, str):
        return _bounded_text(_cloud_scrub_text(value))
    if isinstance(value, Mapping):
        return {
            str(key): _bounded_cloud_value(item, field_name=str(key))
            for key, item in list(value.items())[:LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS]
            if isinstance(key, str)
        }
    if isinstance(value, Sequence) and not isinstance(value, str):
        scrubbed_items: list[object] = []
        redact_next_item = False
        for item in list(value)[:LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS]:
            if redact_next_item:
                scrubbed_items.append("[redacted]")
                redact_next_item = False
                continue
            scrubbed_items.append(_bounded_cloud_value(item, field_name=field_name))
            if isinstance(item, str) and _is_sensitive_cli_flag(item):
                redact_next_item = True
        return scrubbed_items
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _bounded_text(_cloud_scrub_text(str(value)))


def _add_action_envelope_aliases(safe: dict[str, object]) -> None:
    for snake_key, camel_key in (
        ("schema_version", "schemaVersion"),
        ("action_id", "actionId"),
        ("action_type", "actionType"),
        ("workspace_hash", "workspaceHash"),
        ("tool_name", "toolName"),
        ("mcp_server", "mcpServer"),
        ("mcp_tool", "mcpTool"),
        ("package_manager", "packageManager"),
        ("package_name", "packageName"),
        ("package_targets", "packageTargets"),
        ("target_paths", "targetPaths"),
        ("network_hosts", "networkHosts"),
        ("target_resource", "targetResource"),
        ("source_path", "sourcePath"),
        ("skill_name", "skillName"),
        ("requested_permission", "requestedPermission"),
        ("access_mode", "accessMode"),
        ("content_state", "contentState"),
    ):
        if snake_key in safe and camel_key not in safe:
            safe[camel_key] = safe[snake_key]


def _operation_for_action_type(action_type: str | None) -> str | None:
    return {
        "shell_command": "run",
        "file_read": "read",
        "file_read_request": "read",
        "file_write": "write",
        "file_write_request": "write",
        "mcp_tool": "call",
        "package_script": "install",
        "network_request": "request",
        "browser_action": "browse",
        "config_change": "update",
        "harness_start": "start",
        "prompt": "submit",
        "skill": "use",
        "skill_request": "use",
    }.get(action_type or "")


def _target_class_for_action_type(action_type: str | None, envelope: Mapping[str, object]) -> str:
    if action_type in {"file_read", "file_write", "file_read_request", "file_write_request"}:
        return "file"
    if action_type == "mcp_tool":
        return "mcp_tool"
    if action_type == "package_script" or _first_optional_string(envelope, ("package_name", "packageName")):
        return "package"
    if action_type == "network_request":
        return "network"
    if action_type == "browser_action":
        return "browser"
    if action_type in {"skill", "skill_request"}:
        return "skill"
    if action_type == "shell_command":
        return "shell_command"
    return "action"


def _target_count_for_envelope(envelope: Mapping[str, object]) -> int:
    count = 0
    for key in ("target_paths", "targetPaths", "network_hosts", "networkHosts", "package_targets", "packageTargets"):
        value = envelope.get(key)
        if isinstance(value, Sequence) and not isinstance(value, str):
            count += len([item for item in value if isinstance(item, str) and item.strip()])
        elif isinstance(value, str) and value.strip():
            count += 1
    if count:
        return count
    for key in (
        "path",
        "file_path",
        "filePath",
        "url",
        "uri",
        "endpoint",
        "origin",
        "host",
        "selector",
        "package_name",
        "packageName",
        "target_resource",
        "targetResource",
        "resource",
    ):
        if _optional_string(envelope.get(key)) is not None:
            return 1
    return 0


def _preserve_portal_action_contract_fields(
    safe: dict[str, object],
    envelope: Mapping[str, object],
) -> None:
    for key in (
        "operation",
        "resource",
        "resource_uri",
        "target",
        "target_resource",
        "skill_name",
        "source_path",
        "permission",
        "requested_permission",
        "path",
        "access_mode",
        "content_state",
        "url",
        "uri",
        "endpoint",
        "origin",
        "host",
        "selector",
        "method",
        "args",
        "arguments",
        "input",
        "parameters",
    ):
        if key in envelope and key not in safe:
            safe[key] = _bounded_cloud_value(envelope[key])

    action_type = _first_optional_string(envelope, ("action_type", "actionType"))
    target_paths = _string_list_from_envelope(envelope, ("target_paths", "targetPaths"))
    if action_type in {"file_read", "file_write", "file_read_request", "file_write_request"} and target_paths:
        safe.setdefault("path", target_paths[0])
        safe.setdefault("access_mode", "read" if "read" in action_type else "write")
        safe.setdefault("content_state", "metadata_only")

    network_hosts = _string_list_from_envelope(envelope, ("network_hosts", "networkHosts"))
    if action_type == "network_request" and network_hosts:
        safe.setdefault("host", network_hosts[0])

    package_name = _first_optional_string(envelope, ("package_name", "packageName"))
    if package_name is not None:
        safe.setdefault("package_name", _bounded_text(package_name))
    package_manager = _first_optional_string(envelope, ("package_manager", "packageManager"))
    if package_manager is not None:
        safe.setdefault("package_manager", _bounded_text(package_manager))

    mcp_tool = _first_optional_string(envelope, ("mcp_tool", "mcpTool"))
    if action_type == "mcp_tool" and mcp_tool is not None:
        safe.setdefault("tool_name", _bounded_text(mcp_tool))
    if action_type == "mcp_tool" and target_paths:
        safe.setdefault("target_resource", target_paths[0])

    if not any(key in safe for key in ("args", "arguments", "input", "parameters")):
        arguments = _action_arguments_from_raw_payload(envelope)
        if arguments is not None:
            safe["arguments"] = arguments
            safe["args"] = arguments


def _string_list_from_envelope(envelope: Mapping[str, object], keys: Sequence[str]) -> list[str]:
    for key in keys:
        value = envelope.get(key)
        if isinstance(value, str) and value.strip():
            return [_bounded_text(value.strip())]
        if isinstance(value, Sequence) and not isinstance(value, str):
            items = [_bounded_text(item.strip()) for item in value if isinstance(item, str) and item.strip()]
            if items:
                return items
    return []


def _action_arguments_from_raw_payload(envelope: Mapping[str, object]) -> object | None:
    raw_payload = envelope.get("raw_payload_redacted")
    if not isinstance(raw_payload, Mapping):
        return None
    for key in ("tool_input", "toolInput", "args", "arguments", "input", "parameters"):
        if key in raw_payload:
            return _bounded_cloud_value(raw_payload[key])
    return None


def _bounded_text(value: str, *, max_chars: int = LOCAL_REQUEST_TEXT_FIELD_MAX_CHARS) -> str:
    if len(value) <= max_chars:
        return value
    return f"{value[:max_chars]}...[truncated {len(value) - max_chars} chars]"


def _bounded_command(value: str) -> str:
    return _bounded_text(value, max_chars=LOCAL_REQUEST_COMMAND_FIELD_MAX_CHARS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
