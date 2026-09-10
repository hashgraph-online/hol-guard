"""Bounded local display text, separate from command analytics and its journal."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from typing import cast

from .redaction import redact_sensitive_text, redact_text
from .runtime.command_tokens import shell_tokens

MAX_PREVIEW_LENGTH = 2048

_SENSITIVE_ARGUMENT_RE = re.compile(
    r"""
    (?P<prefix>
        (?:^|\s)
        --?
        [\w-]*(?:api[-_]?key|token|secret|password|credential|authorization|cookie)[\w-]*
        (?:\s*=\s*|\s+)
    )
    (?P<value>
        "(?:\\.|[^"\\])*"
        |'(?:\\.|[^'\\])*'
        |[^\s]+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def action_preview(payload: Mapping[str, object]) -> str | None:
    inputs = payload.get("tool_input", payload.get("toolInput", payload))
    if not isinstance(inputs, Mapping):
        return None
    command = cast(Mapping[str, object], inputs).get("command")
    if not isinstance(command, str):
        return None
    # Do not truncate before redaction: that could cut off a secret's terminator.
    if len(command) > 65536:
        return None
    _tokens, parse_succeeded = shell_tokens(command)
    if not parse_succeeded:
        return None

    redacted_command = _SENSITIVE_ARGUMENT_RE.sub(
        lambda match: f"{match.group('prefix')}[redacted]",
        command,
    )
    return redact_sensitive_text(redact_text(redacted_command).text)[:MAX_PREVIEW_LENGTH].strip() or None


def ensure_local_action_preview_schema(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        """create table if not exists local_action_previews (
        activity_id text primary key references command_activity(activity_id) on delete cascade,
        preview text not null check(length(preview) <= 2048)
        )"""
    )
    _ = connection.execute(
        """create trigger if not exists trg_command_activity_delete_local_action_previews
        after delete on command_activity
        begin
          delete from local_action_previews where activity_id = old.activity_id;
        end"""
    )
    _ = connection.execute(
        """delete from local_action_previews
        where not exists (
          select 1 from command_activity where activity_id = local_action_previews.activity_id
        )"""
    )
