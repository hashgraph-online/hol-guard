"""Bounded local display text, separate from command analytics and its journal."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from typing import cast
from urllib.parse import unquote_plus

from .redaction import redact_sensitive_text, redact_text
from .runtime.command_tokens import shell_tokens

MAX_PREVIEW_LENGTH = 2048
_SENSITIVE_NAME_RE = re.compile(r"api_?key|token|secret|password|credential|authorization|cookie", re.IGNORECASE)
_SENSITIVE_QUERY_NAME_RE = re.compile(
    r"api[-_]?key|token|secret|password|credential|authorization|cookie|signature|^(?:key|sig|auth)$",
    re.IGNORECASE,
)

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
    inputs = payload.get("tool_input", payload.get("toolInput", payload.get("arguments")))
    command: str | None = None
    if isinstance(inputs, Mapping):
        arguments = cast(Mapping[str, object], inputs)
        command = next(
            (
                value
                for key in ("command", "cmd", "shell_command", "shellCommand")
                if isinstance(value := arguments.get(key), str) and value.strip()
            ),
            None,
        )
    if command is None:
        command = next(
            (value for key in ("command", "cmd") if isinstance(value := payload.get(key), str) and value.strip()), None
        )
    if command is None:
        return None
    # Do not truncate before redaction: that could cut off a secret's terminator.
    if len(command) > 65536:
        return None
    tokens, parse_succeeded = shell_tokens(command)
    if not parse_succeeded:
        return None

    # Shell parsing catches assignments after `env` and quoted assignment values.
    # If escaping prevents safe replacement, omit the preview rather than leak.
    for token in tokens:
        name, separator, value = token.partition("=")
        if separator and value and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and _SENSITIVE_NAME_RE.search(name):
            if value not in command:
                return None
            command = command.replace(value, "[redacted]")

    for index, token in enumerate(tokens):
        credential = None
        if token in {"-u", "-U", "--user", "--proxy-user"} and index + 1 < len(tokens):
            credential = tokens[index + 1]
        elif token.startswith(("--user=", "--proxy-user=")):
            credential = token.partition("=")[2]
        elif token.startswith(("-u", "-U")) and len(token) > 2 and not token.startswith("--"):
            credential = token[2:]
        elif token.lower().startswith(("authorization:", "proxy-authorization:")):
            credential = token.partition(":")[2].strip()
        if credential:
            if credential not in command:
                return None
            command = command.replace(credential, "[redacted]")

    command = re.sub(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@'\"]+@", r"\1[redacted]@", command)
    command = re.sub(
        r"([?&#])([^=&#\s\"']+)=([^&#\s\"']*)",
        lambda match: f"{match[1]}{match[2]}=[redacted]"
        if _SENSITIVE_QUERY_NAME_RE.search(unquote_plus(match[2]))
        else match[0],
        command,
    )

    redacted_command = _SENSITIVE_ARGUMENT_RE.sub(
        lambda match: f"{match.group('prefix')}[redacted]",
        command,
    )
    preview = redact_sensitive_text(redact_text(redacted_command).text)
    # The dashboard measures string bounds in UTF-16 code units.
    return (
        preview.encode("utf-16-le", errors="replace")[: MAX_PREVIEW_LENGTH * 2]
        .decode("utf-16-le", errors="ignore")
        .strip()
        or None
    )


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
