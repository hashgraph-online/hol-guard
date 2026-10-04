"""Bounded retrieval syntax recognition; no URLs or instructions are executed."""

from __future__ import annotations

import re
import shlex
from ipaddress import IPv6Address
from urllib.parse import urlsplit

_READ_ONLY_CURL_FLAGS = {
    "--silent",
    "--show-error",
    "--fail",
    "--location",
    "--head",
    "--compressed",
    "--no-progress-meter",
}
_FENCE = re.compile(r"^[ \t]*(?P<fence>`{3,}|~{3,})(?P<info>[^\r\n]*)[\r\n]*$")


def read_only_curl_spans(content: str) -> tuple[tuple[int, int], ...]:
    """Index complete, bounded shell fences containing only literal retrievals.

    A whole block must qualify. Process substitution and downloads followed by
    execution cannot be exempted merely because one line looks like a GET.
    """
    if any(char in content for char in "\v\f\x85\u2028\u2029"):
        return ()
    spans = []
    fence = ""
    body_start = 0
    offset = 0
    safe = False
    saw_command = False
    for line in content.splitlines(keepends=True):
        boundary = _FENCE.fullmatch(line)
        if not fence:
            if boundary:
                fence = boundary.group("fence")
                safe = boundary.group("info").strip() in {"", "bash", "sh", "shell"}
                body_start = offset + len(line)
                saw_command = False
        elif (
            boundary
            and boundary.group("fence")[0] == fence[0]
            and len(boundary.group("fence")) >= len(fence)
            and not boundary.group("info").strip()
        ):
            if safe and saw_command and offset - body_start <= 65536:
                spans.append((body_start, offset))
            fence = ""
        elif line.lstrip().startswith("#"):
            safe = safe and not line.rstrip("\r\n").endswith("\\")
        elif line.strip():
            safe = safe and is_read_only_curl(line, 0)
            saw_command = True
        offset += len(line)
    return tuple(spans)


def is_read_only_curl(content: str, start: int) -> bool:
    """Recognize one literal retrieval, not permission to execute the command.

    The caller joins shell continuations first. Unknown options, shell
    composition, authentication and arbitrary query semantics retain findings.
    """
    line_start = content.rfind("\n", 0, start) + 1
    if content[line_start:start].strip():
        return False
    end = content.find("\n", start)
    command = content[start : end if end != -1 else len(content)]
    if end != -1 and command.endswith("\r"):
        command = command[:-1]
    if len(command) > 16384 or any(char in command for char in "$`|;&<>(){}"):
        return False
    if any((ord(char) < 32 and char != "\t") or ord(char) >= 127 for char in command):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens or tokens[0] != "curl":
        return False
    saw_url = False
    args = iter(tokens[1:])
    for token in args:
        if token in _READ_ONLY_CURL_FLAGS or re.fullmatch(r"-[fsSLI]+", token):
            continue
        if token in {"-X", "--request"}:
            if next(args, None) not in {"GET", "HEAD"}:
                return False
            continue
        if token == "--url":
            token = next(args, "")
        if saw_url or not _literal_retrieval_url(token):
            return False
        saw_url = True
    return saw_url


def _literal_retrieval_url(token: str) -> bool:
    """Validate URL syntax explicitly across supported Python parser versions."""
    if len(token) > 4096 or not token.startswith(("https://", "http://")):
        return False
    if any(ord(char) <= 32 or ord(char) >= 127 or char == "\\" for char in token):
        return False
    try:
        parsed = urlsplit(token)
        if not parsed.hostname or "@" in parsed.netloc:
            return False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        if any(char in part for part in (parsed.path, parsed.query, parsed.fragment) for char in "[]{}"):
            return False
        if "[" in parsed.netloc or "]" in parsed.netloc:
            authority = re.fullmatch(r"\[([^\[\]]+)\](?::[0-9]+)?", parsed.netloc)
            if authority is None:
                return False
            address, separator, zone = authority.group(1).partition("%")
            if separator and re.fullmatch(r"(?:25)?[A-Za-z0-9_.-]{1,32}", zone) is None:
                return False
            IPv6Address(address)
        elif re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", parsed.netloc) is None:
            return False
    except ValueError:
        return False
    # One bounded pagination/representation field, not an arbitrary value.
    # Encoded names, duplicates and additional query parameters stay flagged.
    if parsed.query:
        key, separator, value = parsed.query.partition("=")
        if not separator:
            return False
        if key in {"page", "limit", "per_page", "offset"}:
            return re.fullmatch(r"[0-9]{1,4}", value) is not None
        if key == "format":
            return value in {"json", "xml", "text", "csv", "yaml"}
        return False
    return True
