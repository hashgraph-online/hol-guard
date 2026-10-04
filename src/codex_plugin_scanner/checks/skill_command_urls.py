"""Linear-time command/URL matching with the legacy skill finding spans."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv6Address
from urllib.parse import urlsplit

_URL = re.compile(r"https?://[^\s`\"']+", re.IGNORECASE)
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
    """Index complete shell fences containing only simple read-only curl commands.

    A command's enclosing block must qualify as a whole: a standalone-looking
    line inside process substitution, or a download followed by execution, is
    not a read-only instruction. Unfenced or mixed-language text stays flagged.
    """
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
            if safe and saw_command:
                spans.append((body_start, offset))
            fence = ""
        elif line.lstrip().startswith("#"):
            # Keep ambiguous comment/continuation combinations out of exemptions.
            safe = safe and not line.rstrip("\r\n").endswith("\\")
        elif line.strip():
            safe = safe and is_read_only_curl(line, 0)
            saw_command = True
        offset += len(line)
    return tuple(spans)


def is_read_only_curl(content: str, start: int) -> bool:
    """Exempt only a simple literal GET/HEAD command with understood arguments.

    The caller joins shell continuations first. Unknown options, authentication,
    payloads, substitutions and shell composition remain findings for review.
    """
    line_start = content.rfind("\n", 0, start) + 1
    if content[line_start:start].strip():
        return False
    end = content.find("\n", start)
    command = content[start : end if end != -1 else len(content)]
    if any(character in command for character in "$`|;&<>(){}"):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens or tokens[0].lower() != "curl":
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
        if not token.lower().startswith(("https://", "http://")):
            return False
        try:
            parsed = urlsplit(token)
            if not parsed.hostname or parsed.username or parsed.password:
                return False
            if any(character in part for part in (parsed.path, parsed.query, parsed.fragment) for character in "[]"):
                return False
            if "[" in parsed.netloc or "]" in parsed.netloc:
                authority = re.fullmatch(r"\[([^\[\]]+)\](?::[0-9]*)?", parsed.netloc)
                if authority is None:
                    return False
                # Older supported urllib parsers do not validate bracketed hosts.
                _ = IPv6Address(authority.group(1))
        except ValueError:
            return False
        saw_url = True
    return saw_url


@dataclass(frozen=True, slots=True)
class CommandUrlMatch:
    text: str
    begin: int
    end: int

    def span(self) -> tuple[int, int]:
        return self.begin, self.end

    def group(self, index: int = 0) -> str:
        if index != 0:
            raise IndexError("no such group")
        return self.text[self.begin : self.end]


@dataclass(frozen=True, slots=True)
class CommandUrlPattern:
    prefix: re.Pattern[str]

    def finditer(self, text: str) -> Iterator[CommandUrlMatch]:
        """Match prefix, optional same-line text, then the first valid URL.

        Prefix whitespace remains greedy and may include newlines, just like
        the original ``command\\s+.*?https?://...`` expression. URL and newline
        searches only advance, so repeated commands without URLs cannot cause
        repeated scans of the remaining line.
        """
        urls = iter(_URL.finditer(text))
        url = next(urls, None)
        resume = 0
        line_end = -1
        for prefix in self.prefix.finditer(text):
            if prefix.start() < resume:
                continue
            while url is not None and url.start() < prefix.end():
                url = next(urls, None)
            if url is None:
                return
            if line_end < prefix.end():
                line_end = text.find("\n", prefix.end())
                if line_end == -1:
                    line_end = len(text)
            if url.start() >= line_end:
                continue
            resume = url.end()
            yield CommandUrlMatch(text, prefix.start(), resume)

    def search(self, text: str) -> CommandUrlMatch | None:
        return next(self.finditer(text), None)
