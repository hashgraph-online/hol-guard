"""Linear-time command/URL matching with the legacy skill finding spans."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

_URL = re.compile(r"https?://[^\s`\"']+", re.IGNORECASE)


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
