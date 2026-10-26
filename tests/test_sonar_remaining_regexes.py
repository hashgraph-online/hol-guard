"""Span equivalence and adversarial coverage for the remaining Sonar regex findings."""

from __future__ import annotations

import itertools
import re

import pytest

from codex_plugin_scanner.checks.skill_security import _RISKY_SKILL_PATTERNS
from codex_plugin_scanner.guard.inventory_contract import _MCP_SECRET_RE


@pytest.mark.parametrize("index,command", [(1, "curl"), (2, "wget")])
def test_command_url_matcher_bounds_repeated_prefixes(index: int, command: str) -> None:
    pattern = _RISKY_SKILL_PATTERNS[index][0]
    repeated = (command + " ") * 16384
    whitespace = command + (" \t\r\n" * 16384)
    for prefix in (repeated, whitespace):
        assert pattern.search(prefix) is None
        sample = prefix + "https://example.test/payload"
        match = pattern.search(sample)
        assert match is not None
        assert match.span() == (0, len(sample))
        assert match.group(0) == sample
        with pytest.raises(IndexError):
            match.group(1)
    sample = repeated + "\nno command https://example.test"
    match = pattern.search(sample)
    assert match is not None
    assert match.span()[0] == len(repeated) - len(command) - 1


@pytest.mark.parametrize("index,command", [(1, "curl"), (2, "wget")])
def test_command_url_matcher_preserves_multiline_and_unicode_spans(index: int, command: str) -> None:
    pattern = _RISKY_SKILL_PATTERNS[index][0]
    reference = re.compile(re.escape(command) + r"\s+.*?https?://[^\s`\"']+", re.IGNORECASE)
    separators = (" ", "\n", " \n\n ", "\t\r", "\u2003", "\x85", "\x1f")
    bodies = ("", "quote ", "https://` ", 'https://" ', "http:// ", "line\n", "https://x ")
    for whitespace, body in itertools.product(separators, bodies):
        sample = f"https://before.test/{command} {command}{whitespace}{body}https://after.test/{command}\n"
        sample += f"{command} https://second.test"
        assert [m.span() for m in pattern.finditer(sample)] == [m.span() for m in reference.finditer(sample)]


@pytest.mark.parametrize(
    "current,reference,words",
    [
        (
            _MCP_SECRET_RE,
            r"(?<![a-z0-9])(secret|secrets|token|tokens|password|passwords|credential|credentials|api[_\-\s]?key|apiKey)(?![a-z0-9])",
            (
                "secret",
                "secrets",
                "token",
                "tokens",
                "password",
                "passwords",
                "credential",
                "credentials",
                "api_key",
                "api-key",
                "apiKey",
                "api key",
                "api\nkey",
            ),
        ),
    ],
)
def test_retained_service_regex_alternatives_keep_match_spans_and_groups(
    current, reference: str, words: tuple[str, ...]
) -> None:
    original = re.compile(reference, re.IGNORECASE)
    for word, left, right in itertools.product(words, ("", "a", "0", "_", " ", "-"), ("", "s", "a", "0", "_", ".")):
        for value in (word, word.upper(), word.swapcase()):
            sample = f"{left}{value}{right} {value}"
            assert [(m.span(), m.groups()) for m in current.finditer(sample)] == [
                (m.span(), m.groups()) for m in original.finditer(sample)
            ]
