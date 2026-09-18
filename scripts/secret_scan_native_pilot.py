"""Explicit benchmark-only bridge to a bounded ASCII regex extraction child.

No production entrypoint imports this module. Python still owns all finding
classification, suppression, entropy, positions, limits, ordering and HMACs.
Unsupported text uses the original Python patterns; native/protocol failures
abort qualification instead of silently producing an incomplete clean scan.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any

_SCHEMA = "guard-offline-regex-pilot.v1"
_MAX_FRAME = 64 * 1024 * 1024
_MAX_TEXT = 4 * 1024 * 1024
_MAX_MATCHES = 100_000
_PYTHON_ASSIGNMENT = (
    r"(?im)(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*"
    r"(?P<quote>[\"']?)(?P<secret>[^\s\"',}{]{12,256})(?P=quote)"
)
# Python's ASCII whitespace includes the four information separators as well
# as HT..CR and space. Preserve it explicitly instead of Rust's Unicode \s.
_SPACE = r"\x09-\x0d\x1c-\x20"
_SECRET = rf"[^{_SPACE}\"',}}{{]{{12,256}}"
_ASSIGNMENT = (
    rf"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{{1,80}})[{_SPACE}]*[:=][{_SPACE}]*"
    rf"(?:"
    rf'(?P<quote_double>")(?P<secret_double>{_SECRET})"|'
    rf"(?P<quote_single>')(?P<secret_single>{_SECRET})'|"
    rf"(?P<secret_plain>{_SECRET}))"
)


class PilotError(RuntimeError):
    """Fixed-message qualification failure that never includes candidate data."""


def _translate_provider_pattern(pattern: str) -> str:
    parts = []
    inside_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            escaped = pattern[index + 1]
            if escaped == "s":
                if not inside_class:
                    raise PilotError("pilot whitespace translation requires requalification")
                parts.append(_SPACE)
            else:
                parts.append(pattern[index : index + 2])
            index += 2
            continue
        if character == "[":
            inside_class = True
        elif character == "]":
            inside_class = False
        parts.append(character)
        index += 1
    return "".join(parts)


def _catalog(detector: Any) -> tuple[str, list[dict[str, object]]]:
    if (
        detector._ASSIGNMENT.pattern != _PYTHON_ASSIGNMENT
        or detector._ASSIGNMENT.flags != re.UNICODE | re.IGNORECASE | re.MULTILINE
    ):
        raise PilotError("pilot assignment translation requires requalification")
    patterns = [
        {
            "id": rule.rule_id,
            "pattern": _translate_provider_pattern(rule.pattern.pattern),
            "ignore_case": bool(rule.pattern.flags & re.IGNORECASE),
            "multiline": bool(rule.pattern.flags & re.MULTILINE),
            "assignment": False,
        }
        for rule in detector.SECRET_RULES
    ]
    patterns.append(
        {
            "id": "credential-assignment",
            "pattern": _ASSIGNMENT,
            "ignore_case": True,
            "multiline": True,
            "assignment": True,
        }
    )
    for rule in detector.SECRET_RULES:
        if rule.pattern.flags & ~(re.UNICODE | re.IGNORECASE | re.MULTILINE):
            raise PilotError("pilot pattern flags require requalification")
    digest = hashlib.sha256(json.dumps(patterns, sort_keys=True).encode()).hexdigest()
    return digest, patterns


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise PilotError("pilot response contains duplicate fields")
        result[name] = value
    return result


class PilotClient:
    def __init__(self, binary: Path, detector: Any, *, timeout: float = 30.0):
        self.binary = binary.resolve()
        self.timeout = timeout
        self.catalog, self.patterns = _catalog(detector)
        self.process: subprocess.Popen[bytes] | None = None
        self.sequence = 0
        self.stats = {
            "native_files": 0,
            "python_fallback_files": 0,
            "requests": 0,
            "input_bytes": 0,
            "response_bytes": 0,
        }

    def _exchange(self, payload: dict[str, object]) -> dict[str, Any]:
        assert self.process is not None and self.process.stdin is not None and self.process.stdout is not None
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > _MAX_FRAME:
            raise PilotError("pilot request frame budget exceeded")
        sent = 0
        output = bytearray()
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PilotError("pilot request deadline exceeded")
                events = selector.select(remaining)
                if not events:
                    raise PilotError("pilot request deadline exceeded")
                for key, event in events:
                    if event & selectors.EVENT_WRITE:
                        try:
                            sent += os.write(key.fd, encoded[sent : sent + 65536])
                        except BlockingIOError:
                            continue
                        except OSError as error:
                            raise PilotError("pilot request pipe failed") from error
                        if sent == len(encoded):
                            selector.unregister(self.process.stdin)
                    if event & selectors.EVENT_READ:
                        try:
                            chunk = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        except OSError as error:
                            raise PilotError("pilot response pipe failed") from error
                        if not chunk:
                            raise PilotError("pilot response ended before a complete frame")
                        output.extend(chunk)
                        if len(output) > _MAX_FRAME:
                            raise PilotError("pilot response frame budget exceeded")
                        if b"\n" in chunk:
                            if sent != len(encoded) or output[-1:] != b"\n" or b"\n" in output[:-1]:
                                raise PilotError("pilot response framing failed")
                            self.stats["requests"] += 1
                            self.stats["input_bytes"] += len(encoded)
                            self.stats["response_bytes"] += len(output)
                            try:
                                result = json.loads(output, object_pairs_hook=_unique_object)
                            except (ValueError, UnicodeError) as error:
                                raise PilotError("pilot response JSON failed") from error
                            if not isinstance(result, dict):
                                raise PilotError("pilot response was not an object")
                            return result

    def _start(self) -> None:
        if self.process is not None:
            return
        self.process = subprocess.Popen(
            [str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        result = self._exchange({"schema": _SCHEMA, "catalog": self.catalog, "patterns": self.patterns})
        if result != {"schema": _SCHEMA, "catalog": self.catalog, "ready": True} or result.get("ready") is not True:
            raise PilotError("pilot initialization identity failed")

    def extract(self, text: str) -> dict[str, list[dict[str, list[int]]]]:
        try:
            self._start()
            self.sequence += 1
            result = self._exchange({"schema": _SCHEMA, "id": self.sequence, "text": text})
            if (
                set(result) != {"schema", "catalog", "id", "complete", "rules"}
                or result["schema"] != _SCHEMA
                or result["catalog"] != self.catalog
                or type(result["id"]) is not int
                or result["id"] != self.sequence
                or result["complete"] is not True
                or not isinstance(result["rules"], list)
                or len(result["rules"]) != len(self.patterns)
            ):
                raise PilotError("pilot response identity or completeness failed")
            matches = {}
            total = 0
            for spec, row in zip(self.patterns, result["rules"], strict=True):
                if not isinstance(row, dict) or set(row) != {"id", "captures"} or row["id"] != spec["id"]:
                    raise PilotError("pilot response rule order failed")
                captures = row["captures"]
                if not isinstance(captures, list):
                    raise PilotError("pilot captures were not a list")
                total += len(captures)
                if total > _MAX_MATCHES:
                    raise PilotError("pilot response candidate budget exceeded")
                previous_end = 0
                for capture in captures:
                    required = {"whole", "secret", "name", "quote"} if spec["assignment"] else {"whole", "secret"}
                    if not isinstance(capture, dict) or set(capture) != required:
                        raise PilotError("pilot capture fields failed")
                    for span in capture.values():
                        if (
                            not isinstance(span, list)
                            or len(span) != 2
                            or any(type(value) is not int for value in span)
                            or not 0 <= span[0] <= span[1] <= len(text)
                        ):
                            raise PilotError("pilot capture span failed")
                    whole = capture["whole"]
                    if whole[0] < previous_end or whole[0] == whole[1]:
                        raise PilotError("pilot capture ordering failed")
                    previous_end = whole[1]
                    if any(not whole[0] <= span[0] <= span[1] <= whole[1] for span in capture.values()):
                        raise PilotError("pilot capture containment failed")
                matches[row["id"]] = captures
            self.stats["native_files"] += 1
            return matches
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


class SpanMatch:
    def __init__(self, text: str, spans: dict[str, list[int]]):
        self.text, self.spans = text, spans

    def group(self, name: str | int = 0) -> str:
        start, end = self.spans["whole" if name == 0 else name]
        return self.text[start:end]

    def groupdict(self) -> dict[str, str]:
        return {name: self.group(name) for name in self.spans if name != "whole"}

    def start(self, name: str | int = 0) -> int:
        return self.spans["whole" if name == 0 else name][0]

    def span(self, name: str | int = 0) -> tuple[int, int]:
        return tuple(self.spans["whole" if name == 0 else name])


class InstalledPilot:
    """One benchmark process; explicit restoration and child reaping on exit."""

    def __init__(self, binary: Path):
        from codex_plugin_scanner.guard.secrets import secret_detection as detector
        from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository

        self.repository = repository
        self.original_repository_scan = repository.scan_secret_text
        self.detector = detector
        self.original_scan = detector.scan_secret_text
        self.original_rules = detector.SECRET_RULES
        self.original_assignment = detector._ASSIGNMENT
        self.client = PilotClient(binary, detector)
        self.matches: dict[str, list[dict[str, list[int]]]] | None = None
        self.supported = False
        owner = self

        class Pattern:
            def __init__(self, name, original):
                self.name, self.original = name, original
                self.pattern, self.flags = original.pattern, original.flags

            def finditer(self, text):
                if not owner.supported:
                    return self.original.finditer(text)
                if owner.matches is None:
                    owner.matches = owner.client.extract(text)
                return (SpanMatch(text, spans) for spans in owner.matches[self.name])

        def scan(text, **kwargs):
            self.matches = None
            self.supported = isinstance(text, str) and text.isascii() and len(text) <= _MAX_TEXT
            if text and not self.supported:
                self.client.stats["python_fallback_files"] += 1
            try:
                return self.original_scan(text, **kwargs)
            finally:
                self.matches = None
                self.supported = False

        detector.SECRET_RULES = tuple(
            dataclasses.replace(rule, pattern=Pattern(rule.rule_id, rule.pattern)) for rule in self.original_rules
        )
        detector._ASSIGNMENT = Pattern("credential-assignment", self.original_assignment)
        detector.scan_secret_text = scan
        repository.scan_secret_text = scan

    def close(self) -> None:
        self.client.close()
        self.detector.scan_secret_text = self.original_scan
        self.detector.SECRET_RULES = self.original_rules
        self.detector._ASSIGNMENT = self.original_assignment
        self.repository.scan_secret_text = self.original_repository_scan


def install(binary: Path) -> InstalledPilot:
    return InstalledPilot(binary)


def cli_main(binary: Path) -> int:
    """Run the actual source CLI with explicit experimental extraction enabled."""
    import sys

    from codex_plugin_scanner.cli import main

    installed = install(binary)
    try:
        return main()
    finally:
        installed.close()
        print("GUARD_REGEX_PILOT_STATS=" + json.dumps(installed.client.stats, sort_keys=True), file=sys.stderr)
