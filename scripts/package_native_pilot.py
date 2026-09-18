"""Explicit Linux-only measurement adapter for the bounded Rust npm pilot.

This module is never imported by the installed product. The benchmark explicitly
installs it at the existing whole-lockfile seam. Python retains source identity,
the original absolute budget, immutable public results, and every trust decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.runtime import lockfile_evaluation_support as seam
from codex_plugin_scanner.guard.runtime import lockfile_parse_result as contract
from codex_plugin_scanner.guard.runtime.package_manifest_diff import _dependency_map_for_path
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _package_lock_entries
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024 * 1024
MIN_PILOT_BYTES = 256 * 1024


class PilotFallbackError(Exception):
    """A finite native-boundary failure that must return to the Python parser."""


def _exchange(binary: Path, payload: bytes, *, deadline: float) -> bytes:
    """Bound both pipe directions and reap the child before returning any result."""

    if len(payload) > MAX_ENVELOPE_BYTES:
        raise PilotFallbackError("request_byte_limit")
    if time.monotonic() >= deadline:
        raise PilotFallbackError("deadline_exceeded")
    child = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert child.stdin is not None and child.stdout is not None
    output = bytearray()
    written = 0
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(child.stdin.fileno(), False)
            os.set_blocking(child.stdout.fileno(), False)
            selector.register(child.stdin, selectors.EVENT_WRITE)
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PilotFallbackError("deadline_exceeded")
                for key, _events in selector.select(remaining):
                    if key.fileobj is child.stdin:
                        try:
                            count = os.write(child.stdin.fileno(), payload[written : written + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as exc:
                            raise PilotFallbackError("closed_input") from exc
                        written += count
                        if written == len(payload):
                            selector.unregister(child.stdin)
                            child.stdin.close()
                    else:
                        try:
                            block = os.read(child.stdout.fileno(), min(65536, MAX_RESPONSE_BYTES + 1 - len(output)))
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(child.stdout)
                            child.stdout.close()
                        else:
                            output.extend(block)
                            if len(output) > MAX_RESPONSE_BYTES:
                                raise PilotFallbackError("response_byte_limit")
        try:
            code = child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise PilotFallbackError("deadline_exceeded") from exc
        if code:
            raise PilotFallbackError("native_exit")
        if time.monotonic() > deadline:
            raise PilotFallbackError("deadline_exceeded")
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PilotFallbackError("duplicate_response_key")
        result[key] = value
    return result


def _entries(response: bytes, request_id: str, *, max_entries: int):
    payload = json.loads(response, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "request_id", "status", "reason", "entries"}:
        raise PilotFallbackError("response_schema")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["request_id"] != request_id
    ):
        raise PilotFallbackError("response_identity")
    if payload["status"] == "fallback":
        reason = payload["reason"]
        if payload["entries"] != [] or not isinstance(reason, str) or len(reason) > 80:
            raise PilotFallbackError("response_partial_fallback")
        raise PilotFallbackError("native_" + reason)
    if payload["status"] != "complete" or payload["reason"] is not None:
        raise PilotFallbackError("response_status")
    rows = payload["entries"]
    if not isinstance(rows, list) or len(rows) > max_entries:
        raise PilotFallbackError("response_entry_limit")
    entries = []
    seen = set()
    for row in rows:
        if not isinstance(row, list) or len(row) != 4 or not all(isinstance(value, str) for value in row[:3]):
            raise PilotFallbackError("response_entry_type")
        if type(row[3]) is not bool or row[3] != ("node_modules/" not in row[0]) or row[0] in seen:
            raise PilotFallbackError("response_entry_identity")
        seen.add(row[0])
        entries.append(contract.LockfileDependencyEntry(*row))
    return tuple(entries)


class NativePackagePilot:
    """One opt-in benchmark installation, with observable native/fallback counts."""

    def __init__(self, binary: Path, *, min_bytes: int = MIN_PILOT_BYTES):
        self.binary = binary.resolve(strict=True)
        self.binary_sha256 = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.min_bytes = min_bytes
        self.original = seam.parse_lockfile_text
        self.counts: Counter[str] = Counter()

    def install(self):
        seam.parse_lockfile_text = self.parse

    def restore(self):
        seam.parse_lockfile_text = self.original

    def metadata(self):
        current_sha256 = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        if current_sha256 != self.binary_sha256:
            raise AssertionError("The measured native pilot artifact changed during collection")
        return {
            "schema": "guard-package-native-pilot-v1",
            "binary_sha256": self.binary_sha256,
            "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "min_source_bytes": self.min_bytes,
            "max_native_depth": 64,
            "counts": dict(sorted(self.counts.items())),
            "production_default": False,
        }

    def parse(self, path, source_text, *, deadline, budget_ms, dependency_parser, package_lock_parser):
        started = time.monotonic()

        def fallback(reason):
            self.counts["fallback:" + reason] += 1
            result = self.original(
                path,
                source_text,
                deadline=deadline,
                budget_ms=budget_ms,
                dependency_parser=dependency_parser,
                package_lock_parser=package_lock_parser,
            )
            return replace(result, elapsed_ms=(time.monotonic() - started) * 1000)

        if sys.platform != "linux":
            return fallback("platform")
        if path.rsplit("/", 1)[-1].lower() != "package-lock.json":
            return fallback("format")
        if dependency_parser is not _dependency_map_for_path or package_lock_parser is not _package_lock_entries:
            return fallback("custom_parser")
        try:
            source = source_text if isinstance(source_text, bytes) else source_text.encode("utf-8")
            if not self.min_bytes <= len(source) <= contract.LOCKFILE_MAX_BYTES:
                return fallback("source_bytes")
            text = source.decode("utf-8") if isinstance(source_text, bytes) else source_text
            source_hash = stable_digest_hex(source)
            remaining_ms = min(1500, int((deadline - time.monotonic()) * 1000))
            if remaining_ms <= 0:
                return fallback("deadline_exceeded")
            request = {
                "schema_version": 1,
                "request_id": source_hash,
                "source_text": text,
                "limits": {
                    "max_bytes": contract.LOCKFILE_MAX_BYTES,
                    "max_nodes": contract.LOCKFILE_MAX_NODES,
                    "max_entries": contract.LOCKFILE_MAX_ENTRIES,
                    "max_depth": min(64, contract.LOCKFILE_MAX_DEPTH),
                    "remaining_ms": remaining_ms,
                },
            }
            self.counts["native_invocations"] += 1
            response = _exchange(
                self.binary,
                json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                deadline=deadline,
            )
            entries = _entries(response, source_hash, max_entries=contract.LOCKFILE_MAX_ENTRIES)
            manifest = tuple((entry.dependency_path, entry.version) for entry in entries)
            if time.monotonic() > deadline:
                return fallback("deadline_exceeded")
            self.counts["native_complete"] += 1
            return contract.LockfileParseResult(
                entries=entries,
                complete=True,
                format="npm-package-lock",
                source_hash=source_hash,
                elapsed_ms=(time.monotonic() - started) * 1000,
                budget_ms=budget_ms,
                manifest_dependencies=manifest,
            )
        except PilotFallbackError as exc:
            return fallback(str(exc))
        except (OSError, UnicodeError, TypeError, ValueError, MemoryError, RecursionError):
            return fallback("boundary_error")
