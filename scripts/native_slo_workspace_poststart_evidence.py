"""Lossless bounded storage for typed poststart observations and native receipts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_workspace_poststart_session import diagnostic_failure

MAX_PACKET_BYTES = 2 * 1024 * 1024
MAX_PACKETS = 4096
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,95}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,512}")
_SENSITIVE = re.compile(r"secret|token|password|private[_-]?key|api[_-]?key", re.IGNORECASE)
_FORBIDDEN_KEYS = frozenset(
    {
        "raw",
        "payload",
        "command",
        "prompt",
        "path",
        "cwd",
        "home",
        "source",
        "content",
        "secret",
        "token",
        "password",
        "output",
        "endpoint",
        "database",
    }
)
_TEXTS = frozenset(
    {
        "owned Python wrapper endpoints including diagnostic overhead",
        "only the complete declared request set, not all daemon traffic",
        "validated SQLite readback time, not transaction commit time",
        "same-host wall-clock observations at wrapper boundaries",
        "caller-side sequential SQL counts and validated getter, not atomic commit time",
        "Actual service state, owned registries and every retained object; not a complete escaped-descendant census.",
        "poststart registration and same-process service replacement on one owned home",
        "bounded Linux poststart workspace observation",
        "ordered checksummed ASCII JSON packets",
        "full installed sampling and paired baselines",
        "lost metadata hints",
        "key rotation",
        "expiry fault",
        "first admission fault",
        "Python process restart",
        "matched platform hardware",
    }
)
_STOP_FIELDS = frozenset(
    {
        "acknowledged",
        "authenticated",
        "generation_present",
        "owner_lock",
        "marker_lock",
        "endpoint",
        "serving_shutdown",
    }
)
_STOP_VALUES = frozenset({"true", "false", "free", "busy", "unverified", "absent", "present", "verified", "unknown"})


def _stop_diagnostic(value: dict[str, Any]) -> None:
    required = {"schema", "operation", "status"} | _STOP_FIELDS
    if set(value) not in (required, required | {"error"}):
        raise ValueError("poststart native stop diagnostic fields invalid")
    if value["operation"] != "resident-stop" or value["status"] not in {
        "contained",
        "already-stopped",
        "failed",
        "contained_client_cleanup_failed",
    }:
        raise ValueError("poststart native stop diagnostic status invalid")
    if any(value[field] not in _STOP_VALUES for field in _STOP_FIELDS):
        raise ValueError("poststart native stop diagnostic evidence invalid")
    if "error" in value and (
        not isinstance(value["error"], str)
        or re.fullmatch(r"native_resident_stop_[a-z0-9_]{1,128}", value["error"]) is None
    ):
        raise ValueError("poststart native stop diagnostic error invalid")


def _validate(value: Any, depth: int, remaining: list[int]) -> None:
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 24:
        raise ValueError("poststart retained structure outside bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value.bit_length() > 256:
            raise ValueError("poststart retained integer outside bound")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("poststart retained clock is not finite")
        return
    if type(value) is str:
        if value not in _TEXTS and (_IDENTIFIER.fullmatch(value) is None or _SENSITIVE.search(value)):
            raise ValueError("poststart retained text is not a declared identifier")
        return
    if type(value) is dict:
        if len(value) > 256:
            raise ValueError("poststart retained mapping outside bound")
        if value.get("schema") == "guard-native-hook-decision-receipt.v1":
            if validate_native_decision_receipt(value) != value:
                raise ValueError("poststart complete receipt identity invalid")
            return
        if value.get("schema") == "hol-guard.native-resident-stop-diagnostic.v1":
            _stop_diagnostic(value)
            return
        for key, child in value.items():
            if type(key) is not str or _KEY.fullmatch(key) is None or key in _FORBIDDEN_KEYS:
                raise ValueError("poststart retained field is not admitted")
            _validate(child, depth + 1, remaining)
        return
    if type(value) in (list, tuple):
        if len(value) > 512:
            raise ValueError("poststart retained sequence outside bound")
        for child in value:
            _validate(child, depth + 1, remaining)
        return
    raise ValueError("poststart retained object has an unsupported type")


def encode_retained(value: Any) -> bytes:
    """Preserve each admitted field and value; never redact or truncate a record."""

    _validate(value, 0, [131072])
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if not 0 < len(raw) <= MAX_PACKET_BYTES:
        raise ValueError("poststart retained packet exceeded its fixed bound")
    return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("poststart retained JSON has duplicate fields")
        result[key] = value
    return result


def _parse(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_object)


class RetainedLedger:
    """Preserve full objects through the unchanged 8 KiB underlying row limit."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.original = PrivateLedger(path)
        identity = os.fstat(self.original._stream.fileno())
        self.identity = (identity.st_dev, identity.st_ino)
        self.expected: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.finished = False

    def write(self, value: dict[str, Any]) -> bool:
        if self.finished:
            raise RuntimeError("poststart ledger is already finished")
        if self.errors:
            return False
        try:
            raw = encode_retained(value)
            if len(self.expected) >= MAX_PACKETS:
                raise ValueError("poststart retained packet count exceeded its fixed bound")
            kind = value["kind"]
            if not isinstance(kind, str) or re.fullmatch(r"poststart_[a-z_]{1,64}", kind) is None:
                raise ValueError("poststart retained packet kind invalid")
            chunks = [raw[offset : offset + 2048].decode("ascii") for offset in range(0, len(raw), 2048)]
            record = {
                "schema": "poststart.workspace.packet.v1",
                "packet": len(self.expected) + 1,
                "packet_kind": kind,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "parts": len(chunks),
            }
            self.expected.append(record)
            self.original.write({"kind": "packet_begin", **record})
            for index, chunk in enumerate(chunks, 1):
                self.original.write({"kind": "packet_part", **record, "part": index, "payload": chunk})
            self.original.write({"kind": "packet_end", **record})
            return True
        except BaseException as error:
            self.errors.append({"stage": "write", "type": type(error).__name__, "failure": diagnostic_failure(error)})
            raise

    def _readback(self, original: dict[str, Any]) -> dict[str, int]:
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        records = size = packet = 0
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            identity = os.fstat(stream.fileno())
            if (identity.st_dev, identity.st_ino) != self.identity or identity.st_size != original["bytes"]:
                raise ValueError("poststart retained file identity changed")

            def row() -> dict[str, Any] | None:
                nonlocal records, size
                raw = stream.readline(8193)
                if not raw:
                    return None
                if not raw.endswith(b"\n") or len(raw) > 8192 or records >= 350000:
                    raise ValueError("poststart retained row incomplete or oversized")
                records += 1
                size += len(raw)
                if size > 256 * 1024 * 1024:
                    raise ValueError("poststart retained file outside bound")
                digest.update(raw)
                value = _parse(raw)
                if not isinstance(value, dict):
                    raise ValueError("poststart retained row is not a mapping")
                return value

            for expected in self.expected:
                if row() != {"kind": "packet_begin", **expected}:
                    raise ValueError("poststart retained packet begin differs")
                chunks = []
                for index in range(1, expected["parts"] + 1):
                    part = row()
                    if part is None or type(part.get("payload")) is not str:
                        raise ValueError("poststart retained packet part is absent")
                    chunk = part.pop("payload")
                    if part != {"kind": "packet_part", **expected, "part": index} or not 0 < len(chunk) <= 2048:
                        raise ValueError("poststart retained packet part differs")
                    chunks.append(chunk)
                if row() != {"kind": "packet_end", **expected}:
                    raise ValueError("poststart retained packet end differs")
                raw = "".join(chunks).encode("ascii")
                value = _parse(raw)
                if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                    raise ValueError("poststart retained full packet differs")
                if encode_retained(value) != raw or value["kind"] != expected["packet_kind"]:
                    raise ValueError("poststart retained full object differs")
                packet += 1
            if row() is not None:
                raise ValueError("poststart retained ledger has undeclared rows")
        if records != original["records"] or size != original["bytes"] or digest.hexdigest() != original["sha256"]:
            raise ValueError("poststart retained ledger digest differs")
        return {"packets": packet, "records": records, "bytes": size}

    def finish(self) -> dict[str, Any]:
        if self.finished:
            raise RuntimeError("poststart ledger finish repeated")
        self.finished = True
        result: dict[str, Any] = {
            "complete": False,
            "packets": len(self.expected),
            "errors": self.errors,
            "complete_object_encoding": "ordered checksummed ASCII JSON packets",
            "underlying_record_limit_bytes": 8192,
        }
        try:
            original = self.original.finish()
            result.update(original)
            result["readback"] = self._readback(original)
            result["complete"] = not self.errors
        except BaseException as error:
            self.errors.append(
                {
                    "stage": "finish_or_readback",
                    "type": type(error).__name__,
                    "failure": diagnostic_failure(error),
                }
            )
        return result
