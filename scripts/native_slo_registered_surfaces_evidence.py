"""Bounded private per-case evidence, including a strict corpus's first failure."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_EVIDENCE_RECORDS = 4096
MAX_RECORD_BYTES = 1024
_TOKEN = re.compile(r"[A-Za-z0-9_./-]{1,192}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_STAGES = frozenset(
    {"offered", "setup", "registration", "process", "delivery", "readback_after", "route", "witness", "complete"}
)
_ROUTES = frozenset({"native_resident", "native_fail_safe", "legacy_hook_pool", "legacy", "engine_bypassed"})


@dataclass(slots=True)
class SurfaceAttempt:
    stage: str = "setup"
    attempted_exit: int | None = None
    route: str | None = None
    # Private, already bounded process result; the JSONL ledger never copies it.
    delivery_result: BoundedHookProcessResult | None = None
    delivery_validated: bool = False


class SurfaceEvidence:
    """Exclusive 0600 JSONL with space reserved for each offered case's outcome."""

    def __init__(self, path: Path | None) -> None:
        self.stream: BinaryIO | None = None
        self.size = 0
        self.records = 0
        self.pending: tuple[str, str] | None = None
        if path is None:
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.resolve(strict=True)
        parent_info = parent.stat()
        if not stat.S_ISDIR(parent_info.st_mode) or (
            os.name != "nt" and (parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o022)
        ):
            raise RuntimeError("registered_surface_evidence_parent_unsafe")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(parent / path.name, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077):
                raise RuntimeError("registered_surface_evidence_file_unsafe")
            self.stream = os.fdopen(descriptor, "wb")
        except BaseException:
            os.close(descriptor)
            raise

    def __enter__(self) -> SurfaceEvidence:
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if self.stream is not None:
            self.stream.close()

    def _append(self, value: dict[str, object]) -> None:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        if (
            len(raw) > MAX_RECORD_BYTES
            or self.size + len(raw) > MAX_EVIDENCE_BYTES
            or self.records >= MAX_EVIDENCE_RECORDS
        ):
            raise RuntimeError("registered_surface_evidence_limit")
        if self.stream is not None:
            _ = self.stream.write(raw)
            self.stream.flush()
            os.fsync(self.stream.fileno())
        self.size += len(raw)
        self.records += 1

    def offer(self, case_id: str, registration_sha256: str) -> None:
        if (
            self.pending is not None
            or _TOKEN.fullmatch(case_id) is None
            or _DIGEST.fullmatch(registration_sha256) is None
        ):
            raise RuntimeError("registered_surface_evidence_identity_invalid")
        # Refuse before offering a new case if its terminal record cannot fit.
        if self.records + 2 > MAX_EVIDENCE_RECORDS or self.size + 2 * MAX_RECORD_BYTES > MAX_EVIDENCE_BYTES:
            raise RuntimeError("registered_surface_evidence_limit")
        self.pending = (case_id, registration_sha256)
        self._append(
            {
                "schema": "hol-guard.registered-surface-attempt.v1",
                "case_id": case_id,
                "registration_sha256": registration_sha256,
                "status": "offered",
                "stage": "offered",
                "route": None,
                "attempted_exit": None,
            }
        )

    def finish(self, status: str, attempt: SurfaceAttempt) -> None:
        if self.pending is None or status not in {"completed", "failed"} or attempt.stage not in _STAGES:
            raise RuntimeError("registered_surface_evidence_state_invalid")
        if attempt.attempted_exit is not None and type(attempt.attempted_exit) is not int:
            raise RuntimeError("registered_surface_evidence_exit_invalid")
        case_id, digest = self.pending
        self._append(
            {
                "schema": "hol-guard.registered-surface-attempt.v1",
                "case_id": case_id,
                "registration_sha256": digest,
                "status": status,
                "stage": attempt.stage,
                "route": attempt.route if attempt.route in _ROUTES else None,
                "attempted_exit": attempt.attempted_exit,
            }
        )
        self.pending = None
