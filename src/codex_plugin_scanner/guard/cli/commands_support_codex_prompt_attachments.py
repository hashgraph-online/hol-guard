"""Bounded scanning for Codex-managed pasted-text attachments."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from ..models import GuardArtifact
from ..runtime.runner import extract_prompt_requests
from .commands_support_codex_paths import (
    _CODEX_PROMPT_FILE_FINGERPRINT_LENGTH,
    _PROMPT_CONTENT_SCAN_MAX_BYTES,
    _PROMPT_FILE_READ_VERB_PATTERN,
    _PROMPT_PATH_TOKEN_PATTERN,
    _path_contains_symlink,
)

_GUARDED_ATTACHMENT_CLASSES = frozenset(
    {"prompt_injection_intent", "guard_bypass_intent", "exfil_intent", "secret_read"}
)


def _codex_prompt_attachment_artifact(*, prompt_text: str, home_dir: Path, config_path: str) -> GuardArtifact | None:
    """Scan explicitly requested Codex attachment text without exposing its contents."""

    if _PROMPT_FILE_READ_VERB_PATTERN.search(prompt_text) is None:
        return None
    attachment_root = home_dir / ".codex" / "attachments"
    try:
        resolved_root = attachment_root.resolve(strict=True)
    except OSError:
        return None
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(prompt_text):
        requested_path = match.group(0).rstrip(".,:!?")
        candidate = Path(requested_path).expanduser()
        if not candidate.is_absolute() or not candidate.is_relative_to(attachment_root):
            continue
        if _path_contains_symlink(candidate, base_dir=attachment_root):
            return _scan_failure(requested_path, "Guard could not verify the Codex attachment path.", config_path)
        try:
            resolved_path = candidate.resolve(strict=True)
        except OSError:
            return _scan_failure(requested_path, "Guard could not read the Codex attachment safely.", config_path)
        if not resolved_path.is_relative_to(resolved_root):
            return _scan_failure(requested_path, "Guard could not verify the Codex attachment path.", config_path)
        try:
            content = _read_attachment(candidate)
        except (OSError, UnicodeError):
            return _scan_failure(requested_path, "Guard could not fully scan the Codex attachment.", config_path)
        guarded = [
            request
            for request in extract_prompt_requests(content)
            if request.request_class in _GUARDED_ATTACHMENT_CLASSES
        ]
        if not guarded:
            continue
        classes = list(dict.fromkeys(request.request_class for request in guarded))
        digest = hashlib.sha256(content.encode()).hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]
        return GuardArtifact(
            artifact_id=f"codex:session:prompt-attachment:{digest}",
            name="Codex attachment with guarded instructions",
            harness="codex",
            artifact_type="prompt_request",
            source_scope="session",
            config_path=config_path,
            metadata={
                "prompt_signals": ["Requested Codex attachment contains guarded instructions."],
                "prompt_summary": "Guard found risky instructions inside a requested Codex attachment.",
                "prompt_matched_text": "Codex attachment content",
                "prompt_request_class": classes[0],
                "prompt_request_classes": classes,
                "request_summary": "Codex attachment needs review before its instructions are used.",
                "runtime_request_summary": "Codex attachment needs review before its instructions are used.",
                "runtime_request_reason": "Guard scanned the attachment locally and found guarded instructions.",
                "attachment_content_digest": digest,
            },
        )
    return None


def _read_attachment(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > _PROMPT_CONTENT_SCAN_MAX_BYTES:
            raise OSError("unsupported attachment shape")
        content = os.read(descriptor, _PROMPT_CONTENT_SCAN_MAX_BYTES + 1)
        if len(content) > _PROMPT_CONTENT_SCAN_MAX_BYTES:
            raise OSError("attachment exceeds scan limit")
        return content.decode("utf-8")
    finally:
        os.close(descriptor)


def _scan_failure(requested_path: str, reason: str, config_path: str) -> GuardArtifact:
    fingerprint = hashlib.sha256(requested_path.encode()).hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]
    return GuardArtifact(
        artifact_id=f"codex:session:prompt-attachment-unscanned:{fingerprint}",
        name="Codex attachment could not be scanned",
        harness="codex",
        artifact_type="prompt_request",
        source_scope="session",
        config_path=config_path,
        metadata={
            "prompt_signals": [reason],
            "prompt_summary": reason,
            "prompt_matched_text": "Codex attachment",
            "prompt_request_class": "prompt_injection_intent",
            "prompt_request_classes": ["prompt_injection_intent"],
            "request_summary": reason,
            "runtime_request_summary": reason,
            "runtime_request_reason": reason,
        },
    )


__all__ = ["_codex_prompt_attachment_artifact"]
