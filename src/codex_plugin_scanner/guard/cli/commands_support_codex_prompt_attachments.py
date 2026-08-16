"""Bounded scanning for Codex-managed pasted-text attachments."""

from __future__ import annotations

import codecs
import hashlib
import os
import re
import stat
from pathlib import Path

from ..models import GuardArtifact
from ..runtime.runner import (
    _PROMPT_SENTENCE_BOUNDARY_PATTERN,
    _SECRET_READ_INTENT_PATTERN,
    _secret_read_intent_is_negated,
    extract_prompt_requests,
)
from .commands_support_codex_paths import (
    _CODEX_PROMPT_FILE_FINGERPRINT_LENGTH,
    _PROMPT_FILE_READ_VERB_PATTERN,
    _PROMPT_PATH_TOKEN_PATTERN,
    _path_contains_symlink,
)

_ATTACHMENT_SCAN_CHUNK_BYTES = 128 * 1024
_ATTACHMENT_SCAN_MAX_BYTES = 8 * 1024 * 1024
_ATTACHMENT_SCAN_OVERLAP_CHARS = 4 * 1024
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_CODEX_ATTACHMENT_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])(?:\./)?\.codex/attachments/[^\s'\"`<>|;(){}\[\]]{1,512}|" + _PROMPT_PATH_TOKEN_PATTERN.pattern
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
    for match in _CODEX_ATTACHMENT_PATH_TOKEN_PATTERN.finditer(prompt_text):
        requested_path = match.group(0).rstrip(".,:!?")
        candidate = Path(requested_path).expanduser()
        if not candidate.is_absolute():
            candidate = home_dir / candidate
        if not candidate.is_relative_to(attachment_root):
            continue
        if _path_contains_symlink(candidate, base_dir=attachment_root):
            return _scan_failure(requested_path, "Guard could not verify the Codex attachment path.", config_path)
        descriptor: int | None = None
        try:
            descriptor = _open_verified_attachment(
                candidate,
                attachment_root=attachment_root,
                resolved_root=resolved_root,
            )
            classes, digest = _scan_attachment(descriptor)
        except (OSError, UnicodeError):
            return _scan_failure(requested_path, "Guard could not fully scan the Codex attachment.", config_path)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not classes:
            continue
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


def _open_verified_attachment(candidate: Path, *, attachment_root: Path, resolved_root: Path) -> int:
    relative_parts = candidate.relative_to(attachment_root).parts
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        raise OSError("invalid attachment path")
    if not _OPEN_SUPPORTS_DIR_FD:
        resolved_candidate = candidate.resolve(strict=True)
        if not resolved_candidate.is_relative_to(resolved_root):
            raise OSError("attachment escaped managed root")
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if candidate.resolve(strict=True) != resolved_candidate or not os.path.samestat(
                os.fstat(descriptor), candidate.stat(follow_symlinks=False)
            ):
                raise OSError("attachment changed while opening")
        except OSError:
            os.close(descriptor)
            raise
        return descriptor
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = os.open(attachment_root, directory_flags)
    try:
        if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode) or not os.path.samestat(
            os.fstat(directory_descriptor), resolved_root.stat(follow_symlinks=False)
        ):
            raise OSError("attachment root changed while opening")
        for part in relative_parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode):
                raise OSError("attachment parent is not a directory")
        return os.open(
            relative_parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def _scan_attachment(descriptor: int) -> tuple[list[str], str]:
    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > _ATTACHMENT_SCAN_MAX_BYTES:
        raise OSError("unsupported attachment shape")
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    digest = hashlib.sha256()
    overlap = ""
    guarded_classes: list[str] = []
    classification_cache: dict[tuple[int, bytes], tuple[str, ...]] = {}
    inherited_secret_read_state: tuple[int, bool] | None = None
    total_bytes = 0
    while raw_chunk := os.read(descriptor, _ATTACHMENT_SCAN_CHUNK_BYTES):
        total_bytes += len(raw_chunk)
        if total_bytes > _ATTACHMENT_SCAN_MAX_BYTES:
            raise OSError("attachment exceeds scan limit")
        digest.update(raw_chunk)
        decoded_chunk = decoder.decode(raw_chunk, final=False)
        window = f"{overlap}{decoded_chunk}"
        window_classes, inherited_secret_read_state = _classify_stream_window(
            window,
            classification_cache=classification_cache,
            inherited_secret_read_state=inherited_secret_read_state,
        )
        guarded_classes.extend(window_classes)
        overlap = window[-_ATTACHMENT_SCAN_OVERLAP_CHARS:]
    final_text = decoder.decode(b"", final=True)
    if final_text:
        window_classes, _ = _classify_stream_window(
            f"{overlap}{final_text}",
            classification_cache=classification_cache,
            inherited_secret_read_state=inherited_secret_read_state,
        )
        guarded_classes.extend(window_classes)
    return list(dict.fromkeys(guarded_classes)), digest.hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]


def _classify_stream_window(
    content_window: str,
    *,
    classification_cache: dict[tuple[int, bytes], tuple[str, ...]] | None = None,
    inherited_secret_read_state: tuple[int, bool] | None,
) -> tuple[tuple[str, ...], tuple[int, bool] | None]:
    classes = list(_cached_guarded_classes(content_window, classification_cache))
    prefix = ""
    if inherited_secret_read_state is not None:
        distance, positive = inherited_secret_read_state
        verb = "Read" if positive else "Do not read"
        prefix = f"{verb} " if distance == 0 else f"{verb} something. "
    inherited_window = f"{prefix}{content_window}"
    if inherited_secret_read_state is not None and "secret_read" in _cached_guarded_classes(
        inherited_window,
        classification_cache,
    ):
        classes.append("secret_read")
    return tuple(dict.fromkeys(classes)), _trailing_secret_read_state(inherited_window)


def _trailing_secret_read_state(content: str) -> tuple[int, bool] | None:
    previous_sentence_start = 0
    trailing_sentence_start = 0
    for match in _PROMPT_SENTENCE_BOUNDARY_PATTERN.finditer(content):
        previous_sentence_start = trailing_sentence_start
        trailing_sentence_start = match.end()
    trailing_polarity = _secret_read_polarity(content[trailing_sentence_start:])
    if trailing_polarity is not None:
        return 0, trailing_polarity
    previous_polarity = _secret_read_polarity(content[previous_sentence_start:trailing_sentence_start])
    return None if previous_polarity is None else (1, previous_polarity)


def _secret_read_polarity(sentence: str) -> bool | None:
    intents = tuple(_SECRET_READ_INTENT_PATTERN.finditer(sentence))
    if not intents:
        return None
    return any(not _secret_read_intent_is_negated(sentence, match.start(), match.end()) for match in intents)


def _guarded_classes(content_window: str) -> tuple[str, ...]:
    return tuple(
        request.request_class
        for request in extract_prompt_requests(content_window)
        if request.request_class in _GUARDED_ATTACHMENT_CLASSES
    )


def _cached_guarded_classes(
    content_window: str,
    cache: dict[tuple[int, bytes], tuple[str, ...]] | None,
) -> tuple[str, ...]:
    if cache is None:
        return _guarded_classes(content_window)
    encoded_window = content_window.encode()
    cache_key = (len(encoded_window), hashlib.sha256(encoded_window).digest())
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    classes = _guarded_classes(content_window)
    cache[cache_key] = classes
    return classes


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


__all__ = [
    "_ATTACHMENT_SCAN_CHUNK_BYTES",
    "_ATTACHMENT_SCAN_MAX_BYTES",
    "_codex_prompt_attachment_artifact",
]
