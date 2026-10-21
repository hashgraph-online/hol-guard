"""Bounded scanning for Codex-managed pasted-text attachments."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import GuardArtifact
from ..native_codex_tool_output import codex_tool_output_native
from ..native_prompt import artifact_from_dict
from ..native_sensitive_request import NativeSensitiveRequestError

# The resident holds the scan's own bounds; these name them for callers that
# size a payload against the same limits.
_ATTACHMENT_SCAN_CHUNK_BYTES = 64 * 1024
_ATTACHMENT_SCAN_MAX_BYTES = 8 * 1024 * 1024


def _codex_prompt_attachment_artifact(*, prompt_text: str, home_dir: Path, config_path: str) -> GuardArtifact | None:
    """Scan explicitly requested Codex attachment text without exposing its contents."""

    # The resident grants a worker at most nine seconds whatever a caller asks
    # for, so the scan's own deadline stays inside that lease: it then ends in
    # an unscanned-attachment artifact rather than an expired-lease error.
    answer = codex_tool_output_native(
        "prompt_attachment",
        prompt_text=prompt_text,
        home_dir=home_dir,
        config_path=config_path,
        deadline_ms=8_000,
        timeout_seconds=9.0,
    )
    if not answer.allowed or answer.value is None or answer.error_code is not None:
        raise NativeSensitiveRequestError(answer.error_code or "native_codex_attachment_unavailable")
    return artifact_from_dict(json.loads(answer.value))


__all__ = [
    "_ATTACHMENT_SCAN_CHUNK_BYTES",
    "_ATTACHMENT_SCAN_MAX_BYTES",
    "_codex_prompt_attachment_artifact",
]
