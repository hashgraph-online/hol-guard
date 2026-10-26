"""Structured audit evidence for scripts embedded in shell commands.

Heredoc bodies are already retained verbatim in the receipt envelope's
``envelope_full_json`` command text. The native shell helpers add a
hash-addressed index over each embedded script so audits can locate, count,
and verify the bodies without re-parsing opaque envelope JSON, and so denial
messages can tell agents how to make one-off scripts auditable.
"""

from __future__ import annotations

from ..native_shell_helpers import call

EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE = (
    "Put the script in a workspace file and run it by path so HOL Guard can audit it."
)


def embedded_script_evidence_entries(command_text: str | None) -> list[dict[str, object]]:
    """Return bounded scanner-evidence entries for each heredoc script body.

    Each entry carries the body hash, size, source span, and whether the body
    is executed (fed to an interpreter) or written to a file. The body itself
    is not duplicated; it remains in the retained envelope command text and is
    addressable via the span and sha256. The native helper owns the answer.
    """
    if not isinstance(command_text, str) or not command_text.strip():
        return []
    return list(call("embedded_script_evidence", command_text))
