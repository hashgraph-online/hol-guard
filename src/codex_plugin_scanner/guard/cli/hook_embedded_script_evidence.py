"""Lazy embedded-script evidence and review guidance for hook responses."""

from __future__ import annotations


def _embedded_script_evidence(command_text: str | None) -> list[dict[str, object]]:
    """Hash-addressed audit entries for heredoc script bodies (lazy import)."""

    from ..runtime.embedded_script_evidence import embedded_script_evidence_entries

    return embedded_script_evidence_entries(command_text)


def _embedded_script_remediation(command_text: str | None) -> str | None:
    """Guidance for agents whose command carries an inline script body."""

    from ..runtime.embedded_script_evidence import (
        EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE,
        command_has_embedded_script,
    )

    if command_has_embedded_script(command_text):
        return EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE
    return None
