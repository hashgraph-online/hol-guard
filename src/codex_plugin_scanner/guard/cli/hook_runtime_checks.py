"""Bounded runtime posture projection and exact archive command checks."""

from __future__ import annotations

import os
import shlex


def _stamp_runtime_posture_metadata(artifact: object, signals: object) -> None:
    metadata = getattr(artifact, "metadata", None)
    if not isinstance(metadata, dict):
        return
    if isinstance(signals, tuple) and signals:
        metadata["risk_signals"] = [
            {
                "confidence": getattr(signal, "confidence", None),
                "category": getattr(signal, "category", None),
            }
            for signal in signals
        ]
        if any(getattr(signal, "confidence", None) == "strong" for signal in signals):
            metadata["risk_confidence"] = "strong"
    action_class = metadata.get("action_class")
    if isinstance(action_class, str):
        lowered = action_class.lower()
        if any(token in lowered for token in ("launch agent", "login item", "launchctl", "cron", "systemd", "launchd")):
            metadata["persistence_writes_launch_agent"] = True


def _runtime_external_archive_command_matches_executable(raw_command: str | None, executable: str) -> bool:
    if (
        raw_command is None
        or os.name == "nt"
        or "`" in raw_command
        or "$(" in raw_command
        or "\n" in raw_command
        or "\r" in raw_command
    ):
        return False
    lexer = shlex.shlex(raw_command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or tokens[0] != executable:
        return False
    return not any(token and all(character in "();<>|&" for character in token) for token in tokens)
