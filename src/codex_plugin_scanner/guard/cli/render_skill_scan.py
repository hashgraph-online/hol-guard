"""Rows and title for the `guard install` skill security scan panel."""

from __future__ import annotations

from collections.abc import Sequence


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _is_unscanned(entry: dict[str, object]) -> bool:
    return entry.get("status") == "unscanned"


def skill_scan_rows(skill_scan: Sequence[dict[str, object]]) -> list[tuple[str, str, str, str]]:
    """One (skill file, risks, severities, signals) row per scanned or unscanned skill."""
    rows: list[tuple[str, str, str, str]] = []
    for entry in skill_scan:
        skill_path = str(entry.get("skill_path", "?"))
        if _is_unscanned(entry):
            reason = entry.get("scan_error")
            detail = reason if isinstance(reason, str) and reason else "detector unavailable"
            rows.append((skill_path, "—", "", f"not scanned: {detail}"))
            continue
        rows.append(
            (
                skill_path,
                str(entry.get("risk_count", 0)),
                ", ".join(_string_list(entry.get("severities"))),
                " ".join(_string_list(entry.get("signal_ids"))),
            )
        )
    return rows


def skill_scan_title(skill_scan: Sequence[dict[str, object]]) -> str:
    """Panel title that counts risky and unscanned skills separately."""
    unscanned = sum(1 for entry in skill_scan if _is_unscanned(entry))
    risky = len(skill_scan) - unscanned
    parts = []
    if risky:
        parts.append(f"{risky} file(s) with risks")
    if unscanned:
        parts.append(f"{unscanned} file(s) not scanned")
    return f"Skill security scan — {', '.join(parts)}"
