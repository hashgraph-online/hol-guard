"""Bounded Cloud-safe display fields for live review requests."""

from __future__ import annotations

from .local_request_snapshots import _cloud_scrub_text, _local_request_command_text

_COMMAND_MAX_UTF16_UNITS = 65_536
_SUMMARY_MAX_UTF16_UNITS = 512


def resolve_display_provenance(*, has_command_details: bool, redaction_level: str) -> str:
    if redaction_level == "none":
        return "raw"
    if redaction_level == "full" and not has_command_details:
        return "withheld"
    return "redacted"


def build_display_command(item: dict[str, object], redaction_level: str) -> tuple[str, str, str | None, str | None]:
    action_identity = str(item.get("action_identity") or item.get("artifact_id") or "unknown")
    trigger_summary = str(item.get("trigger_summary") or item.get("why_now") or "Guard approval request")
    risk_headline = str(item.get("risk_headline") or item.get("risk_summary") or "")
    harness = str(item.get("harness") or "guard-review")

    fallback_display = f"{_cloud_scrub_text(harness)}: {_cloud_scrub_text(action_identity)}"
    envelope_value = item.get("action_envelope_json")
    envelope = envelope_value if isinstance(envelope_value, dict) else None
    command_text = _local_request_command_text(item, envelope)
    safe_command = _cloud_scrub_text(command_text) if command_text else None
    display_command = _truncate_utf16(safe_command or fallback_display, _COMMAND_MAX_UTF16_UNITS)
    display_summary = f"{trigger_summary}"
    if risk_headline:
        display_summary = f"{risk_headline} — {trigger_summary}"
    display_summary = _truncate_utf16(display_summary, _SUMMARY_MAX_UTF16_UNITS)

    raw_command = display_command if redaction_level == "none" and safe_command else None
    redacted_command = display_command if redaction_level != "none" and safe_command else None
    return display_command, display_summary, raw_command, redacted_command


def _utf16_units(value: str) -> int:
    return sum(2 if ord(character) > 0xFFFF else 1 for character in value)


def _take_utf16_prefix(value: str, max_units: int) -> str:
    units = 0
    for index, character in enumerate(value):
        units += 2 if ord(character) > 0xFFFF else 1
        if units > max_units:
            return value[:index]
    return value


def _take_utf16_suffix(value: str, max_units: int) -> str:
    units = 0
    for index in range(len(value) - 1, -1, -1):
        units += 2 if ord(value[index]) > 0xFFFF else 1
        if units > max_units:
            return value[index + 1 :]
    return value


def _truncate_utf16(value: str, max_units: int) -> str:
    if _utf16_units(value) <= max_units:
        return value
    marker = " … [truncated] … "
    available_units = max_units - _utf16_units(marker)
    prefix_units = available_units * 3 // 4
    suffix_units = available_units - prefix_units
    return _take_utf16_prefix(value, prefix_units) + marker + _take_utf16_suffix(value, suffix_units)
