"""Bundled tested-version coverage manifest: model, eligibility, validation.

The manifest ships inside the Guard build and is the only coverage authority.
Every record names one exact harness version, the Guard version it was tested
against, the platforms, transport, and events it exercised, and the passing
suite run that proves it. There are no ranges: a version that is not listed is
not covered, however close it is to a listed one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from ..adapters.contracts import contract_for
from .versions import HarnessVersion, parse_version

SCHEMA_VERSION = "hol-guard-harness-version-coverage.v1"
MANIFEST_FILENAME = "harness_version_coverage_v1.json"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_RECORDS_PER_HARNESS = 128

SUPPORTED_PLATFORMS = frozenset(
    {"darwin-arm64", "darwin-x86_64", "linux-arm64", "linux-x86_64", "windows-arm64", "windows-x86_64"}
)
EVIDENCE_REFERENCE_PREFIX = "https://github.com/hashgraph-online/hol-guard/"
REMEDIATION_HOSTS = frozenset({"github.com", "www.npmjs.com", "omp.sh"})


@dataclass(frozen=True, slots=True)
class EligibleSuite:
    """A suite whose passing run can support a record, and what it exercises."""

    harnesses: frozenset[str]
    transport: str
    events: frozenset[str]
    evidence_level: str


# The eligibility policy: a record may only claim the events its suite really
# exercises, at the evidence level that suite really reaches. Contract tests
# against a pinned SDK stay "unit_test"; only a live harness run is "live_block".
ELIGIBLE_SUITES: dict[str, EligibleSuite] = {
    "pi-exact-continuation": EligibleSuite(
        harnesses=frozenset({"omp"}),
        transport="managed_extension",
        events=frozenset({"PreToolUse"}),
        evidence_level="unit_test",
    ),
    "guard-gauntlet-full-task": EligibleSuite(
        harnesses=frozenset({"omp"}),
        transport="managed_extension",
        events=frozenset({"UserPromptSubmit", "PreToolUse", "PostToolUse"}),
        evidence_level="live_block",
    ),
}

_TOP_KEYS = {"schema_version", "revision", "harnesses"}
_HARNESS_KEYS = {"harness", "version_source", "limitations", "remediation", "records"}
_RECORD_KEYS = {
    "harness_version",
    "guard_version",
    "platforms",
    "transport",
    "events",
    "suite",
    "evidence_level",
    "evidence_reference",
    "observed_at",
}
_VERSION_SOURCES = {"package-metadata", "unavailable"}


class ManifestError(ValueError):
    """The manifest is malformed or claims more than its evidence supports."""


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    harness_version: HarnessVersion
    guard_version: str
    platforms: tuple[str, ...]
    transport: str
    events: tuple[str, ...]
    suite_id: str
    evidence_level: str
    evidence_reference: str
    observed_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "harness_version": self.harness_version.canonical,
            "guard_version": self.guard_version,
            "platforms": list(self.platforms),
            "transport": self.transport,
            "events": list(self.events),
            # Same shape as the manifest: only passed suites are ever recorded.
            "suite": {"id": self.suite_id, "result": "passed"},
            "evidence_level": self.evidence_level,
            "evidence_reference": self.evidence_reference,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class RemediationLink:
    label: str
    url: str


@dataclass(frozen=True, slots=True)
class HarnessCoverage:
    harness: str
    version_source: str
    limitations: tuple[str, ...]
    remediation: tuple[RemediationLink, ...]
    records: tuple[CoverageRecord, ...]


@dataclass(frozen=True, slots=True)
class CoverageManifest:
    revision: str
    harnesses: dict[str, HarnessCoverage]


def _text(value: object, field: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ManifestError(f"{field} must be a non-empty string of at most {limit} characters")
    return value


def _keys(value: object, allowed: set[str], field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be an object")
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown:
        raise ManifestError(f"{field} has unsupported keys: {sorted(unknown)}")
    if missing:
        raise ManifestError(f"{field} is missing keys: {sorted(missing)}")
    return value


def _text_list(value: object, field: str, *, limit: int = 32) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ManifestError(f"{field} must be a list of at most {limit} strings")
    items = tuple(_text(item, f"{field}[]", limit=400) for item in value)
    if len(set(items)) != len(items):
        raise ManifestError(f"{field} contains duplicates")
    return items


def _remediation(value: object, field: str) -> tuple[RemediationLink, ...]:
    if not isinstance(value, list) or len(value) > 8:
        raise ManifestError(f"{field} must be a list of at most 8 links")
    links: list[RemediationLink] = []
    for index, item in enumerate(value):
        entry = _keys(item, {"label", "url"}, f"{field}[{index}]")
        url = _text(entry["url"], f"{field}[{index}].url", limit=400)
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in REMEDIATION_HOSTS or parts.username or parts.port:
            raise ManifestError(f"{field}[{index}].url must be an https link to a reviewed host")
        links.append(RemediationLink(label=_text(entry["label"], f"{field}[{index}].label", limit=80), url=url))
    return tuple(links)


def _record(harness: str, value: object, field: str) -> CoverageRecord:
    entry = _keys(value, _RECORD_KEYS, field)
    version = parse_version(entry["harness_version"])
    if version is None:
        raise ManifestError(f"{field}.harness_version must be one exact version, not a range or wildcard")
    guard_version = parse_version(entry["guard_version"])
    if guard_version is None:
        raise ManifestError(f"{field}.guard_version must be one exact Guard release version")
    platforms = _text_list(entry["platforms"], f"{field}.platforms", limit=len(SUPPORTED_PLATFORMS))
    if not platforms or not set(platforms) <= SUPPORTED_PLATFORMS:
        raise ManifestError(f"{field}.platforms must name supported platforms")
    events = _text_list(entry["events"], f"{field}.events", limit=16)
    transport = _text(entry["transport"], f"{field}.transport", limit=64)
    suite = _keys(entry["suite"], {"id", "result"}, f"{field}.suite")
    suite_id = _text(suite["id"], f"{field}.suite.id", limit=64)
    eligible = ELIGIBLE_SUITES.get(suite_id)
    if eligible is None or harness not in eligible.harnesses:
        raise ManifestError(f"{field}.suite.id is not an eligible suite for {harness}")
    if suite["result"] != "passed":
        raise ManifestError(f"{field}.suite.result must be passed")
    if transport != eligible.transport or not events or not set(events) <= eligible.events:
        raise ManifestError(f"{field} claims a transport or events its suite does not exercise")
    contract = contract_for(harness)
    declared = {(row.event, row.transport) for row in (contract.capability_events if contract else ())}
    if any((event, transport) not in declared for event in events):
        raise ManifestError(f"{field} names an event that the {harness} adapter does not declare")
    evidence_level = _text(entry["evidence_level"], f"{field}.evidence_level", limit=32)
    if evidence_level != eligible.evidence_level:
        raise ManifestError(f"{field}.evidence_level must be {eligible.evidence_level} for suite {suite_id}")
    reference = _text(entry["evidence_reference"], f"{field}.evidence_reference", limit=400)
    if not reference.startswith(EVIDENCE_REFERENCE_PREFIX) or any(ch.isspace() for ch in reference):
        raise ManifestError(f"{field}.evidence_reference must point at this repository's retained evidence")
    observed_at = _text(entry["observed_at"], f"{field}.observed_at", limit=40)
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ManifestError(f"{field}.observed_at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ManifestError(f"{field}.observed_at must include a timezone")
    return CoverageRecord(
        harness_version=version,
        guard_version=guard_version.canonical,
        platforms=platforms,
        transport=transport,
        events=events,
        suite_id=suite_id,
        evidence_level=evidence_level,
        evidence_reference=reference,
        observed_at=observed_at,
    )


def parse_manifest(payload: object) -> CoverageManifest:
    """Validate a decoded manifest; raise ``ManifestError`` on any defect."""

    top = _keys(payload, _TOP_KEYS, "manifest")
    if top["schema_version"] != SCHEMA_VERSION:
        raise ManifestError("manifest.schema_version is not supported")
    revision = _text(top["revision"], "manifest.revision", limit=64)
    harness_entries = top["harnesses"]
    if not isinstance(harness_entries, list) or len(harness_entries) > 64:
        raise ManifestError("manifest.harnesses must be a list")
    harnesses: dict[str, HarnessCoverage] = {}
    for index, raw in enumerate(harness_entries):
        field = f"manifest.harnesses[{index}]"
        entry = _keys(raw, _HARNESS_KEYS, field)
        harness = _text(entry["harness"], f"{field}.harness", limit=64)
        contract = contract_for(harness)
        if contract is None or contract.harness != harness:
            raise ManifestError(f"{field}.harness must be a canonical harness id")
        if harness in harnesses:
            raise ManifestError(f"{field}.harness is listed twice")
        if entry["version_source"] not in _VERSION_SOURCES:
            raise ManifestError(f"{field}.version_source is not supported")
        records_raw = entry["records"]
        if not isinstance(records_raw, list) or len(records_raw) > MAX_RECORDS_PER_HARNESS:
            raise ManifestError(f"{field}.records must be a bounded list")
        if records_raw and entry["version_source"] == "unavailable":
            raise ManifestError(f"{field} cannot claim tested versions without a version source")
        records = tuple(_record(harness, item, f"{field}.records[{i}]") for i, item in enumerate(records_raw))
        seen: set[tuple[str, str, str, str, str]] = set()
        for record in records:
            for platform in record.platforms:
                for event in record.events:
                    key = (
                        record.harness_version.canonical,
                        record.guard_version,
                        platform,
                        record.transport,
                        event,
                    )
                    if key in seen:
                        raise ManifestError(f"{field}.records has duplicate or conflicting claims for {key}")
                    seen.add(key)
        harnesses[harness] = HarnessCoverage(
            harness=harness,
            version_source=str(entry["version_source"]),
            limitations=_text_list(entry["limitations"], f"{field}.limitations", limit=8),
            remediation=_remediation(entry["remediation"], f"{field}.remediation"),
            records=records,
        )
    return CoverageManifest(revision=revision, harnesses=harnesses)


def bundled_manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "schemas" / MANIFEST_FILENAME


@dataclass(frozen=True, slots=True)
class ManifestLoad:
    manifest: CoverageManifest | None
    error: str | None


def load_manifest(path: Path | None = None) -> ManifestLoad:
    """Load the manifest; any defect yields ``manifest=None`` and a reason code."""

    target = path or bundled_manifest_path()
    try:
        raw = target.read_bytes()
    except OSError:
        return ManifestLoad(None, "manifest_missing")
    if len(raw) > MAX_MANIFEST_BYTES:
        return ManifestLoad(None, "manifest_invalid")
    try:
        return ManifestLoad(parse_manifest(json.loads(raw.decode("utf-8"))), None)
    except (UnicodeDecodeError, json.JSONDecodeError, ManifestError):
        return ManifestLoad(None, "manifest_invalid")
