"""Promote one exact harness version into the bundled coverage manifest.

Run on the release PR, where ``__version__`` is already the release being
cut, after the eligible suite passed against that exact harness version. The
record is written through the runtime validator, so anything the validator
would reject at load time is refused here and the manifest is left untouched.
Promoting a version that is already recorded replaces its record in place.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard.harness_versions.manifest import (  # noqa: E402
    ELIGIBLE_SUITES,
    MAX_MANIFEST_BYTES,
    ManifestError,
    bundled_manifest_path,
    parse_manifest,
)
from codex_plugin_scanner.guard.harness_versions.versions import parse_version  # noqa: E402
from codex_plugin_scanner.version import __version__  # noqa: E402


def next_revision(current: str, today: str) -> str:
    """``YYYY-MM-DD.N``: restart at 1 on a new day, otherwise increment."""

    date, _, serial = current.rpartition(".")
    if date == today and serial.isdigit():
        return f"{today}.{int(serial) + 1}"
    return f"{today}.1"


def _canonical_version(value: object) -> str | None:
    parsed = parse_version(value) if isinstance(value, str) else None
    return parsed.canonical if parsed is not None else None


def promote(
    payload: dict[str, object],
    *,
    harness: str,
    harness_version: str,
    suite_id: str,
    evidence_reference: str,
    platforms: list[str],
    guard_version: str,
    observed_at: str,
    events: list[str] | None = None,
    evidence_level: str | None = None,
    prune_stale: bool = False,
) -> dict[str, object]:
    """Return a new manifest payload with the record promoted; raise ``ManifestError``."""

    version = parse_version(harness_version)
    if version is None:
        raise ManifestError("harness version must be one exact version, not a range or wildcard")
    suite = ELIGIBLE_SUITES.get(suite_id)
    if suite is None:
        raise ManifestError(f"suite {suite_id!r} is not eligible; choose one of {sorted(ELIGIBLE_SUITES)}")
    entries = [entry for entry in payload.get("harnesses", []) if isinstance(entry, dict)]  # type: ignore[union-attr]
    target = next((entry for entry in entries if entry.get("harness") == harness), None)
    if target is None:
        raise ManifestError(f"the manifest has no {harness!r} harness entry")
    record = {
        "harness_version": version.canonical,
        "guard_version": guard_version,
        "platforms": platforms,
        "transport": suite.transport,
        "events": events if events is not None else sorted(suite.events),
        "suite": {"id": suite_id, "result": "passed"},
        "evidence_level": evidence_level if evidence_level is not None else suite.evidence_level,
        "evidence_reference": evidence_reference,
        "observed_at": observed_at,
    }
    # Compare the forms the runtime compares, so a "v"-prefixed record is
    # replaced rather than left beside its re-promotion as a duplicate.
    kept = [
        item
        for item in target["records"]  # type: ignore[union-attr]
        if isinstance(item, dict)
        and _canonical_version(item.get("harness_version")) != version.canonical
        and not (prune_stale and _canonical_version(item.get("guard_version")) != _canonical_version(guard_version))
    ]
    promoted = json.loads(json.dumps(payload))
    for entry in promoted["harnesses"]:
        if entry.get("harness") == harness:
            entry["records"] = [*kept, record]
    promoted["revision"] = next_revision(str(payload.get("revision", "")), observed_at[:10])
    parse_manifest(promoted)
    if len(render(promoted)) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"the manifest would exceed {MAX_MANIFEST_BYTES} bytes")
    return promoted


def render(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _write_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", required=True, help="harness id, for example omp")
    parser.add_argument("--harness-version", required=True, help="one exact harness version")
    parser.add_argument("--suite", required=True, choices=sorted(ELIGIBLE_SUITES), help="suite that passed")
    parser.add_argument("--evidence-reference", required=True, help="URL of the retained run in this repository")
    parser.add_argument(
        "--platform", action="append", required=True, dest="platforms", help="platform the run covered (repeatable)"
    )
    parser.add_argument("--event", action="append", dest="events", help="event to claim; default is all the suite does")
    parser.add_argument("--evidence-level", help="default is the level the suite reaches")
    parser.add_argument("--observed-at", help="ISO-8601 timestamp with timezone; default is now (UTC)")
    parser.add_argument("--prune-stale", action="store_true", help="drop records bound to another Guard version")
    parser.add_argument("--manifest", type=Path, default=None, help="manifest to rewrite (default: bundled)")
    args = parser.parse_args(argv)

    path = args.manifest or bundled_manifest_path()
    observed_at = args.observed_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
        parse_manifest(payload)
        promoted = promote(
            payload,
            harness=args.harness,
            harness_version=args.harness_version,
            suite_id=args.suite,
            evidence_reference=args.evidence_reference,
            platforms=args.platforms,
            guard_version=__version__,
            observed_at=observed_at,
            events=args.events,
            evidence_level=args.evidence_level,
            prune_stale=args.prune_stale,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ManifestError) as error:
        print(f"harness version coverage: refusing to promote: {error}", file=sys.stderr)
        return 1
    _write_atomic(path, render(promoted))
    print(f"promoted {args.harness} {args.harness_version} for Guard {__version__}; revision {promoted['revision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
