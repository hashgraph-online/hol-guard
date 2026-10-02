"""Read-only preflight for source-bound evidence before a source PR can merge.

The native compiler and full corpus tests remain the semantic authorities.
This inexpensive gate detects stale bindings, malformed reports and mismatched
package copies without generating new expectations or requiring Git history.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous reports rather than accepting the last duplicate key."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in generated evidence")
        result[key] = value
    return result


def _read(path: Path) -> bytes:
    """Require a bounded regular generated file, never a symlink substitute."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError(f"missing or invalid generated file: {path.name}")
    return path.read_bytes()


def snapshot_errors(
    report_path: Path,
    expected_bindings: Mapping[str, Mapping[str, str]],
    mirrors: Sequence[tuple[Path, Path]],
) -> list[str]:
    """Compare committed evidence and package copies without modifying either."""
    errors: list[str] = []
    try:
        raw = _read(report_path)
        report = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(report, dict):
            raise ValueError("generated evidence must be a JSON object")
        if report.get("bindings") != expected_bindings:
            errors.append("decision-diff report does not bind the current source and fixture bytes")
        canonical = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        if raw != canonical:
            errors.append("decision-diff report is not canonically serialized")
        digest_path = report_path.with_suffix(".framed-sha256")
        digest = hashlib.sha256(len(raw).to_bytes(8, "big") + raw).hexdigest()
        if _read(digest_path) != (digest + "\n").encode():
            errors.append("decision-diff framed digest does not match the committed report")
    except (OSError, ValueError) as error:
        errors.append(f"cannot validate decision-diff evidence: {error}")
    for canonical_path, package_path in mirrors:
        try:
            if _read(canonical_path) != _read(package_path):
                errors.append(f"package copy differs from canonical {canonical_path.name}")
        except (OSError, ValueError) as error:
            errors.append(f"cannot validate {canonical_path.name}: {error}")
    return errors


def main() -> int:
    """Derive bindings from the real report generator and fail closed on drift."""
    sys.path.insert(0, str(ROOT))
    try:
        from tests.guard_command_decision_diff import (
            KNOWN_GAPS_PATH,
            MANIFEST_PATH,
            NATIVE_CONTRACT_PATH,
            PAIRS_PATH,
            REPORT_PATH,
            _source_bindings,
        )

        fixtures = (KNOWN_GAPS_PATH, PAIRS_PATH, MANIFEST_PATH, NATIVE_CONTRACT_PATH)
        bindings = {
            "sources_sha256": _source_bindings(),
            "fixtures_sha256": {path.name: hashlib.sha256(_read(path)).hexdigest() for path in fixtures},
        }
        names = ("native-command-program.v1.json", "command-catalog.v1.json")
        mirrors = [
            (
                ROOT / "contracts/extensions" / name,
                ROOT / "src/codex_plugin_scanner/guard/contracts/data/extensions" / name,
            )
            for name in names
        ]
        errors = snapshot_errors(REPORT_PATH, bindings, mirrors)
    except (ImportError, OSError, ValueError, KeyError, TypeError) as error:
        errors = [f"cannot establish current evidence inputs: {error}"]
    print(json.dumps({"ok": not errors, "errors": errors}, sort_keys=True))
    if errors:
        print(
            "Regenerate on this PR branch with: uv run --no-sync python scripts/refresh_extension_artifacts.py\n"
            "Commit the generated changes with their source changes. Do not merge source-only drift and wait for main.",
            file=sys.stderr,
        )
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
