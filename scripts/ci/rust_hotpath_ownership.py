#!/usr/bin/env python3
"""Validate and classify HOL Guard Rust hot-path ownership."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("Python 3.11 or newer is required") from exc

SCHEMA_VERSION = 1
HOT_PATH_PREFIXES = (
    "rust/",
    "ci/native_runtime/",
    "src/codex_plugin_scanner/guard/",
    "scripts/ci/",
    "scripts/integration/",
    ".github/workflows/",
)
VALID_AUTHORITY = {
    "rust",
    "rust-artifact",
    "rust-data-plane",
    "hybrid-transport",
    "migration",
    "ci",
}
VALID_FALLBACK = {
    "native-fail-safe",
    "native-review-or-block",
    "bounded-native-oneshot-or-fail-safe",
    "none",
}
JOB_OUTPUTS: Final[dict[str, str]] = {
    "rust": "rust",
    "resident-integration": "resident_integration",
    "pretool-integration": "pretool_integration",
    "all-harness": "all_harness",
    "command-differential": "command_differential",
    "transport-faults": "transport_faults",
    "performance": "performance",
    "native-release": "native_release",
    "installed-wheel": "installed_wheel",
}
PROTECTED_SURFACE_INVARIANTS: Final[dict[str, dict[str, object]]] = {
    "post-tool-content-review": {
        "authority": "rust",
        "target_authority": "rust",
        "python_authority_allowed": False,
        "fallback": "native-fail-safe",
        "events": frozenset({"PostToolUse"}),
        "required_jobs": frozenset({"rust", "resident-integration", "all-harness"}),
    },
    "pre-tool-command-decision": {
        "authority": "migration",
        "target_authority": "rust",
        "python_authority_allowed": False,
        "fallback": "native-review-or-block",
        "events": frozenset({"PreToolUse"}),
        "required_jobs": frozenset(
            {"rust", "resident-integration", "pretool-integration", "command-differential"}
        ),
    },
    "resident-transport": {
        "authority": "hybrid-transport",
        "target_authority": "rust-data-plane",
        "python_authority_allowed": False,
        "fallback": "bounded-native-oneshot-or-fail-safe",
        "events": frozenset({"PreToolUse", "PostToolUse"}),
        "required_jobs": frozenset({"resident-integration", "transport-faults", "performance"}),
    },
    "native-packaging": {
        "authority": "rust-artifact",
        "target_authority": "rust-artifact",
        "python_authority_allowed": False,
        "fallback": "none",
        "events": frozenset({"release"}),
        "required_jobs": frozenset({"native-release", "installed-wheel"}),
    },
    "migration-governance": {
        "authority": "ci",
        "target_authority": "ci",
        "python_authority_allowed": True,
        "fallback": "none",
        "events": frozenset({"repository-change"}),
        "required_jobs": frozenset({"ownership"}),
    },
}
THRESHOLD_INVARIANTS: Final[dict[str, tuple[str, float]]] = {
    "minimum_rust_decision_share": ("minimum", 0.95),
    "minimum_rust_inspected_byte_share": ("minimum", 0.95),
    "minimum_resident_share": ("minimum", 0.99),
    "maximum_python_decision_fallback_share": ("maximum", 0.0),
}


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"ownership manifest could not be read: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("ownership manifest must be a TOML table")
    return payload


def _date(value: object, field: str) -> dt.date:
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{field} must be an ISO date") from exc
    raise ValueError(f"{field} must be an ISO date")


def _validate_header(payload: dict[str, Any]) -> None:
    expected = {
        "schema_version": SCHEMA_VERSION,
        "release_branch": "release/3.0",
        "product_default": "rust",
        "python_decision_fallback_allowed": False,
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            raise ValueError(f"{field} must equal {value!r}")


def _validate_thresholds(payload: dict[str, Any]) -> None:
    thresholds = payload.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a TOML table")
    for name, (comparison, protected_value) in THRESHOLD_INVARIANTS.items():
        raw = thresholds.get(name)
        if not isinstance(raw, (int, float)) or isinstance(raw, bool):
            raise ValueError(f"thresholds.{name} must be numeric")
        value = float(raw)
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"thresholds.{name} must be between zero and one")
        if comparison == "minimum" and value < protected_value:
            raise ValueError(f"thresholds.{name} cannot be lowered below {protected_value}")
        if comparison == "maximum" and value > protected_value:
            raise ValueError(f"thresholds.{name} cannot be raised above {protected_value}")


def _string_array(surface_id: str, raw: dict[str, Any], field: str) -> list[str]:
    values = raw.get(field)
    if not isinstance(values, list) or not values:
        raise ValueError(f"surface {surface_id}.{field} must be a non-empty string array")
    if not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"surface {surface_id}.{field} must be a non-empty string array")
    return values


def _validate_surface_shape(index: int, raw: object, seen: set[str]) -> tuple[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ValueError(f"surface[{index}] must be a table")
    surface_id = raw.get("id")
    if not isinstance(surface_id, str) or not surface_id.strip() or surface_id in seen:
        raise ValueError(f"surface[{index}].id is missing or duplicated")
    if raw.get("authority") not in VALID_AUTHORITY or raw.get("target_authority") not in VALID_AUTHORITY:
        raise ValueError(f"surface {surface_id} has invalid authority or target_authority")
    if raw.get("fallback") not in VALID_FALLBACK:
        raise ValueError(f"surface {surface_id} has invalid fallback")
    if not isinstance(raw.get("python_authority_allowed"), bool):
        raise ValueError(f"surface {surface_id} must declare python_authority_allowed")
    for field in ("events", "harnesses", "required_jobs", "paths"):
        _string_array(surface_id, raw, field)
    unknown_jobs = sorted(set(raw["required_jobs"]) - ({"ownership"} | set(JOB_OUTPUTS)))
    if unknown_jobs:
        raise ValueError(f"surface {surface_id} declares unmapped required jobs: {unknown_jobs}")
    return surface_id, raw


def _surface_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    surfaces = payload.get("surface")
    if not isinstance(surfaces, list) or not surfaces:
        raise ValueError("at least one [[surface]] entry is required")
    seen: set[str] = set()
    indexed: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(surfaces):
        surface_id, surface = _validate_surface_shape(index, raw, seen)
        seen.add(surface_id)
        indexed[surface_id] = surface
    return indexed


def _validate_protected_surfaces(surfaces: dict[str, dict[str, Any]]) -> None:
    fixed_fields = ("authority", "target_authority", "python_authority_allowed", "fallback")
    for surface_id, invariant in PROTECTED_SURFACE_INVARIANTS.items():
        surface = surfaces.get(surface_id)
        if surface is None:
            raise ValueError(f"protected surface {surface_id} is missing")
        for field in fixed_fields:
            if surface.get(field) != invariant[field]:
                raise ValueError(f"protected surface {surface_id}.{field} cannot change")
        required_events = invariant["events"]
        required_jobs = invariant["required_jobs"]
        assert isinstance(required_events, frozenset) and isinstance(required_jobs, frozenset)
        if not required_events <= set(surface["events"]):
            raise ValueError(f"protected surface {surface_id} is missing required events")
        missing_jobs = sorted(required_jobs - set(surface["required_jobs"]))
        if missing_jobs:
            raise ValueError(f"protected surface {surface_id} is missing required jobs: {missing_jobs}")


def _validate_waiver(index: int, raw: object, surface_ids: set[str], seen: set[str], today: dt.date) -> str:
    if not isinstance(raw, dict):
        raise ValueError(f"waiver[{index}] must be a table")
    waiver_id = raw.get("id")
    if not isinstance(waiver_id, str) or not waiver_id or waiver_id in seen:
        raise ValueError("waiver id is missing or duplicated")
    if raw.get("surface") not in surface_ids:
        raise ValueError(f"waiver {waiver_id} references an unknown surface")
    for field in ("owner", "issue", "reason"):
        if not isinstance(raw.get(field), str) or not raw[field].strip():
            raise ValueError(f"waiver {waiver_id}.{field} is required")
    created = _date(raw.get("created"), f"waiver {waiver_id}.created")
    expires = _date(raw.get("expires"), f"waiver {waiver_id}.expires")
    if expires < created:
        raise ValueError(f"waiver {waiver_id} expires before it was created")
    if expires < today:
        raise ValueError(f"waiver {waiver_id} expired on {expires.isoformat()}")
    return waiver_id


def _validate_waivers(payload: dict[str, Any], surface_ids: set[str], today: dt.date) -> None:
    waivers = payload.get("waiver", [])
    if not isinstance(waivers, list):
        raise ValueError("waiver must be an array of tables")
    seen: set[str] = set()
    for index, raw in enumerate(waivers):
        seen.add(_validate_waiver(index, raw, surface_ids, seen, today))


def validate_manifest(payload: dict[str, Any], *, today: dt.date | None = None) -> None:
    _validate_header(payload)
    _validate_thresholds(payload)
    surfaces = _surface_index(payload)
    _validate_protected_surfaces(surfaces)
    _validate_waivers(payload, set(surfaces), today or dt.date.today())


def _decode_path(value: bytes) -> str:
    try:
        path = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("git diff contained a non-UTF-8 path") from exc
    if not path or "\n" in path or "\r" in path or "\x00" in path:
        raise ValueError("git diff contained an invalid path")
    return path


def _parse_name_status(payload: bytes) -> list[str]:
    fields = payload.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    paths: list[str] = []
    index = 0
    while index < len(fields):
        try:
            status = fields[index].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("git diff contained a non-ASCII status") from exc
        index += 1
        if not status or status[0] not in {"A", "C", "D", "M", "R", "T", "U", "X", "B"}:
            raise ValueError(f"git diff contained an unsupported status: {status!r}")
        path_count = 2 if status[0] in {"R", "C"} else 1
        if index + path_count > len(fields):
            raise ValueError("git diff name-status output was truncated")
        paths.extend(_decode_path(raw_path) for raw_path in fields[index : index + path_count])
        index += path_count
    return paths


def _git_paths(root: Path, base: str, head: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-status", "-z", "--find-renames", "--find-copies", f"{base}...{head}"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git diff failed: {error}")
    return _parse_name_status(completed.stdout)


def classify(payload: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    mapped: dict[str, list[str]] = {}
    selected_jobs: set[str] = {"ownership"}
    unknown: list[str] = []
    for path in sorted(set(paths)):
        matches = [surface for surface in payload["surface"] if any(fnmatch.fnmatchcase(path, p) for p in surface["paths"])]
        if matches:
            mapped[path] = [str(surface["id"]) for surface in matches]
            for surface in matches:
                selected_jobs.update(str(job) for job in surface["required_jobs"])
        elif path.startswith(HOT_PATH_PREFIXES):
            unknown.append(path)
    return {
        "schema_version": SCHEMA_VERSION,
        "changed_paths": sorted(set(paths)),
        "mapped_paths": mapped,
        "unknown_hot_paths": unknown,
        "selected_jobs": sorted(selected_jobs),
    }


def _manifest_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_outputs(selected_jobs: set[str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8") as handle:
        for job, output_name in JOB_OUTPUTS.items():
            handle.write(f"{output_name}={'true' if job in selected_jobs else 'false'}\n")


def _expect_invalid(payload: dict[str, Any], needle: str) -> None:
    try:
        validate_manifest(payload, today=dt.date(2026, 8, 26))
    except ValueError as exc:
        assert needle in str(exc)
    else:  # pragma: no cover
        raise AssertionError(f"invalid manifest was accepted: expected {needle!r}")


def _self_test() -> None:
    manifest = Path(__file__).resolve().parents[2] / "ci" / "rust-hotpath-ownership.toml"
    payload = _load(manifest)
    validate_manifest(payload, today=dt.date(2026, 8, 26))
    report = classify(payload, ["rust/crates/guard-runtime/src/main.rs", "README.md"])
    assert not report["unknown_hot_paths"] and "rust" in report["selected_jobs"]

    records = _parse_name_status(
        b"R100\x00src/codex_plugin_scanner/guard/runtime/hook_old.py\x00docs/old.py\x00"
        b"C100\x00README.md\x00rust/crates/guard-runtime/src/copied.rs\x00"
        b"D\x00rust/crates/guard-runtime/src/deleted.rs\x00A\x00docs/new.md\x00"
    )
    renamed = classify(payload, records)
    assert "src/codex_plugin_scanner/guard/runtime/hook_old.py" in renamed["mapped_paths"]
    assert "docs/old.py" in renamed["changed_paths"]
    assert "README.md" in renamed["changed_paths"]
    assert "rust/crates/guard-runtime/src/copied.rs" in renamed["mapped_paths"]
    assert "rust/crates/guard-runtime/src/deleted.rs" in renamed["mapped_paths"]
    assert not renamed["unknown_hot_paths"]

    expired = dict(payload)
    expired["waiver"] = [dict(payload["waiver"][0], created="2026-08-01", expires="2026-08-25")]
    _expect_invalid(expired, "expired")

    downgraded = dict(payload)
    downgraded["surface"] = [dict(surface) for surface in payload["surface"]]
    post_tool = next(surface for surface in downgraded["surface"] if surface["id"] == "post-tool-content-review")
    post_tool.update(authority="migration", python_authority_allowed=True, required_jobs=["ownership"])
    _expect_invalid(downgraded, "protected surface post-tool-content-review")

    weakened = dict(payload)
    weakened["thresholds"] = dict(payload["thresholds"], minimum_rust_decision_share=0.5)
    _expect_invalid(weakened, "cannot be lowered")

    with tempfile.TemporaryDirectory(prefix="guard-ownership-") as temporary:
        invalid = Path(temporary) / "invalid.toml"
        invalid.write_text("schema_version = 99\n", encoding="utf-8")
        _expect_invalid(_load(invalid), "schema_version")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("ci/rust-hotpath-ownership.toml"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--paths-file", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        _self_test()
        print(json.dumps({"schema_version": SCHEMA_VERSION, "self_test": "passed"}, sort_keys=True))
        return 0

    manifest = args.manifest.resolve()
    payload = _load(manifest)
    validate_manifest(payload)
    if args.paths_file is not None:
        paths = [line for line in args.paths_file.read_text(encoding="utf-8").splitlines() if line]
    else:
        paths = _git_paths(args.root.resolve(), args.base, args.head) if args.base else []
    report = classify(payload, paths)
    report["manifest_sha256"] = _manifest_digest(manifest)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    _write_outputs(set(report["selected_jobs"]))
    if report["unknown_hot_paths"]:
        print("Unmapped Rust hot-path files were changed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
