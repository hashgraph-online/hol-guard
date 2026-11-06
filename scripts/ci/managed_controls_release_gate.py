from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
BATCH_DIRECTORY = ROOT / "docs" / "guard" / "managed-controls" / "batches"
CAPABILITY_MODULE = Path("src") / "codex_plugin_scanner" / "guard" / "runtime" / "managed_controls_posture_wire.py"
EXPECTED_BATCHES = tuple(range(3, 18))
EXPECTED_TASK_START = 31
EXPECTED_TASK_END = 255
REQUIRED_CAPABILITIES = frozenset(
    {
        "extension-catalog.v1",
        "extension-control-layer.v1",
        "policy-extension-targets.v1",
        "managed-controls-atomic-apply.v1",
    }
)


def _load_manifest(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid batch manifest {path}: {error}") from error
    if not isinstance(payload, Mapping):
        raise SystemExit(f"batch manifest must be an object: {path}")
    return payload


def _required_integer(value: object, *, label: str, path: Path) -> int:
    if type(value) is not int:
        raise SystemExit(f"{label} must be an integer in {path}")
    return value


def _validate_evidence(root: Path, manifest_path: Path, value: object) -> None:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"evidence must be a non-empty array in {manifest_path}")
    resolved_root = root.resolve()
    for item in value:
        if not isinstance(item, str) or not item:
            raise SystemExit(f"evidence path must be a non-empty string in {manifest_path}")
        relative_path = Path(item)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise SystemExit(f"evidence path must stay within the repository: {item}")
        try:
            evidence_path = (resolved_root / relative_path).resolve(strict=True)
        except OSError as error:
            raise SystemExit(f"missing evidence path: {item}") from error
        if not evidence_path.is_relative_to(resolved_root):
            raise SystemExit(f"evidence path must stay within the repository: {item}")
        if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
            raise SystemExit(f"evidence must be a non-empty regular file: {item}")


def _load_capabilities(root: Path) -> frozenset[str]:
    capability_path = root / CAPABILITY_MODULE
    if not capability_path.is_file():
        raise SystemExit(f"missing capability module: {CAPABILITY_MODULE}")
    try:
        module = ast.parse(capability_path.read_text(encoding="utf-8"), filename=str(capability_path))
    except (OSError, UnicodeError, SyntaxError) as error:
        raise SystemExit(f"invalid capability module {CAPABILITY_MODULE}: {error}") from error
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "MANAGED_CONTROLS_RUNTIME_CAPABILITIES"
            for target in statement.targets
        ):
            continue
        try:
            capabilities = ast.literal_eval(statement.value)
        except (ValueError, TypeError) as error:
            raise SystemExit("MANAGED_CONTROLS_RUNTIME_CAPABILITIES must be a literal sequence") from error
        if not isinstance(capabilities, (tuple, list, set, frozenset)) or not all(
            isinstance(item, str) for item in capabilities
        ):
            raise SystemExit("MANAGED_CONTROLS_RUNTIME_CAPABILITIES must be a sequence of strings")
        return frozenset(cast(tuple[str, ...] | list[str] | set[str] | frozenset[str], capabilities))
    raise SystemExit("missing MANAGED_CONTROLS_RUNTIME_CAPABILITIES advertisement")


def validate_release_gate(
    root: Path = ROOT,
    batch_directory: Path | None = None,
) -> None:
    directory = batch_directory or root / BATCH_DIRECTORY.relative_to(ROOT)
    if not directory.is_dir():
        raise SystemExit(f"missing batch manifest directory: {directory}")

    batches: dict[int, tuple[int, int, Path]] = {}
    for path in sorted(directory.glob("*.json")):
        payload = _load_manifest(path)
        batch = _required_integer(payload.get("batch"), label="batch", path=path)
        if batch in batches:
            raise SystemExit(f"duplicate batch {batch}: {batches[batch][2]} and {path}")
        if payload.get("target_branch") != "release/3.0":
            raise SystemExit(f"invalid target branch in {path}")
        task_range = payload.get("task_range")
        if not isinstance(task_range, Mapping):
            raise SystemExit(f"task_range must be an object in {path}")
        start = _required_integer(task_range.get("start"), label="task range start", path=path)
        end = _required_integer(task_range.get("end"), label="task range end", path=path)
        if start > end:
            raise SystemExit(f"task range is inverted in {path}: {start}-{end}")
        _validate_evidence(root, path, payload.get("evidence"))
        batches[batch] = (start, end, path)

    actual_batches = tuple(sorted(batches))
    if actual_batches != EXPECTED_BATCHES:
        raise SystemExit(f"managed controls Local batches incomplete: {list(actual_batches)}")

    expected_start = EXPECTED_TASK_START
    for batch in EXPECTED_BATCHES:
        start, end, path = batches[batch]
        if start != expected_start:
            raise SystemExit(
                f"task ranges must be contiguous at batch {batch} in {path}: expected {expected_start}, found {start}"
            )
        expected_start = end + 1
    if expected_start - 1 != EXPECTED_TASK_END:
        raise SystemExit(
            f"managed controls task coverage incomplete: expected end {EXPECTED_TASK_END}, found {expected_start - 1}"
        )

    missing = sorted(REQUIRED_CAPABILITIES - _load_capabilities(root))
    if missing:
        raise SystemExit(f"missing managed controls capabilities: {missing}")


def main() -> int:
    validate_release_gate()
    print("Managed Controls Local release gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
