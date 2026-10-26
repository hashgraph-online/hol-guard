from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci.managed_controls_release_gate import CAPABILITY_MODULE, validate_release_gate

CAPABILITIES = {
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
}


def _write_fixture(root: Path) -> Path:
    batch_directory = root / "docs/guard/managed-controls/batches"
    batch_directory.mkdir(parents=True)
    (root / "evidence.txt").write_text("verified\n", encoding="utf-8")
    capability_path = root / CAPABILITY_MODULE
    capability_path.parent.mkdir(parents=True)
    capability_path.write_text(
        f"MANAGED_CONTROLS_RUNTIME_CAPABILITIES = {tuple(sorted(CAPABILITIES))!r}\n",
        encoding="utf-8",
    )
    start = 31
    for batch in range(3, 18):
        payload = {
            "batch": batch,
            "evidence": ["evidence.txt"],
            "target_branch": "release/3.0",
            "task_range": {"start": start, "end": start + 14},
        }
        (batch_directory / f"{batch:02}.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        start += 15
    return batch_directory


def _manifest(directory: Path, batch: int) -> tuple[Path, dict[str, object]]:
    path = directory / f"{batch:02}.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_managed_controls_release_gate() -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/ci/managed_controls_release_gate.py"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_release_gate_accepts_complete_fixture(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    validate_release_gate(tmp_path, directory)


@pytest.mark.parametrize("payload", ["[]", "{"])
def test_release_gate_rejects_malformed_manifest(tmp_path: Path, payload: str) -> None:
    directory = _write_fixture(tmp_path)
    (directory / "03.json").write_text(payload, encoding="utf-8")
    with pytest.raises(SystemExit, match="manifest"):
        validate_release_gate(tmp_path, directory)


def test_release_gate_rejects_invalid_evidence_type(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    path, payload = _manifest(directory, 3)
    payload["evidence"] = "evidence.txt"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="non-empty array"):
        validate_release_gate(tmp_path, directory)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("batch", "3", "batch must be an integer"),
        ("task_range", [], "task_range must be an object"),
        ("task_range", {"start": True, "end": 45}, "task range start must be an integer"),
        ("task_range", {"start": 45, "end": 31}, "task range is inverted"),
    ],
)
def test_release_gate_rejects_invalid_manifest_field_types(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    directory = _write_fixture(tmp_path)
    path, payload = _manifest(directory, 3)
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match=message):
        validate_release_gate(tmp_path, directory)


def test_release_gate_rejects_traversal_and_empty_evidence(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    path, payload = _manifest(directory, 3)
    payload["evidence"] = ["../outside.txt"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="stay within"):
        validate_release_gate(tmp_path, directory)

    (tmp_path / "empty.txt").touch()
    payload["evidence"] = ["empty.txt"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="non-empty regular file"):
        validate_release_gate(tmp_path, directory)

    evidence_directory = tmp_path / "evidence-directory"
    evidence_directory.mkdir()
    payload["evidence"] = ["evidence-directory"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="non-empty regular file"):
        validate_release_gate(tmp_path, directory)


def test_release_gate_rejects_duplicate_batches(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    duplicate = json.loads((directory / "03.json").read_text(encoding="utf-8"))
    (directory / "duplicate.json").write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicate batch 3"):
        validate_release_gate(tmp_path, directory)


def test_release_gate_rejects_non_contiguous_task_ranges(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    path, payload = _manifest(directory, 4)
    task_range = payload["task_range"]
    assert isinstance(task_range, dict)
    task_range["start"] = 47
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="must be contiguous"):
        validate_release_gate(tmp_path, directory)


def test_release_gate_reads_production_runtime_capability_advertisement(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    capability_path = tmp_path / CAPABILITY_MODULE
    capability_path.write_text(
        "# extension-catalog.v1 extension-control-layer.v1 "
        "policy-extension-targets.v1 managed-controls-atomic-apply.v1\n"
        "MANAGED_CONTROLS_RUNTIME_CAPABILITIES = ()\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="missing managed controls capabilities"):
        validate_release_gate(tmp_path, directory)


def test_release_gate_reports_missing_capability_module(tmp_path: Path) -> None:
    directory = _write_fixture(tmp_path)
    capability_path = tmp_path / CAPABILITY_MODULE
    capability_path.unlink()
    with pytest.raises(SystemExit, match="missing capability module"):
        validate_release_gate(tmp_path, directory)
