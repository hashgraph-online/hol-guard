from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _REPOSITORY_ROOT / "scripts" / "guard_network_remediation_proof.py"
_MANIFEST_PATH = _REPOSITORY_ROOT / "ci" / "guard-network-remediation-proof.v1.json"
_WORKFLOW_PATH = _REPOSITORY_ROOT / ".github" / "workflows" / "guard-network-remediation-proof.yml"


def test_network_remediation_proof_compares_the_exact_installed_version() -> None:
    workflow = _WORKFLOW_PATH.read_text(encoding="utf-8")

    assert 'test "$INSTALLED_VERSION" = "$EXPECTED_VERSION"' in workflow
    assert "3.0.0a" not in workflow


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("guard_network_remediation_proof", _SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("proof script must be importable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest() -> dict[str, object]:
    payload = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def _tasks(payload: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], payload["tasks"])


def test_network_remediation_proof_manifest_is_valid_and_bounded() -> None:
    module = _load_module()
    errors = module.validate_proof_manifest(_manifest(), repository_root=_REPOSITORY_ROOT)

    assert errors == ()
    report = module.build_proof_report(_manifest(), repository_root=_REPOSITORY_ROOT)
    assert report["task_counts"] == {
        "total": 19,
        "complete": 6,
        "incomplete": 13,
        "partial": 10,
        "blocked_or_not_ready": 3,
    }
    assert report["ready"] is False
    assert report["release_authorized"] is False
    assert report["advertised_capabilities"] == []
    assert report["production_ready_capabilities"] == []
    assert report["raw_domain_storage"] is False
    assert report["private_artifact_hits"] == []
    assert report["reason"] == cast(dict[str, object], _manifest()["closure"])["reason"]
    assert "--require-ready" in cast(str, report["recommended_action"])


def test_network_remediation_tasks_are_exact_and_ordered() -> None:
    module = _load_module()
    identifiers = [task["id"] for task in _tasks(_manifest())]

    assert identifiers == list(module.TASK_IDS)
    assert identifiers[0] == "REM-121"
    assert identifiers[-1] == "REM-139"


def test_network_remediation_proof_rejects_false_ready_state() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    closure = cast(dict[str, object], payload["closure"])
    closure["ready"] = True
    closure["verdict"] = "ready"

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert "closure cannot be ready while any task remains incomplete" in errors
    assert "closure cannot be ready without an advertised production capability" in errors


def test_network_remediation_proof_rejects_completed_task_with_blocker() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    task = _tasks(payload)[0]
    task["complete"] = True
    task["outcome"] = "passed"

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert "REM-121: completed tasks must pass without blockers" in errors


def test_network_remediation_proof_rejects_empty_evidence() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    _tasks(payload)[0]["evidence"] = []

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert "REM-121.evidence must contain at least one entry" in errors


def test_network_remediation_proof_rejects_unrelated_existing_evidence() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    task = next(item for item in _tasks(payload) if item["id"] == "REM-130")
    task["evidence"] = ["README.md"]

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert "REM-130.evidence must match the task-specific evidence contract" in errors


def test_network_remediation_proof_rejects_raw_domain_storage() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    privacy = cast(dict[str, object], payload["privacy"])
    privacy["raw_domain_storage"] = True

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert "raw_domain_storage must remain disabled" in errors


def test_network_remediation_require_ready_exits_nonzero_without_overstating_protection() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT_PATH),
            "--repository-root",
            str(_REPOSITORY_ROOT),
            "--require-ready",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    report = json.loads(result.stdout)
    assert report["verdict"] == "not-ready"
    assert report["advertised_capabilities"] == []
    assert report["release_authorized"] is False
    assert "--require-ready" in report["recommended_action"]
    assert result.stderr == ""


def test_network_remediation_proof_rejects_missing_evidence_path() -> None:
    module = _load_module()
    payload = copy.deepcopy(_manifest())
    task = _tasks(payload)[0]
    task["evidence"] = ["tests/does-not-exist.py"]

    errors = module.validate_proof_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert any("does not exist" in error for error in errors)


def test_network_remediation_proof_rejects_external_evidence_symlink(tmp_path: Path) -> None:
    module = _load_module()
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private host evidence", encoding="utf-8")
    (repository_root / "evidence.txt").symlink_to(outside)

    with pytest.raises(module.ProofValidationError, match="non-symlink regular file"):
        module._repository_file(repository_root, "evidence.txt", field="REM-121.evidence[0]")


def test_network_remediation_proof_uses_authoritative_reachability_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    def invalid_manifest(_payload: object, *, repository_root: Path) -> tuple[str, ...]:
        assert repository_root == _REPOSITORY_ROOT
        return ("synthetic reachability failure",)

    monkeypatch.setattr(module, "validate_reachability_manifest", invalid_manifest)

    with pytest.raises(module.ProofValidationError, match="synthetic reachability failure"):
        module._capability_summary(_REPOSITORY_ROOT)


@pytest.mark.parametrize("task_id", ["REM-127", "REM-128", "REM-139"])
def test_network_remediation_blocked_tasks_keep_exact_blockers(task_id: str) -> None:
    task = next(item for item in _tasks(_manifest()) if item["id"] == task_id)

    assert task["complete"] is False
    assert task["outcome"] in {"blocked", "not-ready"}
    assert cast(list[str], task["blockers"])
