"""Token grants stay explicit and local to the jobs that consume them."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.check_privileged_workflows import validate_privileged_workflows

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACTION = "actions/checkout@0123456789abcdef0123456789abcdef01234567"


def _write_workflow(root: Path, header: str, job_permissions: str = "") -> Path:
    path = root / ".github/workflows/fixture.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{header}\njobs:\n  test:\n{job_permissions}    steps:\n      - uses: {PINNED_ACTION}\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "header",
    ["", "permissions:", "permissions: null", "permissions: []", "permissions: read-all", "permissions: write-all"],
)
def test_workflow_requires_explicit_named_permissions(tmp_path: Path, header: str) -> None:
    _write_workflow(tmp_path, header, "    permissions: {}\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["permission-map-required"]
    assert violations[0].job == "<workflow>"


@pytest.mark.parametrize(
    "scope",
    [
        "contents",
        "packages",
        "actions",
        "security-events",
        "id-token",
        "attestations",
        "artifact-metadata",
        "pull-requests",
        "issues",
    ],
)
def test_workflow_write_grants_are_rejected_even_with_read_only_job(tmp_path: Path, scope: str) -> None:
    _write_workflow(tmp_path, f"permissions:\n  {scope}: write", "    permissions:\n      contents: read\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["workflow-write-permission"]
    assert scope in violations[0].message


@pytest.mark.parametrize("value", ["read-all", "write-all", "null", "[]", "true"])
def test_job_wildcard_and_malformed_grants_are_rejected(tmp_path: Path, value: str) -> None:
    _write_workflow(tmp_path, "permissions: {}", f"    permissions: {value}\n")
    violations = validate_privileged_workflows(tmp_path)
    assert [item.code for item in violations] == ["permission-map-required"]
    assert violations[0].job == "test"


@pytest.mark.parametrize(
    "entry",
    ["contents: true", "contents: null", "contents: [read]", "contents: admin", '"": read', "123: read"],
)
@pytest.mark.parametrize("job_level", [False, True])
def test_invalid_scope_values_fail_closed(tmp_path: Path, entry: str, job_level: bool) -> None:
    header = "permissions: {}" if job_level else f"permissions:\n  {entry}"
    job = f"    permissions:\n      {entry}\n" if job_level else ""
    _write_workflow(tmp_path, header, job)
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["permission-invalid"]


@pytest.mark.parametrize(
    "header", ["permissions: {}", "permissions:\n  contents: read", "permissions:\n  contents: none"]
)
def test_read_only_or_empty_defaults_are_allowed(tmp_path: Path, header: str) -> None:
    _write_workflow(tmp_path, header)
    assert validate_privileged_workflows(tmp_path) == ()


def test_explicit_job_grants_do_not_inherit_root_scopes(tmp_path: Path) -> None:
    path = _write_workflow(tmp_path, "permissions:\n  contents: read", "    permissions: {}\n")
    path.write_text(path.read_text().replace(PINNED_ACTION, "actions/checkout@v4"))
    assert validate_privileged_workflows(tmp_path) == ()


def test_job_write_grants_still_enforce_action_pins(tmp_path: Path) -> None:
    path = _write_workflow(tmp_path, "permissions: {}", "    permissions:\n      contents: write\n")
    path.write_text(path.read_text().replace(PINNED_ACTION, "actions/checkout@v4"))
    assert [item.code for item in validate_privileged_workflows(tmp_path)] == ["action-not-commit-pinned"]


@pytest.mark.parametrize("text", ["", "null", "[]", "workflow", "[broken"])
def test_non_mapping_or_unreadable_workflow_fails_closed(tmp_path: Path, text: str) -> None:
    path = _write_workflow(tmp_path, "permissions: {}")
    path.write_text(text, encoding="utf-8")
    violations = validate_privileged_workflows(tmp_path)
    assert len(violations) == 1
    assert violations[0].code in {"workflow-invalid", "workflow-unreadable"}


@pytest.mark.parametrize(
    ("filename", "job", "permissions"),
    [
        ("finish-extension-authority-stability.yml", "finish", {"contents": "write"}),
        (
            "guarded-repository.yml",
            "scan",
            {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
                "artifact-metadata": "write",
                "security-events": "write",
            },
        ),
        ("extension-claim-notice.yml", "notify", {"contents": "read", "pull-requests": "write"}),
        ("publish-mcp-registry.yml", "publish", {"contents": "read", "id-token": "write"}),
        (
            "scorecard.yml",
            "scorecard",
            {"actions": "read", "contents": "read", "id-token": "write", "security-events": "write"},
        ),
    ],
)
def test_writer_workflows_start_empty_and_preserve_needed_job_grants(
    filename: str, job: str, permissions: dict[str, str]
) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"))
    assert workflow["permissions"] == {}
    assert workflow["jobs"][job]["permissions"] == permissions


def test_security_gate_runs_permission_policy_on_pull_requests() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/security-gates.yml").read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 loader represents the GitHub Actions `on` key as True.
    assert "pull_request" in workflow[True]
    steps = workflow["jobs"]["privileged-workflow-policy"]["steps"]
    assert any(step.get("run") == "uv run --no-sync python scripts/check_privileged_workflows.py" for step in steps)
