from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_multi_device_lab_is_registered_and_isolated() -> None:
    compose = read("scripts/mdm/cloud-lab/docker-compose.yml")
    for service in ("cloud:", "proxy:", "device-a:", "device-b:", "device-c:", "orchestrator:"):
        assert service in compose
    assert "internal: true" in compose
    assert "condition: service_healthy" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "docker.sock" not in compose
    assert "ports:" not in compose


def test_workflow_runs_focused_and_docker_gates_with_pinned_actions() -> None:
    workflow = read(".github/workflows/mdm-cloud-integration-lab.yml")
    assert "tests/test_guard_mdm_cloud_lab_integration.py" in workflow
    assert "scripts/mdm/run-cloud-integration-lab.py" in workflow
    assert "nativeCertification" in workflow
    assert "down --volumes --remove-orphans" in workflow
    uses = re.findall(r"uses:\s*([^\s]+)", workflow)
    assert uses
    assert all("@" in value and len(value.rsplit("@", 1)[1]) == 40 for value in uses)


def test_prd_todo_and_takeaway_are_complete_and_native_boundary_is_explicit() -> None:
    prd = read("docs/guard/mdm-cloud-integration-lab-prd.md")
    todo = read("docs/guard/mdm-cloud-integration-lab-todo.md")
    prompt = read("docs/guard/mdm-cloud-integration-lab-takeaway-prompt.md")
    task_ids = re.findall(r"MDM-(\d{3})", todo)
    assert len(task_ids) == 360
    assert len(set(task_ids)) == 360
    task_lines = [line for line in todo.splitlines() if line.startswith("- [") and "MDM-" in line]
    assert sum(line.startswith("- [x]") for line in task_lines) == 336
    assert sum(line.startswith("- [ ]") for line in task_lines) == 24
    assert "native certification" in prd.lower()
    assert "not-evaluated" in prompt
    assert "arbitrary commands" in prompt
