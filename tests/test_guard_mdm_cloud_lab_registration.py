from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_multi_device_lab_is_registered_isolated_and_non_root() -> None:
    compose_text = read("scripts/mdm/cloud-lab/docker-compose.yml")
    compose = yaml.safe_load(compose_text)
    services = compose["services"]
    for service in (
        "volume-init",
        "cloud",
        "proxy",
        "device-a",
        "device-b",
        "device-c",
        "device-d",
        "orchestrator",
    ):
        assert service in services
    assert compose["networks"]["mdm-lab"]["internal"] is True
    assert "ports:" not in compose_text
    assert "docker.sock" not in compose_text
    assert "no-new-privileges:true" in compose_text
    assert "cap_drop:" in compose_text and "- ALL" in compose_text
    assert "lab-artifacts:/artifacts" in compose_text
    for service in ("cloud", "proxy", "device-a", "device-b", "device-c", "device-d", "orchestrator"):
        assert str(services[service].get("user")) == "${HOL_MDM_LAB_UID:-10001}:${HOL_MDM_LAB_GID:-10001}"
    dockerfile = read("scripts/mdm/cloud-lab/Dockerfile")
    assert "USER 10001:10001" in dockerfile
    assert "@sha256:" in dockerfile


def test_runner_executes_restart_phase_and_exports_named_volume_evidence() -> None:
    runner = read("scripts/mdm/run-cloud-integration-lab.py")
    assert '"--phase",\n        "initial"' in runner
    assert '"--phase",\n        "restart"' in runner
    assert '"restart", *SERVICES' in runner
    assert '"/bin/cat"' in runner
    assert "mdm-cloud-integration-report.json.sha256" in runner
    assert "Draft202012Validator" in runner
    assert "len(steps) < 50" in runner
    assert 'down", "--volumes", "--remove-orphans' in runner


def test_workflow_runs_focused_docker_and_security_gates_with_pinned_actions() -> None:
    workflow = read(".github/workflows/mdm-cloud-integration-lab.yml")
    assert "tests/test_guard_mdm_cloud_lab_integration.py" in workflow
    assert "tests/test_guard_mdm_cloud_hardening.py" in workflow
    assert "scripts/mdm/run-cloud-integration-lab.py" in workflow
    assert "nativeCertification" in workflow
    assert "mdm-cloud-integration-report.json.sha256" in workflow
    assert "Trivy" in workflow or "trivy" in workflow
    assert "down --volumes --remove-orphans" in workflow
    uses = re.findall(r"uses:\s*([^\s]+)", workflow)
    assert uses
    assert all("@" in value and len(value.rsplit("@", 1)[1]) == 40 for value in uses)


def test_report_schema_accepts_only_bounded_honest_result_shape() -> None:
    schema = json.loads(read("docs/guard/schemas/mdm-cloud-lab-report-v1.schema.json"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["nativeCertification"]["properties"]["outcome"]["const"] == "not-evaluated"
    assert schema["properties"]["steps"]["items"]["additionalProperties"] is False
