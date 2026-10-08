from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
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


def assert_pinned_actions(document: str, ancestry: frozenset[str] = frozenset()) -> None:
    """Require immutable external actions, including dependencies of local composites."""
    uses = re.findall(r"uses:\s*([^\s]+)", document)
    assert uses
    for value in uses:
        if value.startswith("./"):
            assert re.fullmatch(r"\./\.github/actions/[a-z0-9-]+", value)
            assert value not in ancestry, "local action dependency cycle"
            local = read(value[2:] + "/action.yml")
            action = yaml.safe_load(local)
            assert isinstance(action, dict), "local action must be a mapping"
            runs = action.get("runs")
            assert isinstance(runs, dict), "local action must declare runs"
            assert runs.get("using") == "composite", "local action must be composite"
            assert_pinned_actions(local, ancestry | {value})
        else:
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value), value


def test_workflow_runs_focused_docker_and_security_gates_with_pinned_actions() -> None:
    workflow = read(".github/workflows/mdm-cloud-integration-lab.yml")
    assert "tests/test_guard_mdm_cloud_lab_integration.py" in workflow
    assert "tests/test_guard_mdm_cloud_hardening.py" in workflow
    assert "scripts/mdm/run-cloud-integration-lab.py" in workflow
    assert "nativeCertification" in workflow
    assert "mdm-cloud-integration-report.json.sha256" in workflow
    assert "Trivy" in workflow or "trivy" in workflow
    assert "down --volumes --remove-orphans" in workflow
    assert_pinned_actions(workflow)


def test_report_schema_accepts_only_bounded_honest_result_shape() -> None:
    schema = json.loads(read("docs/guard/schemas/mdm-cloud-lab-report-v1.schema.json"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["nativeCertification"]["properties"]["outcome"]["const"] == "not-evaluated"
    assert schema["properties"]["steps"]["items"]["additionalProperties"] is False


@pytest.mark.parametrize("reference", ["v4", "main", "z" * 40])
def test_local_composite_cannot_hide_unpinned_external_actions(monkeypatch, reference: str) -> None:
    """A local action is not an exemption from third-party action pinning."""
    document = "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + reference + "\n"
    monkeypatch.setitem(assert_pinned_actions.__globals__, "read", lambda _path: document)
    with pytest.raises(AssertionError):
        assert_pinned_actions("steps:\n  - uses: ./.github/actions/stage-command-projections\n")


def test_local_composite_cycles_cannot_skip_dependency_validation(monkeypatch) -> None:
    """Reject cyclic local action declarations instead of silently skipping them."""
    document = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/stage-command-projections\n"
    monkeypatch.setitem(assert_pinned_actions.__globals__, "read", lambda _path: document)
    with pytest.raises(AssertionError, match="dependency cycle"):
        assert_pinned_actions(document)


@pytest.mark.parametrize("document", ["", "[]", "runs: null", "runs: {}"])
def test_malformed_local_action_is_rejected_explicitly(monkeypatch, document: str) -> None:
    monkeypatch.setitem(assert_pinned_actions.__globals__, "read", lambda _path: document)
    with pytest.raises(AssertionError, match="local action"):
        assert_pinned_actions("steps:\n  - uses: ./.github/actions/stage-command-projections\n")
