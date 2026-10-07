"""The RSA backport must run before CLI use and remain scoped in scanning."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_every_mcpb_cli_install_is_hardened_before_use() -> None:
    installs = 0
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        payload = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for job in payload.get("jobs", {}).values():
            for step in job.get("steps", []):
                command = step.get("run", "")
                if "npm ci --ignore-scripts --prefix .github/tools/mcpb-cli" not in command:
                    continue
                installs += 1
                install = command.index("npm ci --ignore-scripts --prefix .github/tools/mcpb-cli")
                harden = command.index("node .github/tools/mcpb-cli/harden-forge.cjs")
                assert install < harden
                if "MCPB_CLI=" in command:
                    assert harden < command.index("MCPB_CLI=")
    assert installs == 4


def test_backport_vex_does_not_filter_the_general_release_scan() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/security-gates.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["release-scan"]["steps"]
    commands = {step.get("name"): step.get("run", "") for step in steps}
    verify = commands["Verify the locked MCPB RSA backport"]
    tool_scan = commands["Scan the verified MCPB tool dependency"]
    general_scan = commands["Run Trivy on release surfaces"]
    assert "--vex-output" in verify
    assert "--vex /verified-openvex.json" in tool_scan
    assert '-v "$PWD/.github/tools/mcpb-cli:/workdir:ro"' in tool_scan
    assert "--vex" not in general_scan
    assert "--skip-files /workdir/.github/tools/mcpb-cli/package-lock.json" in general_scan
    assert "--exit-code 1" in tool_scan and "--exit-code 1" in general_scan
