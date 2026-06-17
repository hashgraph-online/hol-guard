"""Regression checks for the GitHub Action bundle and Marketplace packaging."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_action_yaml_is_valid_mapping() -> None:
    yaml = pytest.importorskip("yaml")

    action_text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(action_text)
    assert isinstance(parsed, dict)
    assert parsed["runs"]["using"] == "composite"


def test_action_metadata_includes_marketplace_branding_and_pypi_install() -> None:
    action_text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")

    assert 'name: "HOL AI Plugin Scanner"' in action_text
    assert "branding:" in action_text
    assert 'icon: "check-circle"' in action_text
    assert 'color: "blue"' in action_text
    assert "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405" in action_text
    assert 'python3 -P -m pip install "pypi-attestations==' in action_text
    assert "install_source:" in action_text
    assert 'default: "pypi"' in action_text
    assert "INSTALL_SOURCE: ${{ inputs.install_source }}" in action_text
    assert "install_cisco:" in action_text
    assert "INSTALL_CISCO: ${{ inputs.install_cisco }}" in action_text
    assert 'PYTHONNOUSERSITE: "1"' in action_text
    assert 'PYTHONSAFEPATH: "1"' in action_text
    assert 'ACTION_RUNTIME_ROOT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"' in action_text
    assert 'ACTION_RUNTIME_DIR="$(mktemp -d "$ACTION_RUNTIME_ROOT/hol-guard-action-XXXXXX")"' in action_text
    assert 'trap \'cd "$ACTION_RUNTIME_ROOT" 2>/dev/null || cd /; rm -rf "$ACTION_RUNTIME_DIR"\' EXIT' in action_text
    assert 'cd "$ACTION_RUNTIME_DIR"' in action_text
    assert 'if [ "$INSTALL_CISCO" = "true" ]; then' in action_text
    assert 'if [ "$INSTALL_SOURCE" = "local" ]; then' in action_text
    assert "install_source=local requires the hol-guard source checkout" in action_text
    assert 'python3 -P -m pip install "$LOCAL_SOURCE[cisco]"' in action_text
    assert 'elif [ "$INSTALL_SOURCE" = "pypi" ]; then' in action_text
    assert (
        'python3 -P -m pip download --only-binary=:all: --no-deps --dest "$DIST_DIR" '
        '"plugin-scanner==${SCANNER_VERSION}"'
    ) in action_text
    assert "scanner-sha256.txt" in action_text
    assert 'SCANNER_SHA256_FILE="$GITHUB_ACTION_PATH/scanner-sha256.txt"' in action_text
    assert 'echo "Downloaded scanner wheel SHA256 does not match scanner-sha256.txt."' in action_text
    assert "python3 -P -m pypi_attestations verify pypi" in action_text
    assert '"$WHEEL_PATH"' in action_text
    assert 'python3 -P -m pip install "$WHEEL_PATH"' in action_text
    assert 'python3 -P -m pip install "cisco-ai-skill-scanner==${CISCO_VERSION}"' in action_text
    assert "scanner-version.txt" in action_text
    scanner_version = (ROOT / "action" / "scanner-version.txt").read_text(encoding="utf-8").strip()
    scanner_sha256 = (ROOT / "action" / "scanner-sha256.txt").read_text(encoding="utf-8").strip()
    assert scanner_version not in {"", "0.0.0"}
    assert scanner_sha256 != "0" * 64
    assert "cisco-version.txt" in action_text
    assert "pypi-attestations-version.txt" in action_text
    assert 'SCANNER_REPOSITORY="https://github.com/hashgraph-online/hol-guard"' in action_text
    assert "python3 -P -m codex_plugin_scanner.action_runner" in action_text
    assert "github/codeql-action/upload-sarif@" in action_text


def test_action_steps_enable_python_safe_path() -> None:
    yaml = pytest.importorskip("yaml")

    parsed = yaml.safe_load((ROOT / "action" / "action.yml").read_text(encoding="utf-8"))
    steps = parsed["runs"]["steps"]
    install_step = next(step for step in steps if step["name"] == "Install scanner")
    scan_step = next(step for step in steps if step["name"] == "Run scanner")

    assert install_step["env"]["PYTHONNOUSERSITE"] == "1"
    assert install_step["env"]["PYTHONSAFEPATH"] == "1"
    assert 'cd "$ACTION_RUNTIME_DIR"' in install_step["run"]
    assert "python3 -P -m pip install" in install_step["run"]
    assert scan_step["env"]["PYTHONNOUSERSITE"] == "1"
    assert scan_step["env"]["PYTHONSAFEPATH"] == "1"
    assert scan_step["run"] == "python3 -P -m codex_plugin_scanner.action_runner"


def test_python_safe_path_blocks_workspace_module_shadowing(tmp_path: Path) -> None:
    if sys.version_info < (3, 11):
        pytest.skip("python -P requires Python 3.11+")

    module_name = "shadowdemo_pkg"
    trusted_root = tmp_path / "trusted-root"
    trusted_package = trusted_root / module_name
    trusted_package.mkdir(parents=True)
    (trusted_package / "__main__.py").write_text(
        "print('trusted-module')\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    shadow_package = workspace / module_name
    shadow_package.mkdir(parents=True)
    (shadow_package / "__main__.py").write_text(
        "raise SystemExit('workspace-shadowed')\n",
        encoding="utf-8",
    )
    hijacked_env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONSAFEPATH", "PYTHONNOUSERSITE"}
    }
    hijacked_env["PYTHONPATH"] = str(trusted_root)

    hijacked = subprocess.run(
        [sys.executable, "-m", module_name],
        cwd=workspace,
        env=hijacked_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert hijacked.returncode != 0
    assert "workspace-shadowed" in f"{hijacked.stdout}{hijacked.stderr}"

    protected = subprocess.run(
        [sys.executable, "-P", "-m", module_name],
        cwd=workspace,
        env=hijacked_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert protected.returncode == 0
    assert "trusted-module" in protected.stdout
    assert "workspace-shadowed" not in f"{protected.stdout}{protected.stderr}"


def test_publish_action_repo_workflow_syncs_action_repository() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish-action-repo.yml").read_text(encoding="utf-8")

    assert "Publish GitHub Action Repository" in workflow_text
    assert "ACTION_REPO_TOKEN" in workflow_text
    assert "ACTION_REPOSITORY: hashgraph-online/ai-plugin-scanner-action" in workflow_text
    assert "retrying in 30s" in workflow_text
    assert "Validate publication credentials" in workflow_text
    assert "Resolve published scanner version" in workflow_text
    assert "Compute scanner wheel SHA256" in workflow_text
    assert 'workflows: ["Publish to PyPI"]' in workflow_text
    assert 'cp "${GITHUB_WORKSPACE}/action/action.yml" action.yml' in workflow_text
    assert "printf '%s\\n' \"${{ steps.scanner_version.outputs.version }}\" > scanner-version.txt" in workflow_text
    assert "printf '%s\\n' \"${{ steps.scanner_sha256.outputs.sha256 }}\" > scanner-sha256.txt" in workflow_text
    assert "git push origin HEAD:main" in workflow_text
    assert "git push origin refs/tags/v1 --force" in workflow_text


def test_action_bundle_docs_reference_hol_guard_source() -> None:
    action_readme = (ROOT / "action" / "README.md").read_text(encoding="utf-8")

    assert "hashgraph-online/ai-plugin-scanner-action@v1" in action_readme
    assert "hashgraph-online/hol-guard/tree/main/action" in action_readme
    assert "publish-action-repo.yml" in action_readme
