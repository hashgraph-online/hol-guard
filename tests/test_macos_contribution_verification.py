"""Exercise macOS contribution verification without compiling a fixture runtime."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts/ci/build-native-wheel-macos.sh"
BASE_SHA = "a" * 40
TARGETS = ("x86_64-apple-darwin", "aarch64-apple-darwin")


def test_macos_verification_receives_only_the_pull_request_base_sha() -> None:
    """Keep the comparison identity scoped to the pull-request build step."""
    jobs = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text()))["jobs"]
    build = next(step for step in jobs["macos-build"]["steps"] if step.get("name", "").startswith("Build and assemble"))
    assert build["env"]["NATIVE_PR_BASE_SHA"] == (
        "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || '' }}"
    )
    assert build["env"]["HOL_GUARD_BUILD_SHA"] == "${{ github.sha }}"
    assert not build.get("continue-on-error", False)


def _executable(path: Path, text: str) -> None:
    """Create an executable fixture script under the temporary test root."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _build(
    tmp_path: Path, target: str, base_sha: str | None, *, verifier_status: int = 0
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Execute the macOS helper with deterministic compiler and packaging fixtures."""
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("The macOS build helper executes in Bash")
    if sys.version_info < (3, 11):
        pytest.skip("The native wheel workflow uses Python 3.12 with tomllib")
    bins = tmp_path / "bin"
    bins.mkdir()
    (bins / "python").symlink_to(sys.executable)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    _executable(bins / "cargo", "#!/bin/sh\nexit 0\n")
    _executable(bins / "uv", "#!/bin/sh\nexit 0\n")
    _executable(bins / "jq", "#!/bin/sh\nprintf '%s\\n' '{}'\n")
    target_dir = "rust/target/x86_64-apple-darwin" if target == TARGETS[0] else "rust/target"
    _executable(
        tmp_path / target_dir / "release/hol-guard-runtime",
        '#!/bin/sh\nprintf \'{"rule_digest":"fixture-digest"}\\n\'\n',
    )
    _executable(
        tmp_path / target_dir / "release/guard-command-source",
        '#!/bin/sh\nprintf \'{"implementation_digest":"fixture","base_program_digest":"fixture"}\\n\'\n',
    )
    scripts = tmp_path / "scripts"
    (scripts / "ci").mkdir(parents=True)
    (scripts / "ci/verify_native_command_program.py").write_text(
        "import json, os, sys\nfrom pathlib import Path\n"
        "Path('verification.json').write_text(json.dumps(sys.argv[1:]))\n"
        "raise SystemExit(int(os.environ['VERIFIER_STATUS']))\n",
        encoding="utf-8",
    )
    (scripts / "build_native_command_program.py").write_text(
        "from pathlib import Path\nPath('legacy-verification').touch()\n", encoding="utf-8"
    )
    (scripts / "build_native_hol_guard_wheel.py").write_text(
        "from pathlib import Path\nPath('packaged').touch()\n", encoding="utf-8"
    )
    env = {
        **os.environ,
        "PATH": f"{bins}{os.pathsep}{os.environ['PATH']}",
        "TARGET": target,
        "PLATFORM_TAG": "fixture-platform",
        "HOL_GUARD_BUILD_SHA": "b" * 40,
        "VERIFIER_STATUS": str(verifier_status),
    }
    env.pop("NATIVE_PR_BASE_SHA", None)
    if base_sha is not None:
        env["NATIVE_PR_BASE_SHA"] = base_sha
    result = subprocess.run(
        [bash, str(BUILD_SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15, check=False
    )
    recorded = tmp_path / "verification.json"
    return result, json.loads(recorded.read_text()) if recorded.exists() else []


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("base_sha", [None, "", BASE_SHA, BASE_SHA.upper()])
def test_macos_routes_verification_through_the_shared_wrapper(
    tmp_path: Path, target: str, base_sha: str | None
) -> None:
    """Route both macOS targets through the shared verifier with optional PR identity."""
    result, arguments = _build(tmp_path, target, base_sha)
    assert result.returncode == 0, result.stderr
    target_dir = "rust/target/x86_64-apple-darwin" if target == TARGETS[0] else "rust/target"
    expected = ["--compiler", f"{target_dir}/release/guard-command-source"]
    if base_sha:
        expected += ["--changed-from", base_sha]
    assert arguments == expected
    assert not (tmp_path / "legacy-verification").exists()
    assert (tmp_path / "packaged").exists()


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("base_sha", [None, BASE_SHA])
def test_failed_source_verification_prevents_packaging(tmp_path: Path, target: str, base_sha: str | None) -> None:
    """Preserve verifier failures without producing a native wheel."""
    result, arguments = _build(tmp_path, target, base_sha, verifier_status=37)
    assert result.returncode == 37, result.stderr
    assert arguments
    assert not (tmp_path / "packaged").exists()


@pytest.mark.parametrize("base_sha", ["main", "-invalid", "a" * 39, "g" * 40, BASE_SHA + "\n"])
def test_invalid_base_identity_cannot_relax_verification(tmp_path: Path, base_sha: str) -> None:
    """Reject malformed comparison identities before verification or packaging."""
    result, arguments = _build(tmp_path, TARGETS[1], base_sha)
    assert result.returncode != 0
    assert "must be a full Git commit SHA" in result.stderr
    assert not arguments
    assert not (tmp_path / "packaged").exists()
