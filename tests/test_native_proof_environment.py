"""Installed proof setup clears diagnostic overrides without hiding failures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ci/native-proof-environment.sh"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="The sourced proof environment runs in Bash")

# The established installed-proof exclusion contract, independent of the helper.
OVERRIDES = frozenset(
    [
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_HOOK_FAST_PATH",
        "HOL_GUARD_NATIVE_MODE",
        "HOL_GUARD_NATIVE_ORACLE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_HOOK_FAST_PATH_SHADOW",
        "HOL_GUARD_HOOK_SOURCE_REF",
        "HOL_GUARD_HOOK_BINARY",
        "HOL_GUARD_FAST_PATH",
        "HOL_GUARD_BINARY",
        "HOL_GUARD_ORACLE",
        "HOL_GUARD_DIAGNOSTIC",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_KEYRING_FILE",
        "HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON",
        "HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST",
        "GUARD_NATIVE",
        "GUARD_NATIVE_BINARY",
        "GUARD_NATIVE_MODE",
        "GUARD_NATIVE_ORACLE",
        "GUARD_NATIVE_DIAGNOSTIC",
        "GUARD_HOOK_FAST_PATH",
        "GUARD_HOOK_FAST_PATH_SHADOW",
        "GUARD_HOOK_SOURCE_REF",
        "GUARD_HOOK_BINARY",
        "GUARD_FAST_PATH",
        "GUARD_BINARY",
        "GUARD_ORACLE",
        "GUARD_DIAGNOSTIC",
        "GUARD_TEST_MODE",
        "GUARD_TEST_KEYRING_FILE",
        "GUARD_TEST_SYNC_AUTH_CONTEXT_JSON",
        "GUARD_PYTEST_DURATION_OUTPUT",
        "PYTEST_CURRENT_TEST",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTHONPATH",
    ]
)


def test_source_clears_every_override_and_preserves_build_configuration() -> None:
    preserved = {
        "PATH": os.defpath,
        "HOL_GUARD_BUILD_SHA": "a" * 40,
        "HOL_GUARD_PACKAGE_VERSION": "3.2.0",
        "NATIVE_STOP_DIAGNOSTIC_PATH": "native-stop-diagnostic.json",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX": "b" * 64,
    }
    script = 'source "$1"\n"$2" -I -c \'import json, os; print(json.dumps(dict(os.environ)))\''
    result = subprocess.run(
        [BASH, "--noprofile", "--norc", "-euo", "pipefail", "-c", script, "proof", str(HELPER), sys.executable],
        env={**preserved, **dict.fromkeys(OVERRIDES, "test-override")},
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    environment = json.loads(result.stdout)
    assert not OVERRIDES.intersection(environment)
    assert {key: environment[key] for key in preserved} == preserved


@pytest.mark.parametrize("exit_code", [0, 23])
def test_source_preserves_installed_proof_exit_status(exit_code: int) -> None:
    script = (
        'source "$1"\n"$2" -I -c \'import sys; raise SystemExit(int(sys.argv[1]))\' "$3"\nprintf \'proof-finished\'\n'
    )
    result = subprocess.run(
        [
            BASH,
            "--noprofile",
            "--norc",
            "-euo",
            "pipefail",
            "-c",
            script,
            "proof",
            str(HELPER),
            sys.executable,
            str(exit_code),
        ],
        env={"PATH": os.defpath},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == exit_code
    assert result.stdout == ("proof-finished" if exit_code == 0 else "")
