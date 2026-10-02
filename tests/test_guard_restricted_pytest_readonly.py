"""Real OS-boundary checks for unattended, read-only pytest execution."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_pytest import (
    RestrictedPytestError,
    prepare_restricted_pytest,
    run_restricted_pytest,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    PYTEST_READ_ONLY_PROFILE_VERSION,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
)


def test_readonly_evidence_does_not_claim_workspace_writes() -> None:
    plan = prepare_restricted_pytest(
        [sys.executable, "-m", "pytest", "-q"],
        workspace=Path.cwd(),
        platform="darwin",
        backend_executable=Path("/usr/bin/true"),
        read_only_workspace=True,
    )
    evidence = plan.to_evidence()
    assert evidence["profile_version"] == PYTEST_READ_ONLY_PROFILE_VERSION
    assert evidence["writes"] == ["private-temporary-directory"]
    assert "workspace-credential-read" in evidence["denied_capabilities"]
    assert "workspace-write" in evidence["denied_capabilities"]


def test_readonly_rejects_backend_without_credential_filtering() -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-m", "pytest"],
            workspace=Path.cwd(),
            platform="linux",
            backend_executable=Path("/usr/bin/true"),
            read_only_workspace=True,
        )
    assert error.value.reason_code == PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS Seatbelt backend")
@pytest.mark.parametrize("credential_name", (".env", ".ENV.local", ".aws/credentials", "private-key.pem"))
def test_real_readonly_runner_blocks_workspace_secrets_and_destruction(credential_name: str) -> None:
    workspace = Path.cwd().resolve()
    with tempfile.TemporaryDirectory(prefix=".guard-readonly-", dir=workspace) as project_text:
        project = Path(project_text)
        configuration = project / "pytest.ini"
        configuration.write_text("[pytest]\n", encoding="utf-8")
        secret = project / credential_name
        secret.parent.mkdir(parents=True, exist_ok=True)
        secret.write_text("synthetic-only-not-a-real-credential", encoding="utf-8")
        alias = project / "ordinary-looking.txt"
        alias.symlink_to(secret)
        victim = project / "directory-that-must-survive"
        victim.mkdir()
        victim_file = victim / "keep.txt"
        victim_file.write_text("keep", encoding="utf-8")
        source = project / "test_readonly_fixture.py"
        source.write_text(
            f"""
import shutil
from pathlib import Path

SECRET = Path({json.dumps(str(secret))})
ALIAS = Path({json.dumps(str(alias))})
VICTIM = Path({json.dumps(str(victim))})
SOURCE = Path({json.dumps(str(source))})


def blocked(operation):
    try:
        operation()
    except OSError:
        return True
    return False


def test_normal_source_read_and_private_test_writes(tmp_path, request):
    assert 'test_normal_source_read' in SOURCE.read_text()
    output = tmp_path / 'ordinary.txt'
    output.write_text('normal test data')
    assert output.read_text() == 'normal test data'
    request.config.cache.set('guard/synthetic', 'private cache data')
    assert request.config.cache.get('guard/synthetic', None) == 'private cache data'
    assert not str(request.config.cache._cachedir).startswith(str(SOURCE.parent))


def test_credential_and_destructive_operations_are_denied():
    assert blocked(lambda: SECRET.read_text())
    assert blocked(lambda: ALIAS.read_text())
    assert blocked(lambda: (VICTIM / 'keep.txt').unlink())
    assert blocked(lambda: shutil.rmtree(VICTIM))
    assert blocked(lambda: SOURCE.write_text('overwritten'))
""".lstrip(),
            encoding="utf-8",
        )
        result = run_restricted_pytest(
            [
                sys.executable,
                "-m",
                "pytest",
                "--confcutdir",
                str(project),
                "-c",
                str(configuration),
                str(source),
                "-q",
            ],
            workspace=workspace,
            cwd=project,
            timeout_seconds=60,
            read_only_workspace=True,
        )
        assert result == 0
        assert victim_file.read_text() == "keep"
        assert secret.read_text() == "synthetic-only-not-a-real-credential"
        assert "test_normal_source_read" in source.read_text()
