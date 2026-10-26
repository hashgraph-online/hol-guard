"""Real pinned SDK, installed Bash dependency and production native post review."""

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS native Bash owner")


@pytest.mark.parametrize("harness", ["omp", "pi"])
@pytest.mark.parametrize("duration", ["quiet", "once", "persistent-same-intent"])
def test_sdk_captured_package_source_remains_usable_without_cloud(
    native_context_digest,
    tmp_path,
    monkeypatch,
    duration,
    harness,
):
    from tests.test_omp_bound_bash_sdk import (
        test_pinned_sdk_bash_tool_delivers_consent_and_preserves_execution_cwd as run_fixture,
    )

    run_fixture(native_context_digest, tmp_path, monkeypatch, f"native-post-package-{duration}", harness, None)
