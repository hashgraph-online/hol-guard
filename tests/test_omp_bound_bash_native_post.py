"""Real SDK tool, production native post policy and stored-context acknowledgement.

This uses no model or network and is not real-agent/release qualification.
"""

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS native Bash owner")


@pytest.mark.parametrize("harness", ["omp", "pi"])
@pytest.mark.parametrize(
    "duration", ["once", "persistent-same-intent", "persistent-nonzero", "compiled-persistent-same-intent"]
)
def test_sdk_result_passes_production_native_post_before_ack(
    native_context_digest,
    tmp_path,
    monkeypatch,
    harness,
    duration,
):
    from tests.test_omp_bound_bash_sdk import (
        test_pinned_sdk_bash_tool_delivers_consent_and_preserves_execution_cwd as run_fixture,
    )

    run_fixture(
        native_context_digest,
        tmp_path,
        monkeypatch,
        f"native-post-{duration}",
        harness,
        None,
    )
