"""Missing signed source cannot silently become an empty native policy."""

import time

import pytest

from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from tests.native_scoped_resident_fixtures import prepare_store, publish_source


@pytest.mark.parametrize("source,retained", [("canonical", "materialization"), ("canonical", "row"), ("memory", "row")])
def test_missing_original_source_refuses_even_when_an_orphan_projection_remains(tmp_path, source, retained):
    store, _ = prepare_store(tmp_path)
    publish_source(store, source)
    assert len(read_native_policy_authority_inputs(store, now=time.time()).authority.rows) == 1
    with store._connect() as connection:
        keys = (
            ("policy_bundle",)
            if source == "canonical"
            else ("guard_review_memory_registry", "guard_review_memory_policy_version")
        )
        connection.executemany("delete from sync_state where state_key = ?", [(key,) for key in keys])
        if retained == "materialization":
            connection.execute("delete from policy_decisions")
        elif source == "canonical":
            connection.execute("delete from sync_state where state_key = 'policy_bundle_materialization'")
    with pytest.raises(NativePolicySnapshotError, match=r"native_policy_authority_.*_unavailable"):
        read_native_policy_authority_inputs(store, now=time.time())
