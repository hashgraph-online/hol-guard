"""Root inventory rows must never turn into an executable-wide block."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.kit import build_kit
from codex_plugin_scanner.guard.extension_builder.review import load_review
from tests.extension_builder_support import make_discovery
from tests.test_guard_extension_builder_review import reviewed_entry


@pytest.mark.parametrize("safe_vectors", [[], [["--help"]]])
def test_reviewed_root_block_is_rejected_even_without_safe_vectors(
    tmp_path: Path, safe_vectors: list[list[str]]
) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ())
    entry.update({"state": "block", "safeArgv": safe_vectors})
    with pytest.raises(BuilderError) as caught:
        load_review(payload, discovery)
    assert caught.value.code == "root_block_scope"


def test_root_review_can_coexist_with_a_scoped_child_block(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "delete"))
    entry["state"] = "block"
    kit = build_kit(discovery, load_review(payload, discovery))
    decisions = kit.review.by_id()
    root = next(row for row in discovery.operations if not row.path)
    child = next(row for row in discovery.operations if row.path == ("items", "delete"))
    assert decisions[root.operation_id].state == "review"
    assert decisions[child.operation_id].state == "block"
    assert kit.summary()["explicitBlocks"] == 1
