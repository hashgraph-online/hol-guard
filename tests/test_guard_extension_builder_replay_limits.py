"""A successful compilation must remain readable by its own replay boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import MAX_INPUT_BYTES, canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit, load_kit, write_kit
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review
from tests.extension_builder_support import make_discovery, make_kit, metadata


def test_repeated_global_metadata_cannot_publish_an_unreadable_snapshot(tmp_path: Path) -> None:
    flags = ["--" + f"flag{index}".ljust(62, "x") for index in range(128)]
    document = {
        "schemaVersion": "guard.cli-surface.v1",
        "flags": flags,
        "commands": [{"path": [f"operation{index}"]} for index in range(240)],
    }
    source = tmp_path / "source.json"
    source.write_text(canonical_json(document), encoding="utf-8")
    assert source.stat().st_size < MAX_INPUT_BYTES
    discovery = discover("cli", source, metadata())
    assert len(canonical_json(discovery.to_dict()).encode("utf-8")) > MAX_INPUT_BYTES
    with pytest.raises(BuilderError):
        build_kit(discovery, default_review(discovery))
    assert not (tmp_path / "kit").exists()


def test_readable_normalized_inputs_still_round_trip(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    review = load_review(default_review(discovery).to_dict(), discovery)
    kit = build_kit(discovery, review)
    destination = tmp_path / "kit"
    write_kit(kit, destination)
    assert load_kit(destination) == kit


@pytest.mark.parametrize("directory", ["unexpected", "artifacts/unexpected", "artifacts/tests/unexpected"])
def test_extra_empty_directories_are_not_compiler_owned(tmp_path: Path, directory: str) -> None:
    destination = tmp_path / "kit"
    write_kit(make_kit(tmp_path), destination)
    (destination / directory).mkdir(parents=True)
    with pytest.raises(BuilderError) as caught:
        load_kit(destination)
    assert caught.value.code == "kit_files"
