#!/usr/bin/env python3
"""Run one disjoint shard of the complete installed-native regression manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not __package__:
    sys.path.insert(0, str(ROOT))

from scripts.ci.pytest_shard import build_node_shards  # noqa: E402


def select_nodes(node_ids: list[str], index: int, count: int) -> list[str]:
    """Partition the collected platform inventory, rejecting empty or ambiguous shards."""
    if not 0 <= index < count:
        raise ValueError("shard index must be in [0, shard count)")
    return build_node_shards(node_ids, count)[index]


class _AssertInstalled:
    @pytest.hookimpl(trylast=True)
    def pytest_collection_finish(self, session: pytest.Session) -> None:
        import sysconfig

        import codex_plugin_scanner

        site = Path(sysconfig.get_paths()["purelib"]).resolve()
        if site not in Path(codex_plugin_scanner.__file__).resolve().parents:
            raise pytest.UsageError("native regression must import the installed wheel")


class NativeShard:
    def __init__(self, index: int, count: int) -> None:
        self.index = index
        self.count = count
        self.all_nodes: list[str] = []
        self.selected: list[str] = []

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]) -> None:
        self.all_nodes = sorted(item.nodeid for item in items)
        try:
            self.selected = select_nodes(self.all_nodes, self.index, self.count)
        except ValueError as error:
            raise pytest.UsageError(str(error)) from error
        selected = set(self.selected)
        deselected = [item for item in items if item.nodeid not in selected]
        items[:] = [item for item in items if item.nodeid in selected]
        config.hook.pytest_deselected(items=deselected)

    def report(self, exit_code: int) -> dict[str, object]:
        inventory = "\n".join(self.all_nodes).encode("utf-8")
        return {
            "schema": "hol-guard.native-regression-shard.v1",
            "shard_index": self.index,
            "shard_count": self.count,
            "collected_count": len(self.all_nodes),
            "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
            "selected": self.selected,
            "exit_code": exit_code,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    shard = NativeShard(cast(int, args.shard_index), cast(int, args.shard_count))
    report = cast(Path, args.report)
    # Retain the exact manifest, pytest configuration, assertions and exit status.
    exit_code = int(
        pytest.main(["@" + str(ROOT / "ci/native_runtime/regression-tests.txt")], plugins=[shard, _AssertInstalled()])
    )
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps({**shard.report(exit_code), "platform": args.platform}, sort_keys=True) + "\n", encoding="utf-8"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
