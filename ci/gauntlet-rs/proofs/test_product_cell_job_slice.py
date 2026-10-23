"""Check the Python cell launcher boundary used only by Rust-owned jobs."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from ci.gauntlet.benchmark.product_cell_supervisor import cell_placement, rust_job_slice


class ProductCellJobSliceTest(unittest.TestCase):
    def test_existing_python_worker_keeps_system_slice(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            selected = rust_job_slice()
        self.assertIsNone(selected)
        self.assertEqual(cell_placement(selected, "hol-product-cell-" + "a" * 32 + ".service"), (
            [], Path("/sys/fs/cgroup/system.slice/hol-product-cell-" + "a" * 32 + ".service")
        ))

    def test_rust_job_places_product_unit_beneath_exact_slice(self) -> None:
        value = "holgauntletrust0123456789abcdef.slice"
        with patch.dict(os.environ, {"HOL_GAUNTLET_RUST_JOB_SLICE": value}, clear=True):
            selected = rust_job_slice()
        self.assertEqual(selected, value)
        self.assertEqual(cell_placement(selected, "hol-product-cell-" + "b" * 32 + ".service"), (
            ["--slice=" + value],
            Path("/sys/fs/cgroup") / value / ("hol-product-cell-" + "b" * 32 + ".service"),
        ))

    def test_invalid_or_hierarchical_slice_refuses_before_cell_launch(self) -> None:
        for value in ("", "system.slice", "other.slice", "holgauntletrust0123456789abcdef-SLICE.slice",
                      "holgauntletrust0123456789abcdeg.slice", "holgauntletrust0123456789abcdef.slice/other"):
            with self.subTest(value=value), patch.dict(
                os.environ, {"HOL_GAUNTLET_RUST_JOB_SLICE": value}, clear=True
            ):
                with self.assertRaisesRegex(ValueError, "invalid Rust-owned product-cell job slice"):
                    rust_job_slice()


if __name__ == "__main__":
    unittest.main()
