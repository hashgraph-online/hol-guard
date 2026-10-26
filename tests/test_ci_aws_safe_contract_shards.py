"""Require complete AWS native safety coverage after bounded parametrization."""

from __future__ import annotations

from importlib import import_module

import pytest


@pytest.mark.parametrize("batch", [1, 4, 5])
def test_aws_help_and_skeleton_slices_cover_the_exact_original_commands(batch: int) -> None:
    module = import_module(f"tests.test_guard_command_cloud_aws_batch_{batch}")
    commands: tuple[str, ...] = getattr(module, f"AWS_BATCH_{batch}_SAFE_CASES")
    starts: tuple[int, ...] = module._SAFE_CASE_STARTS
    size: int = module._SAFE_CASE_CHUNK_SIZE

    assert size == 50
    assert len(commands) >= 400
    assert starts == tuple(range(0, len(commands), size))
    slices = [commands[start : start + size] for start in starts]
    assert slices
    assert all(0 < len(chunk) <= size for chunk in slices)
    # Preserve even duplicate inputs. No safe commands may be dropped or
    # substituted, and each original position belongs to exactly one node.
    assert tuple(item for chunk in slices for item in chunk) == commands
