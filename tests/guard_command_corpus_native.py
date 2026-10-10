"""Bounded offline corpus batches evaluated by the production native engine."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard.runtime.native_command_evaluation import NativeCommandEvaluation
from tests.guard_command_corpus import CommandCorpusCase
from tests.native_command_test_support import project_native_review_fixture, real_native_review_fixtures

NATIVE_CORPUS_BATCH_SIZE = 256


def pin_neutral_attribution() -> None:
    """Keep corpus evaluation independent of the developer or CI harness."""

    from tests.harness_attribution_env import HARNESS_ENV_MARKERS

    for marker in HARNESS_ENV_MARKERS:
        os.environ.pop(marker, None)
    os.environ["__CFBundleIdentifier"] = "com.apple.Terminal"  # noqa: SIM112
    from codex_plugin_scanner.guard.runtime import package_protect_projection

    package_protect_projection.resolve_parent_process_harness = lambda: None


def pin_offline_shell_context() -> None:
    """Answer shell request context offline: complete, with no directory model.

    The shell context is resident-only, and the corpus evaluates commands through
    the offline compiler without a resident. Without this answer the read
    assessment would take its fail-closed native-unavailable path for every
    command, instead of the literal-marker path the corpus contract describes.
    """

    from codex_plugin_scanner.guard.runtime import shell_secret_reads
    from codex_plugin_scanner.guard.runtime.shell_execution_context import ShellExecutionContext

    shell_secret_reads.model_shell_execution_context = lambda command_text, **_kwargs: ShellExecutionContext(
        command_text=command_text,
        initial_cwd=None,
        workspace_root=None,
        workspace_identity=None,
        segments=(),
        complete=True,
        reason_code=None,
        directory_change_present=False,
    )


def evaluate_native_corpus_batch(
    cases: Sequence[CommandCorpusCase],
    *,
    cwd: Path,
    home_dir: Path,
) -> tuple[NativeCommandEvaluation, ...]:
    """Evaluate each command once and preserve its unmodified native evidence."""

    fixtures = real_native_review_fixtures([case.command for case in cases])
    return tuple(project_native_review_fixture(fixture, cwd=cwd, home_dir=home_dir) for fixture in fixtures)
