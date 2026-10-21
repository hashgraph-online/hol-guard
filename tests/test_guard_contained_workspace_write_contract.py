from __future__ import annotations

from pathlib import Path

import pytest

from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.native_command_test_support import iter_native_command_evaluations, real_native_command_evaluation


def test_every_cdx_062_case_retains_exact_review_or_block_floor() -> None:
    benign_count = 0
    unsupported_apply_count = 0
    for reviewed, oracle in zip(
        iter_native_command_evaluations(
            (case.command for case in iter_benign_corpus()), cwd=Path("workspace"), home_dir=Path("home")
        ),
        iter_benign_oracle(),
        strict=True,
    ):
        evaluation = reviewed.evaluation
        if oracle.owner != "CDX-062":
            continue
        benign_count += 1
        # The native catalog models the read-only --check form. Applying an
        # unchecked patch stays unattributed: it needs a human review and is
        # never contained automatically, and disabled Git controls still block.
        extensions = reviewed.payload["command_extensions"]
        assert isinstance(extensions, dict)
        binding = extensions["binding"]
        assert isinstance(binding, dict)
        if int(binding["uncertainty_count"]) > 0:
            unsupported_apply_count += 1
            assert reviewed.native_minimum_action == "review"
        assert evaluation.minimum_action == "review"
        assert evaluation.decision_plane.action == "review"
        assert evaluation.decision_plane.proof_routes == frozenset()
    assert benign_count == 100
    assert unsupported_apply_count == 25

    adversarial_count = 0
    adversarial_cases = (
        case.command
        for case, oracle in zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True)
        if oracle.owner == "CDX-062"
    )
    for reviewed in iter_native_command_evaluations(adversarial_cases, cwd=Path("workspace"), home_dir=Path("home")):
        adversarial_count += 1
        evaluation = reviewed.evaluation
        assert evaluation.minimum_action == "block"
        assert evaluation.decision_plane.action == "block"
        assert evaluation.decision_plane.proof_routes == frozenset()
    assert adversarial_count == 4167


@pytest.mark.parametrize("command", ("ruff format src/module.py", "cp build/schema.json generated/schema.json"))
def test_direct_workspace_writes_retain_the_review_floor(command: str) -> None:
    evaluation = real_native_command_evaluation(command, cwd=Path("workspace"), home_dir=Path("home")).evaluation
    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.proof_routes == frozenset()

