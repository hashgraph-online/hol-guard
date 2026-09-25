"""Whole-command decision metadata for compound runtime artifacts."""

from __future__ import annotations

from pathlib import Path

from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.native_command_evaluation import NativeCommandEvaluation


def compound_command_decision_metadata(
    command_text: str,
    *,
    native_review: NativeCommandEvaluation | None,
    workspace: Path | None,
    home_dir: Path,
) -> dict[str, object]:
    del command_text, workspace, home_dir
    if native_review is None:
        return {
            "command_action_floor": "require-reapproval",
            "command_evaluation_status": "native_unavailable",
        }
    evaluation = native_review.evaluation
    return {
        "command_action_floor": evaluation.decision_plane.action,
        "command_decision_plane": effect_decision_to_dict(evaluation.decision_plane),
    }
