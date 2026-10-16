"""Informational token-usage aggregation and rendering. No live inference is started."""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.summary import inference_usage, render_summary_markdown


def test_usage_totals_skip_missing_bool_and_negative_rounds(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "alpha.json").write_text(
        json.dumps(
            {
                "inference": {
                    "live_rounds": [
                        {
                            "usage": {
                                "prompt_tokens": 10,
                                "completion_tokens": 4,
                                "total_tokens": 14,
                                "cached_tokens": 6,
                                "reasoning_tokens": 2,
                            }
                        },
                        {"note": "round without usage"},
                        {"usage": {"prompt_tokens": -5, "cached_tokens": True, "completion_tokens": 1}},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (cases / "beta.json").write_text(
        json.dumps(
            {
                "inference": {
                    "live_rounds": [
                        {"usage": {"prompt_tokens": 7, "total_tokens": 9, "reasoning_tokens": 3}},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    usage = inference_usage(cases, ["alpha", "beta"])
    assert usage == {
        "prompt_tokens": 17,
        "completion_tokens": 5,
        "total_tokens": 23,
        "cached_tokens": 6,
        "reasoning_tokens": 5,
        "rounds": 4,
        "rounds_with_usage": 3,
    }
    report = {
        "platform": "darwin",
        "full_profile": True,
        "merge_qualified": True,
        "inference_usage": usage,
        "hook_latency": {
            "samples": 0,
            "missing_samples": 0,
            "failed_attempts": 0,
            "p50_ms": None,
            "p90_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "mean_ms": None,
            "max_ms": None,
            "by_event": {},
        },
        "cases": [{"id": "alpha", "outcome": "pass", "tool_calls": 2}],
    }
    rendered = render_summary_markdown(report, {"candidate_sha": "c" * 40}, "b" * 40, "omp/test")
    assert "Inference tokens: input 17 (cached 6), output 5 over 4 rounds" in rendered
