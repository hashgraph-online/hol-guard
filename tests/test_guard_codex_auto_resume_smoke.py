from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "codex-auto-resume-smoke.py"
MODULE_NAME = "guard_codex_auto_resume_smoke"


def _load_smoke_module():
    spec = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load smoke module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def test_codex_auto_resume_smoke_script_resumes_only_allowed_requests() -> None:
    module = _load_smoke_module()
    args = argparse.Namespace(
        codex_home=None,
        timeout_seconds=240.0,
        request_timeout_seconds=120.0,
        keep_temp_dir=False,
    )

    allow_result = module._run_scenario(decision="allow", args=args)
    block_result = module._run_scenario(decision="block", args=args)

    assert allow_result.resume_status == "sent"
    assert allow_result.request_id
    assert allow_result.resume_strategy == "codex-app-server-thread"
    assert allow_result.proof_created is False
    assert allow_result.assistant_message
    assert "turn/start" in allow_result.transcript_excerpt
    assert block_result.resume_status == "skipped"
    assert block_result.request_id
    assert block_result.resume_strategy == "codex-app-server-thread"
    assert block_result.proof_created is False
    assert block_result.assistant_message
    assert "turn/start" not in block_result.transcript_excerpt
