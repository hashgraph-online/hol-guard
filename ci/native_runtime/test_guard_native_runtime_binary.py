from __future__ import annotations

import importlib.metadata
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_runtime import native_runtime_status, review_post_tool_native
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _NATIVE_BINARY, reason="compiled native runtime is required")


def _request(tmp_path: Path, text: str) -> HookReviewRequest:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": text}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=guard_home,
        source_scope="project",
        request_id="native-binary-proof",
    )


def _github_like_token() -> str:
    prefix = "".join(("gh", "p_"))
    return prefix + "c" * 30


def _native_state_files(guard_home: Path) -> list[Path]:
    return list((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))


def _stop_native_runtime(runtime: Path, guard_home: Path) -> None:
    subprocess.run(
        (str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime")),
        check=False,
        capture_output=True,
        timeout=2,
    )


def test_compiled_native_runtime_reviews_and_reuses_resident_service(tmp_path: Path) -> None:
    status = native_runtime_status()
    assert status.available and status.compatible, status
    assert status.identity is not None
    assert status.capabilities is not None
    assert status.capabilities.runtime_version == importlib.metadata.version("hol-guard")
    assert "post-tool-inline-v1" in status.capabilities.features

    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp" if os.name != "nt" else None) as short_tmp:
        clean_request = _request(Path(short_tmp), "const value = 1;\n")
        try:
            clean = review_post_tool_native(clean_request, observe_mode=False)
            assert clean is not None
            assert clean.decision == "allow"
            assert clean.reason_code == "output_scan_allow"

            secret_request = _request(Path(short_tmp), _github_like_token())
            secret = review_post_tool_native(secret_request, observe_mode=False)
            assert secret is not None
            assert secret.decision == "deny"
            assert secret.reason_code == "output_secret_match"

            assert len(_native_state_files(clean_request.guard_home)) == 1
        finally:
            _stop_native_runtime(status.identity.path, clean_request.guard_home)
