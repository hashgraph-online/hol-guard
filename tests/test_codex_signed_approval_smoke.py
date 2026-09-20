from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "codex_signed_approval_smoke.py"
_SPEC = importlib.util.spec_from_file_location("codex_signed_approval_smoke", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SMOKE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SMOKE)


def test_smoke_parser_accepts_guard_token_after_existing_fragment_fields() -> None:
    url = "http://127.0.0.1:5474/requests/req-1#surface=approval-center&guard-token=gld1.payload.signature"
    assert _SMOKE._urls(f"Review: {url}") == [url]
    assert _SMOKE._url_summary(url)[1] is True


def test_smoke_parser_keeps_unsigned_local_url_unsigned() -> None:
    url = "http://127.0.0.1:5474/requests/req-1#surface=approval-center"
    assert _SMOKE._urls(f"Review: {url}") == [url]
    assert _SMOKE._url_summary(url)[1] is False


def test_daemon_endpoint_requires_loopback_and_valid_port() -> None:
    assert _SMOKE._daemon_endpoint({"host": "127.0.0.1", "port": 65535, "pid": 1}) == (
        "127.0.0.1",
        65535,
        1,
    )
    assert _SMOKE._daemon_endpoint({"host": "192.0.2.1", "port": 58739, "pid": 1}) is None
    assert _SMOKE._daemon_endpoint({"host": "127.0.0.1", "port": 65536, "pid": 1}) is None


def test_existing_root_layout_rejects_symlinked_child(tmp_path: Path) -> None:
    root = tmp_path / "hol-guard-codex-smoke-test"
    (root / "home").mkdir(parents=True)
    (root / "guard-home").mkdir()
    (root / "workspace" / "fixture-package").mkdir(parents=True)
    assert _SMOKE._existing_root_layout_is_safe(root)

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "home").rmdir()
    (root / "home").symlink_to(outside, target_is_directory=True)
    assert not _SMOKE._existing_root_layout_is_safe(root)


def test_existing_root_layout_rejects_symlinked_fixed_output(tmp_path: Path) -> None:
    root = tmp_path / "hol-guard-codex-smoke-test"
    root.mkdir()
    target = tmp_path / "outside-output"
    target.write_text("outside", encoding="utf-8")
    (root / "codex.jsonl").symlink_to(target)
    assert not _SMOKE._existing_root_layout_is_safe(root)


def test_run_rejects_symlinked_output(tmp_path: Path) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW is unavailable")
    target = tmp_path / "outside-output"
    target.write_text("outside", encoding="utf-8")
    stdout = tmp_path / "stdout.txt"
    stdout.symlink_to(target)
    with pytest.raises(OSError):
        _SMOKE._run(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            env=os.environ.copy(),
            stdout=stdout,
            stderr=tmp_path / "stderr.txt",
            timeout=1,
        )
    assert target.read_text(encoding="utf-8") == "outside"


def test_negative_timeout_is_rejected() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _SMOKE._non_negative_int("-1")


def test_run_timeout_terminates_descendant_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-finished"
    child_code = (
        "import pathlib,sys,time; time.sleep(1); "
        "pathlib.Path(sys.argv[1]).write_text('finished', encoding='utf-8')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); time.sleep(30)"
    )
    result = _SMOKE._run(
        [sys.executable, "-c", parent_code, str(marker), child_code],
        cwd=tmp_path,
        env=os.environ.copy(),
        stdout=tmp_path / "stdout.txt",
        stderr=tmp_path / "stderr.txt",
        timeout=0.1,
    )
    assert result == 124
    time.sleep(1.2)
    assert not marker.exists()
