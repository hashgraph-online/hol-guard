from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets import git_object_reader as reader_module
from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository_module
from codex_plugin_scanner.guard.secrets import secret_staged_scanner as staged_module
from codex_plugin_scanner.guard.secrets.git_blob_scan_cache import GitBlobScanCache
from codex_plugin_scanner.guard.secrets.git_object_reader import (
    GitObjectReader,
    GitObjectReadError,
    _read_exact,
    parse_raw_diff,
)
from codex_plugin_scanner.guard.secrets.secret_repository_scanner import _scan_blob, scan_repository_secrets
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout


def _init(root: Path, *, object_format: str = "sha1") -> None:
    _git(root, "init", f"--object-format={object_format}")
    _git(root, "config", "user.name", "Guard Test")
    _git(root, "config", "user.email", "guard@example.invalid")


def _token() -> str:
    return "ghp_" + "9tH3mZ5qP7vC2xL4nR6sB8wF1jK0dE5uA7iY"


def _count_git_children(monkeypatch: pytest.MonkeyPatch) -> list[subprocess.Popen[bytes]]:
    original = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []

    def launch(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original(*args, **kwargs)
        if "cat-file" in args[0]:
            children.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    return children


def test_staged_batch_reuses_two_children_and_one_detector_run_for_identical_blobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _init(tmp_path)
    data = f"TOKEN={_token()}\n".encode()
    for index in range(25):
        (tmp_path / f"config-{index}.env").write_bytes(data)
    _git(tmp_path, "add", ".")
    children = _count_git_children(monkeypatch)
    scans: list[str] = []

    def scan(data: bytes, **kwargs: object) -> object:
        scans.append(kwargs["path"])
        return _scan_blob(data, **kwargs)

    monkeypatch.setattr(staged_module, "_scan_blob", scan)
    result = scan_staged_secrets(tmp_path)

    assert result.truncated is False
    assert result.files_scanned == 25
    assert result.bytes_scanned == 25 * len(data)
    assert len(result.findings) == 25
    assert {finding.path for finding in result.findings} == {f"config-{index}.env" for index in range(25)}
    assert len(scans) == 1
    assert len(children) == 2 and all(child.poll() is not None for child in children)
    assert _token() not in json.dumps(result.to_public_dict())


def test_history_cache_keeps_each_commit_occurrence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init(tmp_path)
    secret = f"TOKEN={_token()}\n".encode()
    safe = b"VALUE=ordinary\n"
    target = tmp_path / "config.env"
    commits = []
    for index, data in enumerate((secret, safe, secret, safe)):
        target.write_bytes(data)
        _git(tmp_path, "add", ".")
        _git(tmp_path, "commit", "-m", f"change {index}")
        if data == secret:
            commits.append(_git(tmp_path, "rev-parse", "HEAD").decode().strip())
    children = _count_git_children(monkeypatch)
    scans: list[tuple[bytes, str]] = []

    def scan(data: bytes, **kwargs: object) -> object:
        scans.append((data, kwargs["source"]))
        return _scan_blob(data, **kwargs)

    monkeypatch.setattr(repository_module, "_scan_blob", scan)
    result = scan_repository_secrets(tmp_path, include_history=True)

    assert result.truncated is False
    assert result.files_scanned == 5 and result.commits_scanned == 4
    assert result.bytes_scanned == 2 * len(secret) + 3 * len(safe)
    assert {finding.commit for finding in result.findings} == set(commits)
    assert len(scans) == 3  # working-tree bytes and each distinct historical blob
    assert len(children) == 2 and all(child.poll() is not None for child in children)


def test_staged_oid_is_frozen_before_index_mutates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init(tmp_path)
    target = tmp_path / "config.env"
    target.write_text(f"TOKEN={_token()}\n")
    _git(tmp_path, "add", ".")
    original = staged_module._git_staged_paths

    def enumerate_then_mutate(root: Path) -> object:
        references = original(root)
        target.write_text("VALUE=ordinary\n")
        _git(root, "add", ".")
        return references

    monkeypatch.setattr(staged_module, "_git_staged_paths", enumerate_then_mutate)
    result = scan_staged_secrets(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].candidate == _token()


def test_git_replacements_cannot_change_admitted_blob_identity(tmp_path: Path) -> None:
    _init(tmp_path)
    target = tmp_path / "config.env"
    data = f"TOKEN={_token()}\n".encode()
    target.write_bytes(data)
    _git(tmp_path, "add", ".")
    original = _git(tmp_path, "rev-parse", ":config.env").decode().strip()
    target.write_text("SAFE_VALUE=ordinary\n")
    replacement = _git(tmp_path, "hash-object", "-w", str(target)).decode().strip()
    _git(tmp_path, "replace", original, replacement)

    result = scan_staged_secrets(tmp_path)

    assert result.truncated is False
    assert result.bytes_scanned == len(data)
    assert len(result.findings) == 1


def test_missing_history_object_is_incomplete_not_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init(tmp_path)
    monkeypatch.setattr(repository_module, "_git_commits", lambda *_args: ["a" * 40])
    monkeypatch.setattr(
        repository_module,
        "_git_changed_paths",
        lambda *_args: [reader_module.GitBlobReference("missing.env", "b" * 40)],
    )
    result = scan_repository_secrets(tmp_path, include_history=True)
    assert result.truncated is True
    assert result.errors == ("git_history_blob_unavailable",)


def test_oversized_blob_is_rejected_before_content_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init(tmp_path)
    (tmp_path / "oversized.env").write_bytes(b"x" * 2048)
    _git(tmp_path, "add", ".")
    children = _count_git_children(monkeypatch)
    result = scan_staged_secrets(tmp_path, max_file_bytes=1024)
    assert result.truncated is True
    assert len(children) == 1
    assert "--batch-check" in children[0].args


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_batch_handles_empty_binary_large_and_newline_paths(tmp_path: Path, object_format: str) -> None:
    _init(tmp_path, object_format=object_format)
    (tmp_path / "empty.env").write_bytes(b"")
    (tmp_path / "image.env").write_bytes(b"\0" + _token().encode())
    (tmp_path / "oversized.env").write_bytes(b"x" * 2048)
    unusual_name = "line\nbreak.env" if os.name != "nt" else "unicode-λ.env"
    (tmp_path / unusual_name).write_text(f"TOKEN={_token()}\n")
    _git(tmp_path, "add", ".")

    result = scan_staged_secrets(tmp_path, max_file_bytes=1024)

    assert result.truncated is True
    assert result.errors == ("git_staged_blob_unavailable_or_oversized",)
    assert result.files_scanned == 3
    assert [finding.path for finding in result.findings] == [unusual_name]


def test_scan_cache_keeps_path_policy_and_finding_budget(tmp_path: Path) -> None:
    _init(tmp_path)
    synthetic_access_key = "AKIA" + "1234567890ABCDEF"
    data = f"AWS_ACCESS_KEY_ID={synthetic_access_key}\nTOKEN={_token()}\n".encode()
    target = tmp_path / "content.env"
    target.write_bytes(data)
    oid = _git(tmp_path, "hash-object", "-w", str(target)).decode().strip()
    cache = GitBlobScanCache()
    paths = ["one.env", "two.env", "docs/config.env", "fixtures/config.env", ".aws/config.env", "source.py"]
    with GitObjectReader(tmp_path) as reader:
        for path in paths:
            for limit in (500, 1, 2, 3):
                found, size = cache.scan(
                    reader,
                    oid=oid,
                    size=len(data),
                    path=path,
                    source="staged",
                    commit=None,
                    finding_budget=limit,
                    max_file_bytes=1024,
                    scan_blob=_scan_blob,
                )
                expected, expected_size = _scan_blob(
                    data, path=path, source="staged", commit=None, finding_budget=limit
                )
                assert size == expected_size
                assert [finding.to_public_dict(fingerprint_key=b"test-key") for finding in found] == [
                    finding.to_public_dict(fingerprint_key=b"test-key") for finding in expected
                ]


def test_public_client_config_and_fixture_suppression_do_not_leak_across_cache(tmp_path: Path) -> None:
    _init(tmp_path)
    google = "AIza" + "9tH3mZ5qP7vC2xL4nR6sB8wF1jK0dE5uA7i"
    data = f"GOOGLE_API_KEY={google}\nTOKEN={_token()}\n# test fixture\n"
    for name in ("google-services.json", "server.json", "fixtures/config.json"):
        target = tmp_path / name
        target.parent.mkdir(exist_ok=True)
        target.write_text(data)
    _git(tmp_path, "add", ".")
    result = scan_staged_secrets(tmp_path)
    expected = []
    for name in ("google-services.json", "server.json", "fixtures/config.json"):
        found, _ = _scan_blob(data.encode(), path=name, source="staged", commit=None, finding_budget=500)
        expected.extend(found)
    assert sorted((f.path, f.rule_id) for f in result.findings) == sorted((f.path, f.rule_id) for f in expected)
    assert all(f.rule_id != "google-api-key" for f in result.findings if f.path == "google-services.json")
    assert all(f.path != "fixtures/config.json" for f in result.findings)


def test_read_exact_accepts_short_pipe_reads_and_rejects_eof() -> None:
    class ShortReads(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            return super().read(min(size, 2))

    assert _read_exact(ShortReads(b"abcdef"), 6) == b"abcdef"
    with pytest.raises(GitObjectReadError, match="short_read"):
        _read_exact(ShortReads(b"abc"), 6)


@pytest.mark.parametrize("failure", ["timeout", "oversized_header", "wrong_oid", "short_content", "digest"])
def test_broken_batch_is_bounded_and_children_are_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    data = b"abc"
    oid = hashlib.sha1(b"blob 3\0" + data).hexdigest()
    original = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []
    script = """
import sys, time
for line in sys.stdin.buffer:
    oid = line.strip()
    if FAILURE == 'timeout':
        time.sleep(10)
    elif FAILURE == 'oversized_header':
        sys.stdout.buffer.write(b'x' * 300 + b'\\n')
    elif FAILURE == 'wrong_oid':
        sys.stdout.buffer.write(b'0' * 40 + b' blob 3\\n')
    else:
        sys.stdout.buffer.write(oid + b' blob 3\\n')
        if CONTENTS:
            sys.stdout.buffer.write(b'a' if FAILURE == 'short_content' else b'bad\\n')
    sys.stdout.buffer.flush()
    if CONTENTS:
        break
"""

    def launch(args: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        contents = "--batch" in args
        code = f"FAILURE={failure!r}\nCONTENTS={contents!r}\n" + script
        process = original([sys.executable, "-c", code], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(reader_module.subprocess, "Popen", launch)
    started = time.monotonic()
    with GitObjectReader(tmp_path, timeout=0.15) as reader, pytest.raises(GitObjectReadError):
        reader.read(oid, size=3, max_bytes=1024)
    assert time.monotonic() - started < 3
    assert children and all(child.poll() is not None for child in children)
    assert not any(thread.name == "guard-git-object-reader" for thread in threading.enumerate())


def test_raw_diff_rejects_protocol_errors_and_preserves_gitlinks_for_coverage() -> None:
    oid = b"a" * 40
    assert parse_raw_diff(b":100644 100644 " + oid + b" " + oid + b" M\0new\nname.env\0")[0].path == "new\nname.env"
    assert parse_raw_diff(b":100644 000000 " + oid + b" " + b"0" * 40 + b" D\0gone.env\0") == []
    assert parse_raw_diff(b":000000 160000 " + b"0" * 40 + b" " + oid + b" A\0module\0")[0].path == "module"
    for invalid in (b"no terminator", b"x\0", b"x\0name\0", b":100644 100644 bad bad M\0name\0"):
        assert parse_raw_diff(invalid) is None


def test_staged_gitlink_retains_incomplete_coverage(tmp_path: Path) -> None:
    _init(tmp_path)
    (tmp_path / "config.env").write_text("SAFE_VALUE=ordinary\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    commit = _git(tmp_path, "rev-parse", "HEAD").decode().strip()
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{commit},module")
    result = scan_staged_secrets(tmp_path)
    assert result.truncated is True
    assert result.errors == ("git_staged_blob_unavailable_or_oversized",)
