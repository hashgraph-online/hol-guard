from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_runtime import parity_signature, review_post_tool_native
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import (
    HookReviewRequest,
    HookReviewResponse,
    HookSourceFileRef,
)
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _NATIVE_BINARY, reason="compiled native runtime is required")


def _secret_token() -> str:
    return "".join(("gh", "p_")) + "d" * 30


def _engine(store: GuardStore) -> HookReviewEngine:
    return HookReviewEngine(
        store=store,
        scanner=ContentScanner(),
        cache=HookDecisionCache(store),
        config_loader=lambda guard_home, workspace: load_guard_config(guard_home, workspace=workspace),
    )


def _inline_request(
    *,
    tmp_path: Path,
    payload: dict[str, object],
    request_id: str,
) -> HookReviewRequest:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={"hook_event_name": "PostToolUse", **payload},
        payload_kind="inline",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _source_request(
    *,
    workspace: Path,
    reference_path: str,
    text: str,
    request_id: str,
    actual_path: Path | None = None,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    write_file: bool = True,
    external_allowed: bool = False,
) -> HookReviewRequest:
    home = home_dir or workspace
    guard = guard_home or (home / "guard-home")
    guard.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = actual_path or (workspace / reference_path)
    if write_file:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    source_ref = HookSourceFileRef(
        version=1,
        path=reference_path,
        output_sha256=sha256_text(text),
        output_chars=len(text),
        tool_input_path=reference_path,
    )
    return HookReviewRequest(
        harness="pi",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": reference_path},
            "guard_source_ref": {
                "version": 1,
                "path": reference_path,
                "output_sha256": source_ref.output_sha256,
                "output_chars": source_ref.output_chars,
                "tool_input_path": reference_path,
            },
        },
        payload_kind="source_file_ref",
        config_path=None,
        cwd=workspace,
        home_dir=home,
        guard_home=guard,
        source_scope="project",
        source_ref_external_allowed=external_allowed,
        source_ref=source_ref,
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _assert_parity(request: HookReviewRequest) -> None:
    store = GuardStore(request.guard_home)
    python_response = _engine(store).review(request)
    with native_policy_snapshot(request.guard_home) as snapshot:
        native_response = review_post_tool_native(request, observe_mode=False, policy_snapshot=snapshot)
    assert native_response is not None
    _assert_native_security_floor(native_response, python_response)


def _assert_native_security_floor(
    native_response: HookReviewResponse,
    python_response: HookReviewResponse,
) -> None:
    """Allow native policy floors to add metadata without weakening the oracle."""

    if python_response.decision == "deny":
        assert native_response.decision == "deny"
        assert native_response.model_output_action == "block"
        return
    if native_response.decision == "deny":
        assert native_response.model_output_action == "block"
        return
    assert native_response.decision == "allow"
    native_signature = parity_signature(native_response)
    python_signature = parity_signature(python_response)
    assert native_signature[1] == python_signature[1]
    assert native_signature[6:] == python_signature[6:]


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("clean-small", {"tool_response": [{"type": "text", "text": "const value = 1;\n"}]}),
        ("empty", {"tool_response": ""}),
        (
            "multi-field-clean",
            {"stdout": "build complete\n", "stderr": "", "result": [{"type": "text", "text": "ok"}]},
        ),
        (
            "docs-placeholder",
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "docs/example.md"},
                "tool_response": [{"type": "text", "text": "token = placeholder-only\n"}],
            },
        ),
        (
            "large-clean",
            {"tool_response": [{"type": "text", "text": "const x = 1;\n" * 15_000}]},
        ),
    ],
)
def test_compiled_native_inline_allow_parity(tmp_path: Path, name: str, payload: dict[str, object]) -> None:
    try:
        _assert_parity(_inline_request(tmp_path=tmp_path, payload=payload, request_id=name))
    finally:
        close_resident_native_runtimes()


def test_compiled_native_inline_secret_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _inline_request(
                tmp_path=tmp_path,
                payload={"stdout": "ok", "stderr": _secret_token()},
                request_id="inline-secret",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_clean_source_read_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _source_request(
                workspace=tmp_path,
                reference_path="src/example.ts",
                text="export const value = 1;\n",
                request_id="source-clean",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_secret_source_read_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _source_request(
                workspace=tmp_path,
                reference_path="src/private.ts",
                text=f"export const value = '{_secret_token()}';\n",
                request_id="source-secret",
            )
        )
    finally:
        close_resident_native_runtimes()


@pytest.mark.parametrize(
    ("relative_path", "text"),
    [
        (".env", "SAFE_PLACEHOLDER=value\n"),
        (".hidden/config.py", "VALUE = 1\n"),
        ("credentials", "not-a-secret\n"),
    ],
)
def test_compiled_native_rejected_workspace_source_path_parity(
    tmp_path: Path,
    relative_path: str,
    text: str,
) -> None:
    try:
        _assert_parity(
            _source_request(
                workspace=tmp_path,
                reference_path=relative_path,
                text=text,
                request_id=f"source-rejected-{relative_path.replace('/', '-')}",
            )
        )
    finally:
        close_resident_native_runtimes()


@pytest.mark.parametrize(
    ("relative_path", "text"),
    [
        (".github/workflows/ci.yml", "name: ci\n"),
        (".nvmrc", "20\n"),
        ("docs/guide.md", "# Guide\n"),
    ],
)
def test_compiled_native_allowed_workspace_source_path_parity(
    tmp_path: Path,
    relative_path: str,
    text: str,
) -> None:
    try:
        _assert_parity(
            _source_request(
                workspace=tmp_path,
                reference_path=relative_path,
                text=text,
                request_id=f"source-allowed-{relative_path.replace('/', '-')}",
            )
        )
    finally:
        close_resident_native_runtimes()


@pytest.mark.skipif(os.name == "nt", reason="symlink source fixture is POSIX-only")
def test_compiled_native_source_symlink_rejection_parity(tmp_path: Path) -> None:
    source = tmp_path / "src" / "actual.ts"
    source.parent.mkdir(parents=True)
    text = "export const value = 1;\n"
    source.write_text(text, encoding="utf-8")
    link = source.with_name("link.ts")
    link.symlink_to(source)
    try:
        _assert_parity(
            _source_request(
                workspace=tmp_path,
                reference_path="src/link.ts",
                actual_path=link,
                text=text,
                write_file=False,
                request_id="source-symlink",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_external_sibling_checkout_source_parity(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    sibling = home / "sibling"
    workspace.mkdir(parents=True)
    (sibling / ".git").mkdir(parents=True)
    source = sibling / "src" / "library.ts"
    text = "export const library = true;\n"
    source.parent.mkdir(parents=True)
    source.write_text(text, encoding="utf-8")
    try:
        _assert_parity(
            _source_request(
                workspace=workspace,
                reference_path=str(source),
                actual_path=source,
                text=text,
                home_dir=home,
                guard_home=home / "guard-home",
                write_file=False,
                external_allowed=True,
                request_id="source-external-sibling",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_known_skill_source_parity(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    skill = home / ".codex" / "skills" / "example" / "SKILL.md"
    workspace.mkdir(parents=True)
    text = "# Example skill\n"
    skill.parent.mkdir(parents=True)
    skill.write_text(text, encoding="utf-8")
    try:
        _assert_parity(
            _source_request(
                workspace=workspace,
                reference_path="skill://example",
                actual_path=skill,
                text=text,
                home_dir=home,
                guard_home=home / "guard-home",
                write_file=False,
                request_id="source-known-skill",
            )
        )
    finally:
        close_resident_native_runtimes()
