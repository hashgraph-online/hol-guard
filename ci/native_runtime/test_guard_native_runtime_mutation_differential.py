from __future__ import annotations

import os
import random
import string
import tempfile
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_runtime import parity_signature, review_post_tool_native
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest
from codex_plugin_scanner.guard.store import GuardStore

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _NATIVE_BINARY, reason="compiled native runtime is required")
_SEEDS = (7, 29, 113)
_CASES_PER_SEED = 64
_OUTPUT_KEYS = ("tool_response", "stdout", "stderr", "result")
_TEXT_KEYS = ("text", "output", "content", "message", "stdout", "stderr")


def _engine(store: GuardStore) -> HookReviewEngine:
    return HookReviewEngine(
        store=store,
        scanner=ContentScanner(),
        cache=HookDecisionCache(store),
        config_loader=lambda guard_home, workspace: load_guard_config(guard_home, workspace=workspace),
    )


def _clean_text(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + " _-/:.\n"
    length = rng.randint(0, 5000)
    return "".join(rng.choice(alphabet) for _ in range(length))


def _risk_text(rng: random.Random) -> str:
    family = rng.randrange(4)
    if family == 0:
        return "".join(("gh", "p_")) + "z" * 30
    if family == 1:
        return "".join(("AK", "IA")) + "A" * 16
    if family == 2:
        return "Bearer " + "sk-" + "x" * 32
    return "token = " + "xoxb-" + "1" * 20 + "-" + "a" * 24


def _leaf(rng: random.Random) -> object:
    selector = rng.randrange(8)
    if selector <= 2:
        return _clean_text(rng)
    if selector == 3:
        return _risk_text(rng)
    if selector == 4:
        return rng.randint(-1000, 1000)
    if selector == 5:
        return rng.choice((True, False, None))
    if selector == 6:
        return {"type": "text", "text": _clean_text(rng)}
    return {"type": "text", "text": _risk_text(rng)}


def _nested_value(rng: random.Random, depth: int) -> object:
    if depth >= 4 or rng.random() < 0.45:
        return _leaf(rng)
    if rng.random() < 0.5:
        return [_nested_value(rng, depth + 1) for _ in range(rng.randint(0, 8))]
    record: dict[str, object] = {}
    keys = list(_TEXT_KEYS)
    rng.shuffle(keys)
    for key in keys[: rng.randint(0, min(5, len(keys)))]:
        record[key] = _nested_value(rng, depth + 1)
    if rng.random() < 0.25:
        record["ignored_metadata"] = {"value": rng.randint(0, 50)}
    return record


def _payload(rng: random.Random, case_index: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read" if case_index % 3 == 0 else "Bash",
    }
    keys = list(_OUTPUT_KEYS)
    rng.shuffle(keys)
    for key in keys[: rng.randint(0, len(keys))]:
        payload[key] = _nested_value(rng, 0)
    if case_index % 5 == 0:
        payload["tool_input"] = {"file_path": "docs/example.md"}
    elif case_index % 7 == 0:
        payload["tool_input"] = {"file_path": "src/example.ts"}
    if case_index % 11 == 0:
        payload["unknown"] = {"nested": ["ignored", {"textual": "not-output"}]}
    return payload


def _request(
    workspace: Path,
    *,
    guard_home: Path,
    payload: dict[str, object],
    request_id: str,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload=payload,
        payload_kind="inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


@pytest.mark.parametrize("seed", _SEEDS)
def test_mutated_inline_corpus_keeps_exact_python_rust_parity(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory(prefix=f"hgm-{seed}-", dir=tempfile.gettempdir()) as short_tmp:
        guard_home = Path(short_tmp) / "guard-home"
        guard_home.mkdir(mode=0o700)
        store = GuardStore(guard_home)
        engine = _engine(store)
        try:
            for case_index in range(_CASES_PER_SEED):
                request = _request(
                    tmp_path,
                    guard_home=guard_home,
                    payload=_payload(rng, case_index),
                    request_id=f"mutation-{seed}-{case_index}",
                )
                python_response = engine.review(request)
                native_response = review_post_tool_native(request, observe_mode=False)
                assert native_response is not None, (seed, case_index)
                assert parity_signature(native_response) == parity_signature(python_response), (
                    seed,
                    case_index,
                    request.payload,
                    native_response,
                    python_response,
                )
        finally:
            close_resident_native_runtimes()


def test_mutation_corpus_is_deterministic() -> None:
    first = random.Random(_SEEDS[0])
    second = random.Random(_SEEDS[0])
    assert [_payload(first, index) for index in range(12)] == [_payload(second, index) for index in range(12)]
