"""Pi and native output review must hash the same structured edit text."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from tests.pi_extension_response_callback_support import _run_generated_callback_payload
from tests.pi_extension_response_source_support import _generated_output_text_keys, _generated_source

EDIT_OUTPUTS: tuple[tuple[dict[str, object], str], ...] = (
    ({"originalFile": "before"}, "before"),
    ({"original_file": "before"}, "before"),
    ({"oldString": "old"}, "old"),
    ({"old_string": "old"}, "old"),
    ({"newString": "new"}, "new"),
    ({"new_string": "new"}, "new"),
    ({"structuredPatch": [{"lines": ["-old", "+new"]}]}, "-old+new"),
    ({"structured_patch": [{"lines": ["-old", "+new"]}]}, "-old+new"),
    ({"lines": ["-old", "+new"]}, "-old+new"),
    # Object insertion order must not change the native contract traversal.
    ({"newString": "new", "originalFile": "before", "stdout": "ok"}, "okbeforenew"),
    ({"result": {"newString": "caf\u00e9 \U0001f331"}}, "caf\u00e9 \U0001f331"),
)


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_generated_output_keys_match_native_order(tmp_path: Path, harness: str) -> None:
    generated = _generated_source(tmp_path, harness=harness)
    native_source = (Path(__file__).resolve().parents[1] / "rust/crates/guard-rules/src/lib.rs").read_text()
    native = re.search(r"pub const OUTPUT_TEXT_KEYS:.*?= &\[(.*?)\];", native_source, re.DOTALL)
    assert native is not None
    native_keys = re.findall(r'"([^"\n]+)"', native.group(1))
    pi_keys = re.findall(r'"([^"\n]+)"', _generated_output_text_keys(generated))
    assert pi_keys == native_keys


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(("content", "canonical_text"), EDIT_OUTPUTS)
def test_approved_structured_edit_is_preserved(
    tmp_path: Path, harness: str, content: dict[str, object], canonical_text: str
) -> None:
    digest = hashlib.sha256(canonical_text.encode()).hexdigest()
    response: dict[str, object] = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
    }
    result = _run_generated_callback_payload(_generated_source(tmp_path, harness=harness), content, response)
    assert result["preserved"] is True


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_structured_edit_with_incorrect_review_hash_is_withheld(tmp_path: Path, harness: str) -> None:
    # A response carrying the old empty-text hash must not authorize real text.
    response: dict[str, object] = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(b"").hexdigest(),
    }
    result = _run_generated_callback_payload(
        _generated_source(tmp_path, harness=harness), {"newString": "visible edit"}, response
    )
    assert result["preserved"] is False
    blocked = result["result"]
    assert isinstance(blocked, dict)
    assert blocked["isError"] is True
