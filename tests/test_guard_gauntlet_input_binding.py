"""The Guard input a native tool call was reviewed with is the input the host ran."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ci.gauntlet.evidence import assess_case
from ci.gauntlet.input_evidence import input_digest
from tests.test_guard_gauntlet import observed_case, ordinary


def test_host_execution_must_equal_the_complete_guard_input():
    """Reject host arguments that differ from the digest-verified input reviewed by Guard."""
    from ci.gauntlet.input_evidence import input_digest

    case = observed_case()
    reviewed = {"command": "different command"}
    case["guard_observations"][0].update(input=reviewed, input_sha256=input_digest(reviewed))
    result = assess_case(ordinary(), case)
    assert result["outcome"] == "harness-error"
    assert "input reviewed by Guard" in result["reason"]


def test_anchor_path_metadata_is_checked_instead_of_rejecting_real_omp_edits():
    """Accept derived edit metadata only when paths and edit bytes agree with the host call."""
    from ci.gauntlet.input_evidence import input_matches

    args = {"input": "[src/settings.ts#3BE2]\nPUT 2.=2:\n+  retryLimit: 5,"}
    derived = {**args, "path": "src/settings.ts", "paths": ["src/settings.ts"]}
    assert input_matches("edit", args, derived)
    assert not input_matches("edit", args, {**derived, "path": ".env"})
    assert not input_matches("edit", args, {**derived, "paths": ["src/settings.ts", ".env"]})
    assert not input_matches("edit", args, {**derived, "input": args["input"].replace("5", "9")})
    sibling_args = {
        "path": "{{home}}/other-project/notes.md",
        "input": "[notes.md#3BE2]\nPUT 1.=1:\n+Verified settings change.",
    }
    assert not input_matches("edit", sibling_args, {**sibling_args, "paths": [sibling_args["path"]]})


@pytest.mark.parametrize(
    ("before", "after", "closing"),
    [(" ", "", ""), ("\t", "\t", ""), (" \t", "  ", ""), (" ", "", " "), ("", "", "\t "), (" ", " ", " ")],
)
def test_native_header_padding_keeps_exact_patch_bytes_and_reviewed_target(before, after, closing):
    """Oh My Pi trims the whole header body, so `[ notes.md#FB48 ]` names notes.md."""
    from ci.gauntlet.input_evidence import input_matches
    from ci.gauntlet.proofs import _edit_path

    target = "src/a file.ts"
    args = {"input": f"[{before}{target}{after}#3BE2{closing}]\nPUT 1.=1:\n+changed"}
    reviewed = {**args, "path": target, "paths": [target]}
    assert input_matches("edit", args, reviewed)
    assert _edit_path(args) == target
    assert not input_matches("edit", args, {**reviewed, "path": ".env", "paths": [".env"]})
    assert not input_matches("edit", args, {**reviewed, "input": args["input"].replace("+changed", "+different")})
    assert not input_matches("edit", {**args, "path": "other.ts"}, reviewed)


@pytest.mark.parametrize("header", ["[ \t#3BE2]", "[ src/a.ts#3BE2]\n[src/b.ts#1B2C]"])
def test_empty_or_multiple_native_edit_targets_cannot_borrow_one_review(header):
    from ci.gauntlet.input_evidence import input_matches
    from ci.gauntlet.proofs import _edit_path

    args = {"input": header + "\nPUT 1.=1:\n+changed"}
    reviewed = {**args, "path": "src/a.ts", "paths": ["src/a.ts"]}
    assert not input_matches("edit", args, reviewed)
    assert _edit_path(args) is None


@pytest.mark.parametrize("path", ["src/one.ts", "./src/one.ts", "~/other-project/one.ts"])
def test_resolved_read_post_inputs_remain_bound_to_original_target(path):
    from ci.gauntlet.input_evidence import post_input_matches
    from ci.gauntlet.proofs import guard_inventory

    reviewed = {"path": path, "offset": 2, "limit": 4}
    target = "{{home}}/" + path[2:] if path.startswith("~/") else "{{workspace}}/" + path.removeprefix("./")
    completed = {**reviewed, "path": target}
    assert post_input_matches("read", reviewed, completed)
    rows = deepcopy(observed_case()["guard_observations"])
    for row, value in zip(rows, (reviewed, completed), strict=True):
        row.update(tool="read", input=value, input_sha256=input_digest(value))
    calls = [{"id": "c1", "name": "read", "args": reviewed, "is_error": False}]
    assert guard_inventory(calls, rows, {"native_resident": 2})[1] is None
    for altered in [
        {**completed, "path": "{{workspace}}/.env"},
        {**completed, "offset": 1},
        {**completed, "limit": 100},
        {**completed, "file_path": target},
    ]:
        assert not post_input_matches("read", reviewed, altered)
    rows[1]["input_sha256"] = "0" * 64
    assert guard_inventory(calls, rows, {"native_resident": 2})[1] == "missing or inconsistent Guard input digest"


@pytest.mark.parametrize("tool,path", [("write", "src/one.ts"), ("read", "../one.ts"), ("read", "src/../one.ts")])
def test_post_input_resolution_does_not_hide_mutation_or_traversal(tool, path):
    from ci.gauntlet.input_evidence import post_input_matches

    assert not post_input_matches(tool, {"path": path}, {"path": "{{workspace}}/" + path})


def test_read_selector_resolution_requires_actual_host_result_metadata():
    from ci.gauntlet.input_evidence import post_input_matches

    pre, post = {"path": "README.md:1-15"}, {"path": "{{workspace}}/README.md"}
    result = {
        "details": {"meta": {"source": {"type": "path", "value": post["path"]}}, "displayContent": {"startLine": 1}}
    }
    assert post_input_matches("read", pre, post, result)
    assert not post_input_matches("read", pre, post)
    assert not post_input_matches("read", pre, {"path": "{{workspace}}/.env"}, result)
    assert not post_input_matches("read", {"path": "README.md:15-1"}, post, result)
    assert not post_input_matches("read", pre, {**post, "limit": 500}, result)


def test_raw_read_selector_requires_whole_file_host_result_metadata():
    from ci.gauntlet.input_evidence import post_input_matches

    pre, post = {"path": "{{workspace}}/src/one.ts:raw"}, {"path": "{{workspace}}/src/one.ts"}
    result = {
        "details": {"meta": {"source": {"type": "path", "value": post["path"]}}, "displayContent": {"startLine": 1}}
    }
    assert post_input_matches("read", pre, post, result)
    assert not post_input_matches("read", pre, post)
    assert not post_input_matches("read", pre, {"path": "{{workspace}}/.env"}, result)
    assert not post_input_matches("read", pre, {**post, "limit": 500}, result)
    late = {"details": {**result["details"], "displayContent": {"startLine": 2}}}
    assert not post_input_matches("read", pre, post, late)
    for selector in ("img", "RAW", "1-5:RAW", "raw:raw", "1:raw:2", "conflicts"):
        assert not post_input_matches("read", {"path": f"src/one.ts:{selector}"}, post, result)


def test_compound_raw_selector_binds_with_the_same_host_result_proof():
    """OMP accepts a line range combined with raw in either order, as its own prelude does."""
    from ci.gauntlet.input_evidence import post_input_matches

    post = {"path": "{{workspace}}/src/one.ts"}
    result = {
        "details": {"meta": {"source": {"type": "path", "value": post["path"]}}, "displayContent": {"startLine": 1}}
    }
    for selector in ("1:raw", "1-5:raw", "raw:1", "raw:1-5"):
        pre = {"path": f"{{{{workspace}}}}/src/one.ts:{selector}"}
        assert post_input_matches("read", pre, post, result), selector
        assert not post_input_matches("read", pre, post), selector
        assert not post_input_matches("read", pre, {"path": "{{workspace}}/.env"}, result), selector
    for selector in ("2-5:raw", "raw:2-5", "raw:5-1", "5-1:raw"):
        assert not post_input_matches("read", {"path": f"{{{{workspace}}}}/src/one.ts:{selector}"}, post, result)


def test_windows_resolved_read_paths_bind_only_whole_backslash_form():
    from ci.gauntlet.input_evidence import post_input_matches

    reviewed = {"path": "src/settings.ts"}
    assert post_input_matches("read", reviewed, {"path": "{{workspace}}\\src\\settings.ts"})
    assert post_input_matches("read", {"path": "~/notes.md"}, {"path": "{{home}}\\notes.md"})
    for altered in [
        "{{workspace}}\\.env",
        "{{workspace}}\\src/settings.ts",
        "{{workspace}}\\src\\..\\settings.ts",
        "{{workspace}}/src\\settings.ts",
    ]:
        assert not post_input_matches("read", reviewed, {"path": altered})
    # On POSIX, a reviewed backslash is part of a file name, not a separator.
    windows_form = {"path": "{{workspace}}\\src\\settings.ts"}
    assert not post_input_matches("read", {"path": "src\\settings.ts"}, windows_form)


def test_public_guard_inputs_verify_original_bytes_then_share_host_redactions():
    """Verify raw input digests before redacting paths and recomputing the public digest."""
    import hashlib
    import json

    from ci.gauntlet.input_evidence import input_digest, public_observations

    raw = json.dumps({"path": "/tmp/private fixture/café.txt"}, ensure_ascii=False)
    observation = {"input_json": raw, "input_sha256": hashlib.sha256(raw.encode()).hexdigest()}
    exported = public_observations([observation], {"/tmp/private fixture": "{{workspace}}"})[0]
    assert exported["input"] == {"path": "{{workspace}}/café.txt"}
    assert exported["input_sha256"] == input_digest(exported["input"])
    assert exported["observed_input_sha256"] == observation["input_sha256"]
    assert "input_json" not in exported
    tampered = public_observations([{**observation, "input_json": "{}", "tool": "read"}], {})[0]
    assert tampered == {"tool": "read", "observer_error": True, "observer_error_code": "input_digest_mismatch"}
