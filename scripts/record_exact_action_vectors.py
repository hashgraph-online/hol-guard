#!/usr/bin/env python3
"""Record exact-action and review-binding vectors from the retired Python.

The expected answers come only from the Python implementation that existed
before the resident owned these proofs (a scratch checkout of the base commit,
passed as ``--base-src``). They are never produced by the Rust runtime, so the
vectors stay an independent oracle for it.

Usage:
    record_exact_action_vectors.py --base-src <base-checkout>/src --output <file>

The script runs twice: the parent builds the case catalogue, and a child
(``--oracle``) whose ``PYTHONPATH`` is the base checkout evaluates the old
functions on a materialized file tree per case. The two resident engines that
depend on the machine (launch identity, package intent) are replaced by the
same deterministic fakes the Rust test installs.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from exact_action_vector_cases import all_cases

BASE_COMMIT = "8927f7bf57"
FAKE_TOKEN = "guard-approval-context:v1:AAAA"
GIT_DIGEST_MARK = "{GIT_CONFIG_DIGEST}"
FILE_MARK = "{FILE_SHA}"


def _fill(spec: dict) -> bytes:
    return (spec.get("char", "x") * spec["fill"]).encode()


def _materialize(root: Path, tree: dict) -> None:
    links = []
    for rel, spec in sorted(tree.items(), key=lambda item: item[0].count("/")):
        if spec is None:
            continue
        path = root / rel
        if isinstance(spec, dict) and "symlink" in spec:
            links.append((path, spec["symlink"]))
            continue
        if isinstance(spec, dict) and spec.get("dir"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_dir():
            raise SystemExit(f"tree conflict: {rel}")
        path.write_bytes(_fill(spec) if isinstance(spec, dict) else spec.encode())
    for path, target in links:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def _namespace(value):
    if isinstance(value, dict):
        return SimpleNamespace(**{key: _namespace(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_namespace(item) for item in value]
    return value


def _fake_launch(executable, args=(), structured_command=False, cwd=None, home_dir=None, **_kwargs):
    return {
        "fake_launch": True,
        "executable": executable,
        "args": [str(arg) for arg in args],
        "cwd": str(cwd),
        "home": str(home_dir) if home_dir is not None else None,
    }


def _native_result(facts: dict) -> dict:
    result = {
        key: facts[key]
        for key in ("decision", "minimum_action", "policy_action", "reason_code")
        if facts.get(key) is not None
    }
    if facts.get("action_type") is not None:
        result["action"] = {"action_type": facts["action_type"]}
    return result


def _stub_binding(state: dict):
    def stub(*, harness, native_result, verified_receipt):
        if state["state"] == "invalid":
            raise ValueError("invalid")
        if state["state"] == "unbound":
            return None
        return dict(state["value"])

    return stub


class _PathProxy:
    def __init__(self, real, system_git: str) -> None:
        self._real = real
        self._system_git = system_git

    def __call__(self, *parts):
        if parts == ("/etc/gitconfig",):
            parts = (self._system_git,)
        return self._real(*parts)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _preimage(text: str, file_text: dict) -> str:
    """The digest's pairs, with config files that name the root kept as text."""

    pairs = [[key, FILE_MARK + file_text[value] if value in file_text else value] for key, value in json.loads(text)]
    return GIT_DIGEST_MARK + json.dumps(pairs, separators=(",", ":"))


def _replace_digests(value, preimages: dict):
    """A git config digest hashes absolute paths, so the vector keeps its preimage."""

    if isinstance(value, str):
        return preimages.get(value, value)
    if isinstance(value, list):
        return [_replace_digests(item, preimages) for item in value]
    if isinstance(value, dict):
        return {key: _replace_digests(item, preimages) for key, item in value.items()}
    return value


def _run_exact(case: dict, root: Path) -> dict:
    from codex_plugin_scanner.guard.daemon import (
        hook_native_exact_identity,
        hook_native_launch_identity,
        hook_native_saved_approval,
    )
    from codex_plugin_scanner.guard.runtime import package_intent_parser

    query = case["request"]["query"]
    captured: dict = {}

    def build_token(**kwargs):
        captured.update(kwargs)
        return FAKE_TOKEN

    def parse_intent(command, workspace=None, home_dir=None):
        intent = case["intent"]
        if intent == "raise":
            raise RuntimeError("parser failed")
        if intent is None:
            return None
        return SimpleNamespace(local_executions=_namespace(intent))

    payload: dict = {}
    if query["tool_input"] is not None:
        payload["tool_input"] = {key: value for key, value in query["tool_input"]}
    raw_cwd = case["raw_cwd"]
    if raw_cwd is not None:
        payload["cwd"] = raw_cwd
    from codex_plugin_scanner.guard.daemon.hook_request_parsing import pre_tool_command

    assert pre_tool_command(payload) == query["command"], case["name"]
    workspace = Path(query["workspace"]) if query["workspace"] is not None else None
    home = Path(query["home_dir"]) if query["home_dir"] is not None else None
    preimages: dict[str, str] = {}
    real_dumps = json.dumps

    def recording_dumps(value, *args, **kwargs):
        text = real_dumps(value, *args, **kwargs)
        pairs = isinstance(value, list) and value and all(isinstance(item, tuple) and len(item) == 2 for item in value)
        if pairs and kwargs.get("separators") == (",", ":"):
            preimages[hashlib.sha256(text.encode("utf-8")).hexdigest()] = text
        return text

    patches = [
        mock.patch.object(hook_native_exact_identity.json, "dumps", recording_dumps),
        mock.patch.dict(os.environ, query["environment"], clear=True),
        mock.patch.object(
            hook_native_saved_approval, "native_review_policy_binding", _stub_binding(query["policy_binding"])
        ),
        mock.patch.object(hook_native_saved_approval, "build_approval_context_token", build_token),
        mock.patch.object(hook_native_saved_approval, "parse_approval_context_token", lambda token: object()),
        mock.patch.object(hook_native_launch_identity, "build_runtime_launch_identity", _fake_launch),
        mock.patch.object(
            hook_native_launch_identity,
            "runtime_launch_identity_is_reusable",
            lambda identity: "unreusable" not in str(identity.get("executable")),
        ),
        mock.patch.object(package_intent_parser, "parse_package_intent", parse_intent),
        mock.patch.object(hook_native_exact_identity, "Path", _PathProxy(Path, str(root / "etc" / "gitconfig"))),
    ]
    for patch in patches:
        patch.start()
    try:
        token, reason = hook_native_saved_approval.native_exact_action_decision(
            harness=query["harness"],
            tool_name=query["tool_name"],
            payload=payload,
            native_result=_native_result(query["facts"]),
            native_receipt=None,
            workspace=workspace,
            home_dir=home,
        )
    finally:
        for patch in reversed(patches):
            patch.stop()
    components = None
    if token is not None:
        components = {key: captured[key] for key in ("identity", "content", "capabilities", "policy", "sandbox")}
        file_text = {
            hashlib.sha256(spec.encode()).hexdigest(): spec
            for spec in case["tree"].values()
            if isinstance(spec, str) and str(root) in spec
        }
        resolved = {digest: _preimage(text, file_text) for digest, text in preimages.items()}
        components = _replace_digests(components, resolved)
    return {"token_present": token is not None, "once_only_reason": reason, "components": components}


def _run_binding(case: dict) -> dict:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval

    query = case["request"]["query"]
    payload = {"tool_input": {"command": query["command"]}} if query["command"] is not None else {}
    workspace = Path("/workspace") if query["workspace_bound"] else None
    with mock.patch.object(
        hook_native_review_approval, "native_review_policy_binding", _stub_binding(query["policy_binding"])
    ):
        binding = hook_native_review_approval._native_review_binding(
            query["harness"], payload, _native_result(query["facts"]), query["receipt"], workspace
        )
    return {"binding": binding}


def _oracle(cases: list[dict]) -> list[dict]:
    import codex_plugin_scanner

    out = []
    base = Path(os.environ["EXACT_ACTION_BASE_SRC"]).resolve()
    assert Path(codex_plugin_scanner.__file__).resolve().is_relative_to(base), codex_plugin_scanner.__file__
    for case in cases:
        root = Path(os.path.realpath(tempfile.mkdtemp(prefix="eav-")))
        try:
            text = json.dumps(case).replace("{ROOT}", str(root))
            concrete = json.loads(text)
            _materialize(root, concrete["tree"])
            try:
                is_exact = concrete["family"] == "exact_action"
                result = _run_exact(concrete, root) if is_exact else _run_binding(concrete)
            except Exception as error:
                raise SystemExit(f"oracle crashed on {case['name']}: {error!r}") from error
            out.append(json.loads(json.dumps(result).replace(str(root), "{ROOT}")))
        finally:
            shutil.rmtree(root, ignore_errors=True)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-src")
    parser.add_argument("--output")
    parser.add_argument("--oracle", nargs=2, metavar=("CASES", "RESULT"))
    args = parser.parse_args()
    if args.oracle:
        cases = json.loads(Path(args.oracle[0]).read_text())
        Path(args.oracle[1]).write_text(json.dumps(_oracle(cases)))
        return
    if not args.base_src or not args.output:
        parser.error("--base-src and --output are required")
    cases = all_cases()
    with tempfile.TemporaryDirectory() as scratch:
        cases_file = Path(scratch) / "cases.json"
        result_file = Path(scratch) / "result.json"
        cases_file.write_text(json.dumps(cases))
        env = dict(os.environ, PYTHONPATH=str(Path(args.base_src).resolve()), EXACT_ACTION_BASE_SRC=args.base_src)
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--oracle", str(cases_file), str(result_file)],
            check=True,
            env=env,
            cwd=scratch,
        )
        expected = json.loads(result_file.read_text())
    assert len(expected) == len(cases)
    vectors = [{**case, "expected": answer} for case, answer in zip(cases, expected, strict=True)]
    for vector in vectors:
        vector.pop("raw_cwd", None)
    document = {"base_commit": BASE_COMMIT, "cases": vectors}
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if args.output.endswith(".gz"):
        encoded = gzip.compress(encoded, compresslevel=9, mtime=0)
    Path(args.output).write_bytes(encoded)
    print(f"recorded {len(vectors)} vectors")


if __name__ == "__main__":
    main()
