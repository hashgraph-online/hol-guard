#!/usr/bin/env python3
"""Record ``local_cli_identify`` vectors from the retired Python.

The expected answers come only from the Python implementation that existed
before the resident owned unlisted-CLI identification (a scratch checkout of
the base commit, passed as ``--base-src``). They are never produced by the new
Rust kind, so the vectors stay an independent oracle for it.

Usage:
    record_local_cli_identify_vectors.py --base-src <base-checkout>/src \\
        --native-binary <hol-guard-runtime> --output <file>

The script runs twice: the parent builds the case catalogue, and a child
(``--oracle``) whose ``PYTHONPATH`` is the base checkout evaluates the old
functions on a materialized file tree per case. The machine-dependent engines
(launch identity, package intent) are replaced by the same deterministic fakes
the Rust test installs. The grant hash itself still comes from the resident's
``local_cli_identity`` kind, which the base already delegated to it.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from local_cli_identify_vector_cases import all_cases

BASE_COMMIT = "73c7eb5059"
SCRIPT_KINDS = {
    "python3": "python-script",
    "python": "python-script",
    "node": "node-script",
    "bash": "bash-script",
    "sh": "sh-script",
    "zsh": "zsh-script",
    "ruby": "ruby-script",
    "tsx": "tsx-script",
}


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
        path.write_text(spec)
    for path, target in links:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def _namespace(value):
    if isinstance(value, dict):
        return SimpleNamespace(**{key: _namespace(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_namespace(item) for item in value]
    return value


_ROOT: list[str] = []


def _sha(text: str) -> str:
    """Hash the root-independent form so the recorded digests replay anywhere."""

    if _ROOT:
        text = text.replace(_ROOT[0], "{ROOT}")
    return hashlib.sha256(text.encode()).hexdigest()


def fake_launch(executable, args=(), structured_command=False, cwd=None, home_dir=None, **_kwargs):
    """Deterministic launch identity; the Rust test's ``Fake`` mirrors it."""

    cwd = str(cwd)
    args = [str(arg) for arg in args]
    name = executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    first = args[0] if args else None

    def resolve(value: str) -> str:
        return value if value.startswith("/") else f"{cwd}/{value}"

    path = None
    if name in SCRIPT_KINDS and first is not None and first not in ("-c", "-m", "-e"):
        path = resolve(first)
        kind, status = SCRIPT_KINDS[name], "verified" if os.path.isfile(path) else "missing"
    elif first in ("-c", "-m"):
        kind = ("python-c" if first == "-c" else "python-m") if name.startswith("python") else "inline-script"
        status = "verified"
    elif name == "bun" and first == "run":
        path = f"{cwd}/package.json"
        kind, status = "bun-package-script", "verified"
    elif "/" in executable and name.endswith((".sh", ".py")):
        path = resolve(executable)
        kind, status = "direct-script", "verified" if os.path.isfile(path) else "missing"
    else:
        kind, status = "none", "not-applicable"
    entrypoint: dict[str, object] = {"kind": kind, "status": status}
    if path is not None:
        entrypoint["path"] = path
        entrypoint["sha256"] = _sha(path)
    exe_path = resolve(executable) if "/" in executable else f"/fake/bin/{name}"
    return {
        "fake_launch": True,
        "executable": {
            "path": exe_path,
            "sha256": _sha(exe_path),
            "status": "unverified" if "unverifiable" in name else "verified",
        },
        "entrypoint": entrypoint,
    }


def _reusable(identity: dict) -> bool:
    return "unreusable" not in str(identity["executable"]["path"])


def _run(case: dict) -> list[dict]:
    from codex_plugin_scanner.guard.native_local_cli_identity import track_local_cli_identity_failures
    from codex_plugin_scanner.guard.runtime import local_cli_identity, package_intent_parser

    # The retired module exists only in the base checkout the oracle imports.
    compound = importlib.import_module("codex_plugin_scanner.guard.runtime.local_cli_compound")

    request = case["request"]

    def parse_intent(command, workspace=None, home_dir=None):
        intent = case["intent"]
        if intent == "raise":
            raise RuntimeError("parser failed")
        if intent is None:
            return None
        return SimpleNamespace(local_executions=_namespace(intent))

    cwd = Path(request["cwd"])
    home = Path(request["home_dir"]) if request["home_dir"] is not None else None
    patches = [
        mock.patch.dict(os.environ, request["env"]),
        mock.patch.object(local_cli_identity, "build_runtime_launch_identity", fake_launch),
        mock.patch.object(local_cli_identity, "runtime_launch_identity_is_reusable", _reusable),
        mock.patch.object(package_intent_parser, "parse_package_intent", parse_intent),
    ]
    for patch in patches:
        patch.start()
    try:
        with track_local_cli_identity_failures() as failures:
            if request["compound"]:
                identify = compound.identify_unlisted_cli_identities
                identities = list(identify(request["command_text"], cwd=cwd, home_dir=home))
            else:
                single = local_cli_identity.identify_unlisted_cli(request["command_text"], cwd=cwd, home_dir=home)
                identities = [] if single is None else [single]
    finally:
        for patch in reversed(patches):
            patch.stop()
    if failures:
        raise SystemExit(f"native failure on {case['name']}: {failures}")
    return [
        {
            **identity.to_dict(),
            "source_path": identity.source_path,
            "path_class": identity.path_class,
            "runner": identity.runner,
            "identity_source": identity.identity_source,
        }
        for identity in identities
    ]


def _oracle(cases: list[dict]) -> list[list[dict]]:
    import codex_plugin_scanner
    from codex_plugin_scanner.guard.native_context import bind_context_digest_home

    base = Path(os.environ["LOCAL_CLI_IDENTIFY_BASE_SRC"]).resolve()
    assert Path(codex_plugin_scanner.__file__).resolve().is_relative_to(base), codex_plugin_scanner.__file__
    bind_context_digest_home(Path(os.environ["HOL_GUARD_HOME"]))
    out = []
    for case in cases:
        root = Path(os.path.realpath(tempfile.mkdtemp(prefix="lci-")))
        try:
            _ROOT[:] = [str(root)]
            concrete = json.loads(json.dumps(case).replace("{ROOT}", str(root)))
            _materialize(root, concrete["tree"])
            result = _run(concrete)
            out.append(json.loads(json.dumps(result).replace(str(root), "{ROOT}")))
        finally:
            shutil.rmtree(root, ignore_errors=True)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-src")
    parser.add_argument("--native-binary")
    parser.add_argument("--output")
    parser.add_argument("--oracle", nargs=2, metavar=("CASES", "RESULT"))
    args = parser.parse_args()
    if args.oracle:
        cases = json.loads(Path(args.oracle[0]).read_text())
        Path(args.oracle[1]).write_text(json.dumps(_oracle(cases)))
        return
    if not args.base_src or not args.output or not args.native_binary:
        parser.error("--base-src, --native-binary and --output are required")
    cases = all_cases()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
        cases_file = Path(scratch) / "cases.json"
        result_file = Path(scratch) / "result.json"
        guard_home = Path(scratch) / "guard-home"
        guard_home.mkdir()
        cases_file.write_text(json.dumps(cases))
        env = dict(
            os.environ,
            PYTHONPATH=str(Path(args.base_src).resolve()),
            LOCAL_CLI_IDENTIFY_BASE_SRC=args.base_src,
            HOL_GUARD_HOME=str(guard_home),
            HOL_GUARD_NATIVE="force",
            HOL_GUARD_NATIVE_BINARY=str(Path(args.native_binary).resolve()),
        )
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--oracle", str(cases_file), str(result_file)],
            check=True,
            env=env,
            cwd=scratch,
        )
        expected = json.loads(result_file.read_text())
    assert len(expected) == len(cases)
    vectors = [{**case, "expected": answer} for case, answer in zip(cases, expected, strict=True)]
    document = {"base_commit": BASE_COMMIT, "cases": vectors}
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if args.output.endswith(".gz"):
        encoded = gzip.compress(encoded, compresslevel=9, mtime=0)
    Path(args.output).write_bytes(encoded)
    print(f"recorded {len(vectors)} vectors")


if __name__ == "__main__":
    main()
