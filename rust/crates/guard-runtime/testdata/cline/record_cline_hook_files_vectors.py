#!/usr/bin/env python3
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
"""Record replay vectors for the native `cline_hook_files` runner-authority kind.

Run against a checkout whose `cline_hooks` module still renders the hook files
and computes the health verdict in Python (the base of the commit that
introduced the native kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output cline_hook_files_vectors.json>

`render` cases pin the worker configuration, launcher slot and launcher text
the original renderers produced for every event. `state` cases pin the
original verdict for each canary outcome, with the request a native caller
sends: the state file text, what was read back from each bound hook file and
the proof file texts.

The module it imports is the base checkout's, so the current tree's type
checker cannot see the Python renderers it records.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import cline_hooks

EVENTS = cline_hooks._EVENTS
MARKER = cline_hooks._MARKER
NOW = 1_800_000_000.5
MAX_AGE = cline_hooks._PROOF_MAX_AGE


def _exact_path(value: str) -> Path:
    path = Path(value)
    assert str(path) == value, value
    return path


def _render_case(
    name: str, *, windows: bool, runtime: str, guard_cli: list[str], adapter_state: str, base: str
) -> dict[str, object]:
    separator = "\\" if windows else "/"
    events = {
        event: {
            "worker": f"{base}{separator}hook-workers{separator}{event}.json",
            "proof": f"{base}{separator}proofs{separator}native-{event.lower()}.json",
        }
        for event in EVENTS
    }
    original_state = cline_hooks._adapter_state_path
    original_proof = cline_hooks._proof_path
    cline_hooks._adapter_state_path = lambda _context: _exact_path(adapter_state)
    cline_hooks._proof_path = lambda _context, event: _exact_path(events[event]["proof"])
    files: dict[str, object] = {}
    try:
        with tempfile.TemporaryDirectory() as root:
            for event in EVENTS:
                worker_path = _exact_path(events[event]["worker"])
                worker = cline_hooks._worker_config(
                    SimpleNamespace(guard_home=Path("/unused")),  # type: ignore[arg-type]
                    event_name=event,
                    guard_cli=list(guard_cli),
                )
                if windows:
                    launcher = cline_hooks._powershell_wrapper(
                        worker=worker_path, runtime=runtime, blocking=event == "PreToolUse"
                    )
                else:
                    launcher = cline_hooks._posix_wrapper(worker=worker_path, runtime=runtime)
                files[event] = {
                    "slot": cline_hooks._slot_for_event(Path(root), event, windows=windows).name,
                    "worker": worker,
                    "worker_sha256": sha256(worker.encode()).hexdigest(),
                    "launcher": launcher,
                    "launcher_sha256": sha256(launcher.encode()).hexdigest(),
                }
    finally:
        cline_hooks._adapter_state_path = original_state
        cline_hooks._proof_path = original_proof
    args = {
        "windows": windows,
        "runtime": runtime,
        "guard_cli": guard_cli,
        "adapter_state": adapter_state,
        "events": events,
    }
    return {"name": name, "args": args, "files": files}


def _render_cases() -> list[dict[str, object]]:
    bridge = ["/opt/guard/runtime", "bounded-cli-hook", '{"harness": "cline", "timeout_seconds": 8}']
    return [
        _render_case(
            "posix plain paths",
            windows=False,
            runtime="/opt/guard/hol-guard-native",
            guard_cli=bridge,
            adapter_state="/home/user/.hol-guard/managed/cline/adapter-state.json",
            base="/home/user/.hol-guard/managed/cline",
        ),
        _render_case(
            "posix spaces quotes dollars and backticks",
            windows=False,
            runtime='/opt/My Guard/it\'s $HOME `id` "x"/hol-guard-native',
            guard_cli=["/usr/bin/python3", "it's", "$(id)", "`id`", 'say "hi"', "tab\there", "line\nbreak"],
            adapter_state="/home/o'brien/.hol-guard/managed/cline/adapter-state.json",
            base="/home/o'brien/Guard $HOME `x`/managed/cline",
        ),
        _render_case(
            "posix unicode and safe punctuation",
            windows=False,
            runtime="/opt/gu@rd%+=:,.-_/hol-guard-native",
            guard_cli=["/home/日本語/python", "émoji-😀", "\u007f", "back\\slash"],
            adapter_state="/home/日本語/.hol-guard/managed/cline/adapter-state.json",
            base="/home/日本語/.hol-guard/managed/cline",
        ),
        _render_case(
            "posix empty guard argv and empty runtime",
            windows=False,
            runtime="",
            guard_cli=[],
            adapter_state="/state.json",
            base="/g",
        ),
        _render_case(
            "windows plain paths",
            windows=True,
            runtime="C:\\Program Files\\HOL Guard\\hol-guard-native.exe",
            guard_cli=["C:\\Python\\python.exe", "-m", "codex_plugin_scanner", "guard", "hook"],
            adapter_state="C:\\Users\\user\\.hol-guard\\managed\\cline\\adapter-state.json",
            base="C:\\Users\\user\\.hol-guard\\managed\\cline",
        ),
        _render_case(
            "windows quotes dollars backticks and unicode",
            windows=True,
            runtime='C:\\Users\\O\'Brien\\$env:TEMP\\`x`\\"q"\\日本\\hol-guard-native.exe',
            guard_cli=["C:\\Users\\O'Brien\\python.exe", "it''s", "$(whoami)", "😀"],
            adapter_state="C:\\Users\\O'Brien\\.hol-guard\\managed\\cline\\adapter-state.json",
            base="C:\\Users\\O'Brien\\.hol-guard\\managed\\cline",
        ),
    ]


def _proof(**fields: object) -> str:
    return json.dumps(fields)


LIVE_BLOCKED = _proof(timestamp=NOW - 10, source="cline", outcome="blocked")
LIVE_OBSERVED = _proof(timestamp=NOW - 10, source="cline", outcome="observed")
Spec = dict[str, str]


def _state_case(
    name: str,
    *,
    launchers: Spec | None = None,
    workers: Spec | None = None,
    state_override: Callable[[dict[str, object]], object] | None = None,
    state_text: str | None = None,
    proofs: dict[str, str | None] | None = None,
) -> dict[str, object]:
    """Build real files for one scenario and record the original verdict.

    Each event's spec names how its file and recorded entry look: ``ok``,
    ``modified`` (digest mismatch), ``unmanaged`` (no marker), ``unbound``
    (the recorded path is not a canonical slot), ``directory`` (unreadable),
    ``undecodable`` (bytes that are not UTF-8), ``path_not_str``,
    ``digest_not_str`` or ``omitted``.
    """

    launcher_spec = {event: "ok" for event in EVENTS} | (launchers or {})
    worker_spec = {event: "ok" for event in EVENTS} | (workers or {})
    proof_texts: dict[str, str | None] = {"PreToolUse": LIVE_BLOCKED, "PostToolUse": LIVE_OBSERVED} | (proofs or {})
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        bound: dict[str, Path] = {}

        def plant(kind: str, spec: Spec) -> tuple[dict[str, object], dict[str, object]]:
            recorded: dict[str, object] = {}
            digests: dict[str, object] = {}
            for event in EVENTS:
                shape = spec[event]
                path = base / kind / event
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"# {MARKER}\n{kind} {event}\n".encode()
                if shape == "unmanaged":
                    content = f"user {kind} {event}\n".encode()
                if shape == "undecodable":
                    content = f"# {MARKER}\n".encode() + b"\xff\xfe"
                if shape == "directory":
                    path.mkdir()
                else:
                    path.write_bytes(content)
                if shape != "unbound":
                    bound[str(path)] = path
                if shape == "omitted":
                    continue
                recorded[event] = 7 if shape == "path_not_str" else str(path)
                if shape == "digest_not_str":
                    digests[event] = None
                elif shape == "modified":
                    digests[event] = "0" * 64
                else:
                    digests[event] = sha256(content).hexdigest()
            return recorded, digests

        paths, digests = plant("launchers", launcher_spec)
        worker_paths, worker_digests = plant("workers", worker_spec)
        state: dict[str, object] = {
            "schema_version": 1,
            "root": str(base / "launchers"),
            "paths": paths,
            "sha256": digests,
            "workers": worker_paths,
            "worker_sha256": worker_digests,
        }
        if state_text is None:
            document = state_override(state) if state_override is not None else state
            state_text = json.dumps(document, ensure_ascii=False)
        state_file = base / "native-hooks-state.json"
        if state_text != "<missing>":
            state_file.write_text(state_text, encoding="utf-8")
        proof_files = {}
        for event in ("PreToolUse", "PostToolUse"):
            proof_file = base / "proofs" / event
            proof_file.parent.mkdir(exist_ok=True)
            if proof_texts[event] is not None:
                proof_file.write_text(str(proof_texts[event]), encoding="utf-8")
            proof_files[event] = proof_file

        def canonical(_context: object, _event: str, value: object, **_kwargs: object) -> Path | None:
            return bound.get(value) if isinstance(value, str) else None

        def observed(group: object) -> dict[str, object]:
            result: dict[str, object] = {}
            for event in EVENTS:
                path = canonical(None, event, group.get(event) if isinstance(group, dict) else None)
                try:
                    actual = sha256(path.read_bytes()).hexdigest() if path is not None else None
                except OSError:
                    actual = None
                result[event] = None if actual is None else {"sha256": actual, "managed": cline_hooks._managed(path)}
            return result

        try:
            loaded = json.loads(state_text) if state_text != "<missing>" else {}
        except json.JSONDecodeError:
            loaded = {}
        loaded = loaded if isinstance(loaded, dict) else {}
        args = {
            "now": NOW,
            "state_text": None if state_text == "<missing>" else state_text,
            "launchers": observed(loaded.get("paths")),
            "workers": observed(loaded.get("workers")),
            "proofs": {event: proof_texts[event] for event in ("PreToolUse", "PostToolUse")},
        }
        verdicts: dict[str, object] = {}
        called: list[bool] = []
        saved = (
            cline_hooks._state_path,
            cline_hooks._proof_path,
            cline_hooks._canonical_state_path,
            cline_hooks.run_cline_hook_canary,
            cline_hooks.time,
        )
        try:
            cline_hooks._state_path = lambda _context: state_file
            cline_hooks._proof_path = lambda _context, event: proof_files[event]
            cline_hooks._canonical_state_path = canonical  # type: ignore[assignment]
            cline_hooks.time = SimpleNamespace(time=lambda: NOW)  # type: ignore[assignment]
            for label, ok in (("canary_ok", True), ("canary_failed", False)):
                calls: list[bool] = []
                cline_hooks.run_cline_hook_canary = lambda _context, ok=ok, calls=calls: (
                    calls.append(True) or {"ok": ok}
                )
                verdicts[label] = cline_hooks.cline_native_hook_state(SimpleNamespace())  # type: ignore[arg-type]
                called.append(bool(calls))
        finally:
            (
                cline_hooks._state_path,
                cline_hooks._proof_path,
                cline_hooks._canonical_state_path,
                cline_hooks.run_cline_hook_canary,
                cline_hooks.time,
            ) = saved
    assert called[0] == called[1]
    return {"name": name, "args": args, "canary_called": called[0], "verdicts": verdicts}


def _state_cases() -> list[dict[str, object]]:
    return [
        _state_case("healthy install with live proofs"),
        _state_case("healthy install without proofs", proofs={"PreToolUse": None, "PostToolUse": None}),
        _state_case("missing state file", state_text="<missing>"),
        _state_case("state file is not json", state_text="{not json"),
        _state_case("state file is a list", state_text="[1, 2]"),
        _state_case("state file is empty", state_text=""),
        _state_case("launcher digests are not an object", state_override=lambda s: {**s, "sha256": None}),
        _state_case("launcher paths are not an object", state_override=lambda s: {**s, "paths": ["x"]}),
        _state_case("workers are not an object", state_override=lambda s: {**s, "workers": "x"}),
        _state_case(
            "worker digests are absent", state_override=lambda s: {k: v for k, v in s.items() if k != "worker_sha256"}
        ),
        _state_case(
            "every launcher failure shape",
            launchers={
                "PreToolUse": "modified",
                "PostToolUse": "unmanaged",
                "UserPromptSubmit": "unbound",
                "TaskStart": "directory",
                "TaskError": "path_not_str",
                "SessionShutdown": "digest_not_str",
            },
        ),
        _state_case(
            "every worker failure shape",
            workers={
                "PreToolUse": "omitted",
                "PostToolUse": "modified",
                "UserPromptSubmit": "undecodable",
                "TaskStart": "unmanaged",
                "TaskError": "unbound",
                "SessionShutdown": "directory",
            },
        ),
        _state_case("only modified files", launchers={"TaskStart": "modified"}, workers={"TaskError": "modified"}),
        _state_case(
            "undecodable launcher keeps its digest but is not managed", launchers={"PreToolUse": "undecodable"}
        ),
        _state_case(
            "proof freshness boundary",
            proofs={
                "PreToolUse": _proof(timestamp=NOW - MAX_AGE, source="cline", outcome="blocked"),
                "PostToolUse": _proof(timestamp=NOW - MAX_AGE - 0.25, source="cline", outcome="observed"),
            },
        ),
        _state_case(
            "integer and future timestamps",
            proofs={
                "PreToolUse": _proof(timestamp=int(NOW) - 5, source="cline", outcome="blocked"),
                "PostToolUse": _proof(timestamp=NOW + 1000, source="cline", outcome="observed"),
            },
        ),
        _state_case(
            "proofs from another source or outcome",
            proofs={
                "PreToolUse": _proof(timestamp=NOW, source="codex", outcome="blocked"),
                "PostToolUse": _proof(timestamp=NOW, source="cline", outcome="allowed"),
            },
        ),
        _state_case(
            "proof timestamps that are not numbers",
            proofs={
                "PreToolUse": _proof(timestamp="1800000000", source="cline", outcome="blocked"),
                "PostToolUse": _proof(timestamp=True, source="cline", outcome="observed"),
            },
        ),
        _state_case(
            "proofs without timestamps or outcomes",
            proofs={"PreToolUse": _proof(source="cline"), "PostToolUse": _proof(timestamp=NOW, source="cline")},
        ),
        _state_case(
            "proof outcomes of any shape",
            proofs={
                "PreToolUse": _proof(timestamp=NOW, source="cline", outcome={"nested": [1, 2.5, None, "блок"]}),
                "PostToolUse": _proof(timestamp=NOW, source="cline", outcome=None),
            },
        ),
        _state_case(
            "proof files that are not json",
            proofs={"PreToolUse": "{", "PostToolUse": ""},
        ),
        _state_case(
            "proof whitespace around the document",
            proofs={"PreToolUse": "\n " + LIVE_BLOCKED + "\r\n\t", "PostToolUse": LIVE_OBSERVED},
        ),
        _state_case(
            "unicode state paths",
            state_override=lambda s: {**s, "root": "/home/日本語/hooks"},
        ),
    ]


def main() -> None:
    output = Path(sys.argv[1])
    document = {
        "schema": "guard-cline-hook-files-vectors.v1",
        "now": NOW,
        "render": _render_cases(),
        "state": _state_cases(),
    }
    with output.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main()
