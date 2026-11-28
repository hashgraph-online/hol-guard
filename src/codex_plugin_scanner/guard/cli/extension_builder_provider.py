"""``extensions generate|validate --provider``: thin glue over the native provider commands.

``generate`` sends a provider manifest to the native ``provider-recordings-draft`` command, which
drafts and checks a first ``recordings.json`` for it, and writes that file. ``validate`` runs the
native ``provider-conformance`` kit on the manifest, the same five checks as
``hol-guard integrations conformance``. Nothing here reads a key, calls a provider or decides
anything.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TextIO

from ..extension_builder.errors import BuilderError
from ..extension_builder.io import read_bytes
from .extension_builder_cloud import _write_new

# A provider manifest is at most 256 KiB natively; read a little more so the native refusal names it.
_MAX_MANIFEST_BYTES = 320 * 1024
_NATIVE_TIMEOUT_SECONDS = 60.0


def _native(command: str, request: dict[str, object], *, code: str) -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BuilderError(
            "native_runtime_unavailable", "The HOL Guard native runtime is required for provider integrations."
        )
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
        input_text=json.dumps(request, separators=(",", ":")) + "\n",
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        reply = json.loads(output or "")
    except json.JSONDecodeError as exc:
        raise BuilderError(code, "The native runtime did not answer.") from exc
    if not isinstance(reply, dict):
        raise BuilderError(code, "The native runtime returned an invalid answer.")
    return reply


def _refusal(reply: dict[str, object]) -> str:
    error = reply.get("error")
    return str(error.get("code")) if isinstance(error, dict) else "unknown"


def generate_provider_recordings(args: argparse.Namespace) -> dict[str, object]:
    if args.source_adapter != "manifest":
        raise BuilderError("provider_source", "Provider drafts read a provider manifest (--from manifest).")
    try:
        manifest = read_bytes(args.input, limit=_MAX_MANIFEST_BYTES).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuilderError("input_encoding", "The manifest must be UTF-8 JSON.") from exc
    reply = _native("provider-recordings-draft", {"manifest": manifest}, code="provider_generate")
    if reply.get("ok") is not True:
        raise BuilderError("provider_generate", f"No recordings could be drafted: {_refusal(reply)}.")
    text = reply.get("recordingsText")
    count = reply.get("recordings")
    if not isinstance(text, str) or not isinstance(count, int):
        raise BuilderError("provider_generate", "The native drafter returned invalid recordings.")
    # A new provider has no fixture directory yet. Write the exact text the native kit checked.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_new(args.output, text)
    return {
        "generated": True,
        "provider": True,
        "providerId": reply.get("provider_id"),
        "recordings": count,
        "output": str(args.output),
    }


def validate_provider_manifest(
    manifest: Path, recordings: Path | None = None, gate: Path | None = None
) -> dict[str, object]:
    request: dict[str, object] = {"manifest": str(manifest.expanduser().absolute())}
    if recordings is not None:
        request["recordings"] = str(recordings.expanduser().absolute())
    if gate is not None:
        request["gate"] = str(gate.expanduser().absolute())
    reply = _native("provider-conformance", request, code="provider_validate")
    if reply.get("ok") is not True:
        raise BuilderError("provider_validate", f"The conformance checks could not run: {_refusal(reply)}.")
    checks = reply.get("checks")
    return {
        "validated": True,
        "provider": True,
        "providerId": reply.get("provider_id"),
        "passed": reply.get("passed") is True,
        "recordings": reply.get("recordings"),
        "corpusRows": reply.get("corpus_rows"),
        "checks": checks if isinstance(checks, list) else [],
    }


def emit_provider_summary(command: str, result: dict[str, object], output: TextIO) -> None:
    if command == "generate":
        print(
            f"Drafted {result['recordings']} recorded responses for {result['providerId']} in {result['output']}.",
            file=output,
        )
        print(
            "Replace each placeholder body with a real response from the provider, keep the expectations "
            "honest, save the file as tests/fixtures/provider_integrations/<slug>/recordings.json, "
            "then run extensions validate --provider.",
            file=output,
        )
        return
    verdict = "passes" if result["passed"] else "fails"
    print(
        f"{result['providerId'] or 'The manifest'} {verdict} conformance "
        f"({result['recordings']} recordings, {result['corpusRows']} benign browser rows).",
        file=output,
    )
    for check in result["checks"] if isinstance(result["checks"], list) else []:
        if not isinstance(check, dict):
            continue
        print(f"  {'pass' if check.get('passed') is True else 'FAIL'}  {check.get('id')}", file=output)
        problems = check.get("problems")
        for problem in problems if isinstance(problems, list) else []:
            print(f"        {problem}", file=output)
