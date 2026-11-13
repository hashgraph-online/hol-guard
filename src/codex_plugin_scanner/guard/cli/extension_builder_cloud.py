"""``extensions generate|validate --cloud``: thin glue over the native ``cloud-action pack`` tools.

The native runtime owns parsing, classification, pack construction, validation and fixture
runs. This module only reads bounded input files, sends one request line per step and
reports or writes what comes back.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import TextIO

from ..extension_builder.errors import BuilderError
from ..extension_builder.io import read_bytes

CLOUD_SOURCES = ("openapi", "mcp")
# A source file is read up to 3 MiB; the encoded request line, which escaping can grow, is
# checked against the native 4 MiB line cap before it is sent.
_MAX_SOURCE_BYTES = 3 * 1024 * 1024
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_NATIVE_TIMEOUT_SECONDS = 30.0


def generate_cloud_draft(args: argparse.Namespace) -> dict[str, object]:
    if args.source_adapter not in CLOUD_SOURCES:
        raise BuilderError(
            "cloud_source", "Cloud drafts read an OpenAPI document (--from openapi) or an MCP tool list (--from mcp)."
        )
    if not args.slug:
        raise BuilderError("missing_metadata", "Provide --slug as the provider id of the cloud action pack.")
    try:
        text = read_bytes(args.input, limit=_MAX_SOURCE_BYTES).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuilderError("input_encoding", "The input must be UTF-8 JSON.") from exc
    request: dict[str, object] = {
        "op": "generate",
        "from": args.source_adapter,
        "document": text,
        "providerId": args.slug,
    }
    for key, value in (
        ("providerName", args.name),
        ("publisher", args.publisher_name),
        ("host", args.host),
        ("authMode", args.auth_mode),
    ):
        if value:
            request[key] = value
    reply = native_pack_request(request)
    if reply.get("ok") is not True:
        raise BuilderError("cloud_generate", f"The draft could not be built: {refusal_text(reply)}.")
    pack = reply.get("pack")
    if not isinstance(pack, dict) or not isinstance(pack.get("actions"), list):
        raise BuilderError("cloud_generate", "The native drafter returned an invalid pack.")
    _write_new(args.output, json.dumps(pack, indent=2, ensure_ascii=False) + "\n")
    return {
        "generated": True,
        "cloud": True,
        "providerId": args.slug,
        "actions": len(pack["actions"]),
        "output": str(args.output),
        "proposals": reply.get("proposals", []),
        "notes": reply.get("notes", []),
    }


def native_pack_request(request: dict[str, object] | str, *, code: str = "cloud_generate") -> dict[str, object]:
    """Send one request line to ``cloud-action pack``; a ``str`` is an already-encoded line."""
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BuilderError("native_runtime_unavailable", "The HOL Guard native runtime is required for cloud packs.")
    line = request if isinstance(request, str) else json.dumps(request, separators=(",", ":"))
    if len(line.encode("utf-8")) + 1 > _MAX_REQUEST_BYTES:
        raise BuilderError("input_too_large", "The request is larger than the native runtime accepts (4 MiB).")
    output = _run_native_process(
        status.identity.path,
        ("cloud-action", "pack"),
        input_text=line + "\n",
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        reply = json.loads(output or "")
    except json.JSONDecodeError as exc:
        raise BuilderError(code, "The native runtime did not answer.") from exc
    if not isinstance(reply, dict):
        raise BuilderError(code, "The native runtime returned an invalid answer.")
    return reply


def refusal_text(reply: dict[str, object]) -> str:
    error = reply.get("error")
    if not isinstance(error, dict):
        return "unknown"
    where = error.get("pointer") or error.get("argument")
    return f"{error.get('code')} at {where}" if isinstance(where, str) else str(error.get("code"))


def read_pack_line(path: Path) -> str:
    """The pack file as one JSON line, byte-for-byte otherwise.

    The native runtime parses the request strictly, so duplicate keys in the file are refused there
    rather than silently resolved here. JSON allows a raw line break only between tokens, so replacing
    line breaks with spaces does not change the document.
    """
    try:
        text = read_bytes(path, limit=_MAX_SOURCE_BYTES).decode("utf-8")
        shape = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuilderError("input_encoding", "The pack must be a UTF-8 JSON file.") from exc
    if not isinstance(shape, dict):
        raise BuilderError("input_encoding", "The pack must be a JSON object.")
    return text.replace("\r", " ").replace("\n", " ").strip()


def validate_cloud_pack(path: Path) -> dict[str, object]:
    pack = read_pack_line(path)
    checked = native_pack_request('{"op":"validate","pack":' + pack + "}", code="cloud_validate")
    if checked.get("ok") is not True:
        raise BuilderError("cloud_validate", f"The pack is not valid: {refusal_text(checked)}.")
    tested = native_pack_request('{"op":"test","pack":' + pack + "}", code="cloud_validate")
    report = tested.get("report")
    if tested.get("ok") is not True or not isinstance(report, dict):
        raise BuilderError("cloud_validate", f"The pack fixtures could not run: {refusal_text(tested)}.")
    results = report.get("results")
    results = results if isinstance(results, list) else []
    failures = [item for item in results if isinstance(item, dict) and not item.get("passed")]
    if failures:
        first = failures[0]
        raise BuilderError(
            "cloud_fixtures_failed",
            f"{len(failures)} of {report.get('total')} fixtures failed; first: "
            f'{first.get("actionId")} "{first.get("fixture")}": {first.get("failure")}.',
        )
    return {
        "validated": True,
        "cloud": True,
        "providerId": checked.get("providerId"),
        "actions": checked.get("actions"),
        "fixtures": report.get("total"),
    }


def _write_new(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError as exc:
        raise BuilderError("output_exists", "The output file already exists; choose a new path.") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def emit_cloud_summary(result: dict[str, object], output: TextIO) -> None:
    print(f"Drafted {result['actions']} cloud actions for {result['providerId']} in {result['output']}.", file=output)
    for proposal in result["proposals"] if isinstance(result["proposals"], list) else []:
        if isinstance(proposal, dict):
            evidence = ", ".join(str(item) for item in proposal.get("evidence") or []) or "no evidence"
            print(f"  {proposal.get('actionId')}: {proposal.get('class')} ({evidence})", file=output)
    notes = result["notes"] if isinstance(result["notes"], list) else []
    if notes:
        print(
            f"{len(notes)} notes need review; rerun with --json and a new --output path to list them.",
            file=output,
        )
    print("Add a safe and a risky fixture to every action, then run extensions validate --cloud.", file=output)
