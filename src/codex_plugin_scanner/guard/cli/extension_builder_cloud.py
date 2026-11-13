"""``extensions generate --cloud``: pass an exported API description to the native drafter.

The native runtime owns parsing, classification and pack construction. This module only
reads the bounded input file, sends it as one ``cloud-action pack`` request and writes the
draft it returns to a new file.
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
# The native request line is capped at 4 MiB; escaping can grow the text, so stay well below.
_MAX_SOURCE_BYTES = 3 * 1024 * 1024
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
        error = reply.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        pointer = error.get("pointer") if isinstance(error, dict) else None
        where = f" at {pointer}" if isinstance(pointer, str) else ""
        raise BuilderError("cloud_generate", f"The draft could not be built: {code}{where}.")
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


def native_pack_request(request: dict[str, object]) -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BuilderError("native_runtime_unavailable", "The HOL Guard native runtime is required for cloud drafts.")
    output = _run_native_process(
        status.identity.path,
        ("cloud-action", "pack"),
        input_text=json.dumps(request, separators=(",", ":")) + "\n",
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        reply = json.loads(output or "")
    except json.JSONDecodeError as exc:
        raise BuilderError("cloud_generate", "The native drafter did not answer.") from exc
    if not isinstance(reply, dict):
        raise BuilderError("cloud_generate", "The native drafter returned an invalid answer.")
    return reply


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
        print(f"{len(notes)} notes need review; rerun with --json to list them.", file=output)
    print("Add a safe and a risky fixture to every action, then run the pack validator.", file=output)
