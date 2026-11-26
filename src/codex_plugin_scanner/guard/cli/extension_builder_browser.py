"""``extensions generate|validate --browser``: thin glue over the native ``browser-driver`` command.

The native runtime drafts and compiles browser driver profiles. This module reads bounded input
files, sends one request line and reports or writes what comes back.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TextIO

from ..extension_builder.errors import BuilderError
from ..extension_builder.io import read_bytes
from .extension_builder_cloud import _write_new

# A browser driver profile is at most 256 KiB; a tool list is read up to 3 MiB. The encoded
# request line is checked against the native 4 MiB line cap before it is sent.
_MAX_SOURCE_BYTES = 3 * 1024 * 1024
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_NATIVE_TIMEOUT_SECONDS = 30.0


def _read_text(path: Path, what: str) -> str:
    try:
        return read_bytes(path, limit=_MAX_SOURCE_BYTES).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuilderError("input_encoding", f"The {what} must be UTF-8 JSON.") from exc


def native_browser_request(request: dict[str, object], *, code: str) -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BuilderError(
            "native_runtime_unavailable", "The HOL Guard native runtime is required for browser drivers."
        )
    line = json.dumps(request, separators=(",", ":"))
    if len(line.encode("utf-8")) + 1 > _MAX_REQUEST_BYTES:
        raise BuilderError("input_too_large", "The request is larger than the native runtime accepts (4 MiB).")
    output = _run_native_process(
        status.identity.path,
        ("browser-driver", "--stdin"),
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


def _refusal(reply: dict[str, object]) -> str:
    error = reply.get("error")
    return str(error.get("code")) if isinstance(error, dict) else "unknown"


def generate_browser_draft(args: argparse.Namespace) -> dict[str, object]:
    if args.source_adapter != "mcp":
        raise BuilderError("browser_source", "Browser driver drafts read an MCP tool list (--from mcp).")
    if not args.slug or not args.server:
        raise BuilderError("missing_metadata", "Provide --slug for the driver id and --server for the MCP server name.")
    request: dict[str, object] = {
        "op": "generate",
        "document": _read_text(args.input, "tool list"),
        "slug": args.slug,
        "server": args.server,
    }
    for key, value in (
        ("name", args.name),
        ("publisher", args.publisher_name or args.publisher),
        ("package", args.package),
    ):
        if value:
            request[key] = value
    reply = native_browser_request(request, code="browser_generate")
    if reply.get("ok") is not True:
        raise BuilderError("browser_generate", f"The draft could not be built: {_refusal(reply)}.")
    profile = reply.get("profile")
    profile_text = reply.get("profileText")
    if not isinstance(profile, dict) or not isinstance(profile.get("tools"), list) or not isinstance(profile_text, str):
        raise BuilderError("browser_generate", "The native drafter returned an invalid profile.")
    # Write the exact text the native compiler checked, so the file on disk is the one it accepted.
    _write_new(args.output, profile_text)
    return {
        "generated": True,
        "browser": True,
        "driverId": profile.get("id"),
        "tools": len(profile["tools"]),
        "output": str(args.output),
        "proposals": reply.get("proposals", []),
        "notes": reply.get("notes", []),
    }


def validate_browser_driver(path: Path) -> dict[str, object]:
    reply = native_browser_request({"op": "validate", "profile": _read_text(path, "profile")}, code="browser_validate")
    if reply.get("ok") is not True:
        raise BuilderError("browser_validate", f"The profile is not valid: {_refusal(reply)}.")
    return {
        "validated": True,
        "browser": True,
        "driverId": reply.get("id"),
        "tools": reply.get("tools"),
        "verbs": reply.get("verbs", {}),
        "otherTools": reply.get("otherTools", []),
        "firstPartyOverlap": reply.get("firstPartyOverlap", []),
        "profileMode": reply.get("profileMode"),
    }


_OMISSION_NOTES = {
    "tool_name_unsupported": (
        "Skipped {tool}: Guard tool names are at most 64 characters of lowercase letters, digits, '.', '_' or '-'."
    ),
    "tool_limit": "Skipped {tool}: a profile holds at most 256 tools.",
    "tool_skipped": "Skipped a tool list entry: {detail}.",
}


_SHOWN_NAME_LIMIT = 80


def _shown(value: object) -> str:
    """A tool list value made safe to print: control characters become '?' and long text is cut."""
    text = str(value)
    shown = "".join(character if character.isprintable() else "?" for character in text[:_SHOWN_NAME_LIMIT])
    return shown + ("..." if len(text) > _SHOWN_NAME_LIMIT else "")


def _emit_omissions(notes: object, output: TextIO) -> None:
    for note in notes if isinstance(notes, list) else []:
        if not isinstance(note, dict):
            continue
        code = note.get("code")
        template = _OMISSION_NOTES.get(code) if isinstance(code, str) else None
        if template:
            print(
                "  "
                + template.format(
                    tool=_shown(note.get("tool", "a tool")), detail=_shown(note.get("detail", "unreadable"))
                ),
                file=output,
            )


def emit_browser_summary(command: str, result: dict[str, object], output: TextIO) -> None:
    if command == "generate":
        print(f"Drafted {result['tools']} tools for {result['driverId']} in {result['output']}.", file=output)
        for proposal in result["proposals"] if isinstance(result["proposals"], list) else []:
            if isinstance(proposal, dict):
                evidence = proposal.get("evidence") or "no matching name"
                print(f"  {proposal.get('tool')}: {proposal.get('verb')} ({evidence})", file=output)
        _emit_omissions(result["notes"], output)
        print(
            "Check every verb, set profileMode once you know how the driver launches its browser, "
            "then run extensions validate --browser.",
            file=output,
        )
        return
    print(
        f"Validated {result['driverId']}: {result['tools']} tools, profile mode {result['profileMode']}.", file=output
    )
    other = result["otherTools"] if isinstance(result["otherTools"], list) else []
    if other:
        print(f"Unclassified tools (reviewed as privileged): {', '.join(map(str, other))}.", file=output)
    overlap = result["firstPartyOverlap"] if isinstance(result["firstPartyOverlap"], list) else []
    if overlap:
        print(f"A shipped profile already matches this driver: {', '.join(map(str, overlap))}.", file=output)
