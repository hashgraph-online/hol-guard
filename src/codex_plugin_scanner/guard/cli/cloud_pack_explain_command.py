"""``command explain --cloud``: show what Guard derives from one example cloud action call.

The native runtime checks the arguments against the action, derives the facts and joins
them with each shipped policy preset. This module only reads the optional pack file and the
example arguments, sends one request line and prints the answer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from ..extension_builder.errors import BuilderError
from ..extension_builder.io import canonical_json
from .extension_builder_cloud import native_pack_request, read_pack_line, refusal_text

_MAX_ARGUMENTS_CHARS = 64 * 1024


def run_cloud_explain(args: argparse.Namespace, *, output: TextIO | None = None) -> int:
    stream = output if output is not None else sys.stdout
    as_json = bool(getattr(args, "json", False))
    try:
        result = _explain(args)
    except BuilderError as exc:
        if as_json:
            print(canonical_json(exc.to_dict()), end="", file=stream)
        else:
            print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(canonical_json(result), end="", file=stream)
    else:
        _print(result, stream)
    return 0


def _explain(args: argparse.Namespace) -> dict[str, object]:
    action_id = str(getattr(args, "command_text", "")).strip()
    if not action_id:
        raise BuilderError("missing_action", "Name the action to explain, for example slack.chat.post_message.")
    raw = getattr(args, "arguments", None) or "{}"
    if len(raw) > _MAX_ARGUMENTS_CHARS:
        raise BuilderError("arguments_invalid", "--arguments is too long.")
    try:
        arguments = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BuilderError("arguments_invalid", "--arguments must be a JSON object.") from exc
    if not isinstance(arguments, dict):
        raise BuilderError("arguments_invalid", "--arguments must be a JSON object.")
    request = '{"op":"explain","actionId":' + json.dumps(action_id) + ',"arguments":'
    request += json.dumps(arguments, separators=(",", ":"))
    pack_path = getattr(args, "pack", None)
    if pack_path is not None:
        request += ',"pack":' + read_pack_line(Path(pack_path))
    reply = native_pack_request(request + "}", code="cloud_explain")
    if reply.get("ok") is not True:
        raise BuilderError("cloud_explain", f"The call could not be explained: {refusal_text(reply)}.")
    return {key: value for key, value in reply.items() if key != "ok"}


def _print(result: dict[str, object], stream: TextIO) -> None:
    print(f"{result.get('actionId')} ({result.get('providerId')}), effect {result.get('effect')}", file=stream)
    facts = result.get("facts")
    for key, value in (facts if isinstance(facts, dict) else {}).items():
        print(f"  {key}: {json.dumps(value, ensure_ascii=False)}", file=stream)
    decisions = result.get("decisions")
    decisions = decisions if isinstance(decisions, dict) else {}
    print("Default decision by preset: " + ", ".join(f"{k} {v}" for k, v in decisions.items()), file=stream)
    print("Workspace rules, capabilities and consent can still change the outcome.", file=stream)
