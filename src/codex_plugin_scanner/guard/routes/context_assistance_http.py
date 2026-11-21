"""HTTP framing for the CIGAR routes the daemon still answers.

The Rust daemon answers the built-in engine's own routes (status, setup,
workspace access, folders, versions and jobs). These three edit Codex config
or read Guard's usage records, so they stay here.
"""

from __future__ import annotations

from typing import Any

from . import codex_lean_http, codex_short_replies_http, context_usage_http

READ_PATHS = {
    codex_lean_http.PATH: codex_lean_http.KIND,
    codex_short_replies_http.PATH: codex_short_replies_http.KIND,
    context_usage_http.PATH: context_usage_http.KIND,
}
WRITE_PATHS = {
    codex_lean_http.PATH: codex_lean_http.KIND,
    codex_short_replies_http.PATH: codex_short_replies_http.KIND,
}


def respond(handler: Any, kind: str, payload: dict[str, object] | None = None) -> None:
    if kind == codex_lean_http.KIND:
        codex_lean_http.respond(handler, payload)
        return
    if kind == codex_short_replies_http.KIND:
        codex_short_replies_http.respond(handler, payload)
        return
    if kind == context_usage_http.KIND:
        context_usage_http.respond(handler)
        return
    raise ValueError(kind)
