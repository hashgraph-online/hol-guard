"""Version-bound MCP setup and rollback using the supported Codex config API.

Guard's native runtime does the work (`codex-mcp-setup`): it starts the Codex
app-server, reads and checks the config layers, writes or removes the one
`mcp_servers.<name>` entry bound to the user layer's version, and reads it
back. This module sends it the request, runs the caller's bookkeeping between
the write and the end of setup, and turns the answer into a receipt or a
reason code.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass

_FEATURE = "native-codex-mcp-setup-v1"
_COMMAND = "codex-mcp-setup"
_OUTPUT_LIMIT = 64 * 1024
# The native session ends itself, and its Codex host, within 60 seconds in all
# (`SESSION_LIMIT`). This deadline only backstops it: it kills the native process,
# which cannot clean up after itself, so it must stay above that limit.
_TIMEOUT_SECONDS = 75.0
_NATIVE_UNAVAILABLE = "codex_setup_native_unavailable"


@dataclass(frozen=True)
class CodexMcpSetupReceipt:
    name: str
    file_path: str
    version: str
    entry_json: str
    previous_version: str | None = None


def _ask(request: dict[str, object]) -> dict[str, object]:
    from ..mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        json.dumps(request, sort_keys=True),
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise ValueError(_NATIVE_UNAVAILABLE)
    return answer


def _host(executable: str) -> dict[str, object]:
    # The native runtime starts with a minimal environment of its own: the host
    # gets the one this process has, from the folder this process is in.
    return {"executable": executable, "cwd": os.getcwd(), "environment": dict(os.environ)}


def _reason(answer: dict[str, object]) -> str | None:
    error = answer.get("error")
    if error is None:
        return None
    if not isinstance(error, str):
        raise ValueError(_NATIVE_UNAVAILABLE)
    return error


def _receipt(value: object) -> CodexMcpSetupReceipt:
    if not isinstance(value, dict):
        raise ValueError(_NATIVE_UNAVAILABLE)
    name, file_path, version, entry_json = (value.get(key) for key in ("name", "file_path", "version", "entry_json"))
    previous = value.get("previous_version")
    if (
        not isinstance(name, str)
        or not isinstance(file_path, str)
        or not isinstance(version, str)
        or not isinstance(entry_json, str)
        or not (previous is None or isinstance(previous, str))
    ):
        raise ValueError(_NATIVE_UNAVAILABLE)
    return CodexMcpSetupReceipt(name, file_path, version, entry_json, previous)


def _version_pairs(value: object) -> tuple[str, list[tuple[str, str]]] | None:
    if not isinstance(value, dict):
        return None
    file_path, pairs = value.get("file_path"), value.get("pairs")
    if not isinstance(file_path, str) or not isinstance(pairs, list):
        return None
    chain: list[tuple[str, str]] = []
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(item, str) for item in pair):
            return None
        chain.append((pair[0], pair[1]))
    return file_path, chain


def _rollback(executable: str, receipt: CodexMcpSetupReceipt) -> str:
    answer = _ask({"op": "rollback", **_host(executable), "receipt": _receipt_fields(receipt)})
    reason = _reason(answer)
    if reason is not None:
        raise ValueError(reason)
    version = answer.get("version")
    if not isinstance(version, str):
        raise ValueError(_NATIVE_UNAVAILABLE)
    return version


def _receipt_fields(receipt: CodexMcpSetupReceipt) -> dict[str, object]:
    return {
        "name": receipt.name,
        "file_path": receipt.file_path,
        "version": receipt.version,
        "entry_json": receipt.entry_json,
        "previous_version": receipt.previous_version,
    }


def install_reviewed_codex_mcp(
    executable: str,
    name: str,
    entry: dict[str, object],
    *,
    on_installed: Callable[[CodexMcpSetupReceipt], None] | None = None,
    on_version_chain: Callable[[str, list[tuple[str, str]]], None] | None = None,
) -> str:
    encoded_entry = json.dumps(entry, sort_keys=True, separators=(",", ":"), allow_nan=False)
    answer = _ask({"op": "install", **_host(executable), "name": name, "entry_json": encoded_entry})
    reason = _reason(answer)
    if reason is not None:
        chain = _version_pairs(answer.get("version_chain"))
        if chain is not None and on_version_chain is not None:
            try:
                on_version_chain(*chain)
            except (ValueError, OSError) as error:
                raise ValueError("codex_setup_outcome_uncertain") from error
        raise ValueError(reason)
    installed = _receipt(answer.get("receipt"))
    try:
        if on_installed is not None:
            on_installed(installed)
    except (ValueError, OSError) as error:
        try:
            removed_version = _rollback(executable, installed)
            if on_version_chain is not None and installed.previous_version is not None:
                on_version_chain(
                    installed.file_path,
                    [(installed.previous_version, installed.version), (installed.version, removed_version)],
                )
        except (ValueError, OSError):
            raise ValueError("codex_setup_outcome_uncertain") from error
        raise ValueError("codex_setup_rolled_back") from error
    return name


def rollback_reviewed_codex_mcp(executable: str, receipt: CodexMcpSetupReceipt) -> str:
    return _rollback(executable, receipt)
