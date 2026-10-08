"""Bind a queued native review retry to its payload and verified policy domain."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from pathlib import Path

from .hook_native_review_binding import native_review_policy_binding
from .hook_request_parsing import pre_tool_command

_MUTABLE_CODE_LAUNCHERS = _MUTABLE_CODE_LAUNCHERS = {
    ".",
    "source",
    "sh",
    "bash",
    "dash",
    "ash",
    "zsh",
    "ksh",
    "fish",
    "node",
    "bun",
    "deno",
    "ruby",
    "perl",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bunx",
    "make",
    "just",
    "task",
    "cargo",
    "uv",
    "uvx",
    "pipx",
}
_PYTHON_LAUNCHER = re.compile(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)
_FILE_BACKED_PROGRAM_COMMANDS = {"sed", "grep", "egrep", "fgrep", "rg"}
_DIRECT_REUSABLE_COMMANDS = _DIRECT_REUSABLE_COMMANDS = {
    "cat",
    "head",
    "tail",
    "sed",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "stat",
    "wc",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "strings",
}
_NATIVE_DIGEST = re.compile(r"[0-9a-f]{64}")
_NATIVE_IDENTITY_TOKEN = re.compile(r"[a-z0-9_-]{1,128}")
_SHELL_PUNCTUATION = frozenset(";&|<>")


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def _command_reuse_is_payload_bound(command: str) -> bool:
    """Allow retry reuse only when mutable local code cannot hide behind argv."""

    if any(marker in command for marker in ("`", "$(", "${", "\n", "\r")):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens:
        return False
    # shlex groups adjacent punctuation, so reject every punctuation-only token
    # rather than a fixed operator list. This covers |&, <<<, <>, >| and future
    # combinations without accidentally treating them as part of argv.
    if any(token and all(char in _SHELL_PUNCTUATION for char in token) for token in tokens):
        return False
    # Leading environment assignments can change executable lookup or loader
    # behavior without changing the apparent command. They are never reusable.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        return False
    executable = tokens[0]
    if "/" in executable or "\\" in executable or executable.startswith("."):
        return False
    basename = Path(executable).name.lower()
    if basename in _MUTABLE_CODE_LAUNCHERS or _PYTHON_LAUNCHER.fullmatch(basename):
        return False
    if basename in _FILE_BACKED_PROGRAM_COMMANDS and _uses_file_backed_program(tokens[1:]):
        return False
    if basename == "rg" and _rg_executes_unreviewed_preprocessor(tokens[1:]):
        return False
    return basename in _DIRECT_REUSABLE_COMMANDS


def _rg_executes_unreviewed_preprocessor(tokens: list[str]) -> bool:
    """Reject ripgrep launches that run a mutable preprocessor."""

    return any(token == "--pre" or token.startswith("--pre=") for token in tokens)


def _uses_file_backed_program(tokens: list[str]) -> bool:
    """Reject programs or patterns loaded from a mutable file instead of argv."""

    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {"-f", "--file", "--fi", "--fil"}:
            return True
        if token.startswith(("--file=", "--fi=", "--fil=")):
            return True
        if token in {"-e", "--expression", "--regexp"}:
            skip_next = True
            continue
        if token.startswith("-") and not token.startswith("--") and token != "-":
            cluster = token[1:]
            for index, flag in enumerate(cluster):
                if flag == "e":
                    skip_next = index == len(cluster) - 1
                    break
                if flag == "f":
                    return True
    return False


def _native_review_binding(
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
) -> str | None:
    """Bind a short-lived retry to Rust-owned request and decision evidence."""

    command = pre_tool_command(payload)
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    if action_type == "package":
        return None
    if command is not None and not _command_reuse_is_payload_bound(command):
        return None
    if not isinstance(native_receipt, Mapping):
        return None
    if (
        native_receipt.get("schema") != "guard-native-hook-decision-receipt.v1"
        or native_receipt.get("version") != 1
        or native_receipt.get("authority") != "rust"
        or native_receipt.get("harness") != harness
        or native_receipt.get("event_name") != "PreToolUse"
        or native_receipt.get("workspace_bound") is not (workspace is not None)
    ):
        return None
    request_digest = native_receipt.get("request_digest")
    if not isinstance(request_digest, str) or _NATIVE_DIGEST.fullmatch(request_digest) is None:
        return None
    decision = str(native_result.get("decision") or "")
    minimum_action = str(native_result.get("minimum_action") or "")
    policy_action = str(native_result.get("policy_action") or "")
    reason_code = str(native_result.get("reason_code") or "")
    if (
        native_receipt.get("decision") != decision
        or native_receipt.get("policy_action") != policy_action
        or native_receipt.get("reason_code") != reason_code
    ):
        return None
    identity_tokens = (decision, minimum_action, policy_action, reason_code)
    if any(_NATIVE_IDENTITY_TOKEN.fullmatch(value) is None for value in identity_tokens):
        return None
    identity = ":".join(("native-review-v4", request_digest, *identity_tokens))
    try:
        policy_binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=native_receipt
        )
    except ValueError:
        return None
    if policy_binding is None:
        return identity
    encoded = json.dumps(policy_binding, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    domain = hashlib.sha256(b"hol-guard.native-review-extension-binding.v1\0" + encoded).hexdigest()
    return f"{identity}:{domain}"
