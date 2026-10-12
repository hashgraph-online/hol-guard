"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# ruff: noqa: F403, F405

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

_CODEX_TOOL_RESPONSE_MAX_DEPTH = 5


_CODEX_TOOL_RESPONSE_TEXT_LIMIT = 5 * 1024 * 1024


_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH = 24


def _redact_codex_prompt_secret_assignments(value: str) -> str:
    """Resolve redaction lazily so Codex output handling has no import-order gap."""

    from .commands_support_runtime_resolution import _redact_codex_prompt_secret_assignments as resolve

    return resolve(value)


def _resolve_prompt_scan_path(requested_path: str, *, cwd: Path | None) -> Path | None:
    """Resolve prompt paths lazily so output inspection remains available at startup."""

    from .commands_support_runtime_resolution import _resolve_prompt_scan_path as resolve

    return resolve(requested_path, cwd=cwd)


def _truncate_codex_display_text(value: str, *, limit: int) -> str:
    """Resolve display truncation lazily so output inspection remains available at startup."""

    from .commands_support_runtime_resolution import _truncate_codex_display_text as resolve

    return resolve(value, limit=limit)


def _path_contains_symlink(path: Path, *, base_dir: Path) -> bool:
    from ..runtime.source_paths import path_contains_symlink

    return path_contains_symlink(path, base_dir=base_dir)


def _collect_codex_tool_response_text(value: object, *, depth: int = 0) -> str:
    if depth > _CODEX_TOOL_RESPONSE_MAX_DEPTH:
        return ""
    if isinstance(value, str):
        return value[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, dict):
        parts: list[str] = []
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"stdout", "stderr", "output", "text", "content", "result", "message"} or depth > 0:
                text = _collect_codex_tool_response_text(child, depth=depth + 1)
                if text:
                    parts.append(text)
        return "\n".join(parts)[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, list):
        return "\n".join(_collect_codex_tool_response_text(item, depth=depth + 1) for item in value)[
            :_CODEX_TOOL_RESPONSE_TEXT_LIMIT
        ]
    return ""


_PROMPT_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])\.[A-Za-z0-9][A-Za-z0-9_.-]{0,255}|"
    r"(?:~|\.{1,2}|/)[^\s'\"`<>|;(){}\[\]]{0,255}"
)


_PROMPT_FILE_READ_VERB_PATTERN = re.compile(r"\b(?:read|open|print|show|dump|cat|head|tail|less|view|display)\b", re.I)


_PROMPT_CONTENT_SCAN_MAX_BYTES = 64 * 1024


_PROMPT_CONTENT_SCAN_SKIP_BASENAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
    }
)


_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS = frozenset(
    {
        "auth",
        "credential",
        "env",
        "key",
        "pass",
        "secret",
        "token",
    }
)


_CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS = (
    re.compile(
        r"Warning:\s*HOL Guard flagged this prompt because it asks for direct local secret access and is protecting "
        r"your local secrets\. If that is intentional, continue and Guard will ask again on the actual tool call\. "
        r"Open HOL Guard to approve or keep this blocked:\s*\S+\. "
        r"After you choose, retry the same the harness action\.?",
        re.IGNORECASE,
    ),
    re.compile(
        r"HOL Guard stopped this Codex prompt before Codex could open (?:a credential-looking local file|a sensitive "
        r"local file)\. Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this "
        r"request at prompt time\. Open HOL Guard to approve or keep this blocked:\s*\S+\. After you choose, retry "
        r"the same Codex action\.?",
        re.IGNORECASE,
    ),
)


def _codex_prompt_credential_file_artifact(
    *,
    prompt_text: str,
    cwd: Path | None,
    config_path: str,
) -> GuardArtifact | None:
    if _PROMPT_FILE_READ_VERB_PATTERN.search(prompt_text) is None:
        return None
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(prompt_text):
        requested_path = match.group(0)
        path = _resolve_prompt_scan_path(requested_path, cwd=cwd)
        if path is None or path.name in _PROMPT_CONTENT_SCAN_SKIP_BASENAMES:
            continue
        if not path.name.startswith("."):
            continue
        if not _prompt_path_looks_secret_bearing(path):
            continue
        if not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                content = handle.read(_PROMPT_CONTENT_SCAN_MAX_BYTES).decode("utf-8", errors="ignore")
        except OSError:
            continue
        if not classify_secret_content(content):
            continue
        normalized_path = str(path)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "harness": "codex",
                    "prompt_path": normalized_path,
                    "content_class": "credential-looking local file",
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]
        prompt_display = _codex_prompt_display_text(prompt_text, requested_path=requested_path)
        prompt_intent_hash = hashlib.sha256(_codex_prompt_intent_text(prompt_text).encode("utf-8")).hexdigest()
        return GuardArtifact(
            artifact_id=f"codex:project:prompt-file:{fingerprint}",
            name=f"credential-looking local file {path.name}",
            harness="codex",
            artifact_type="prompt_request",
            source_scope="project",
            config_path=config_path,
            metadata={
                "prompt_signals": ["requested file content contains credential-looking material"],
                "prompt_summary": "Prompt asks Codex to read a credential-looking local file.",
                "prompt_matched_text": requested_path,
                "prompt_intent_hash": prompt_intent_hash,
                "prompt_display_text": prompt_display,
                "prompt_request_class": "secret_read",
                "prompt_request_classes": ["secret_read"],
                "request_summary": prompt_display,
                "runtime_request_summary": prompt_display,
                "runtime_request_reason": (
                    "Guard scanned a small local dotfile before Codex read it and found credential-looking text."
                ),
                "normalized_path": normalized_path,
            },
        )
    return None


def _prompt_path_looks_secret_bearing(path: Path) -> bool:
    lowered_name = path.name.lower()
    return any(marker in lowered_name for marker in _PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS)


def _with_codex_prompt_display_metadata(artifact: GuardArtifact, *, prompt_text: str) -> GuardArtifact:
    matched_text = artifact.metadata.get("prompt_matched_text")
    display = _codex_prompt_display_text(
        prompt_text,
        requested_path=matched_text if isinstance(matched_text, str) else None,
    )
    metadata = {
        **artifact.metadata,
        "prompt_display_text": display,
        "request_summary": display,
        "runtime_request_summary": display,
    }
    return replace(artifact, metadata=metadata)


def _codex_prompt_display_text(prompt_text: str, *, requested_path: str | None = None) -> str:
    sanitized_prompt = _sanitize_codex_display_text(prompt_text)
    path_suffix = ""
    if requested_path is not None and requested_path.strip():
        path_suffix = f" for `{_sanitize_codex_display_text(requested_path.strip())}`"
    return f"Codex prompt{path_suffix}: {_truncate_codex_display_text(sanitized_prompt, limit=320)}"


def _codex_prompt_intent_text(prompt_text: str) -> str:
    normalized = _sanitize_codex_display_text(prompt_text)
    for pattern in _CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS:
        normalized = pattern.sub(" ", normalized)
    return " ".join(normalized.split())


def _sanitize_codex_display_text(value: str) -> str:
    collapsed = " ".join(value.strip().split())
    redacted = _redact_codex_prompt_secret_assignments(collapsed)
    sanitized = re.sub(r"/(?:Users|home)/[^/\s]+", "~", redacted)
    return re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", "~", sanitized)


__all__ = [
    "_PROMPT_CONTENT_SCAN_MAX_BYTES",
    "_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS",
    "_PROMPT_CONTENT_SCAN_SKIP_BASENAMES",
    "_PROMPT_FILE_READ_VERB_PATTERN",
    "_PROMPT_PATH_TOKEN_PATTERN",
    "_codex_prompt_credential_file_artifact",
    "_codex_prompt_display_text",
    "_collect_codex_tool_response_text",
    "_path_contains_symlink",
    "_prompt_path_looks_secret_bearing",
    "_sanitize_codex_display_text",
    "_with_codex_prompt_display_metadata",
]
