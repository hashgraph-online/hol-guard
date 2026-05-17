"""False-positive classification rules for Guard runtime detectors."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

_SOURCE_SEARCH_TOOLS = frozenset(
    {
        "rg",
        "ripgrep",
        "grep",
        "egrep",
        "fgrep",
        "fd",
        "find",
        "ls",
    }
)

_READ_ONLY_INLINE_TOOLS = frozenset({"jq", "yq", "awk", "sed"})
SOURCE_INSPECTION_PARTS = frozenset(
    {"__tests__", "app", "dashboard", "docs", "lib", "packages", "scripts", "src", "test", "tests", "workers"}
)
SOURCE_INSPECTION_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".css",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".jsx",
        ".json",
        ".md",
        ".mjs",
        ".py",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".yaml",
        ".yml",
    }
)
SOURCE_INSPECTION_SENSITIVE_PARTS = frozenset(
    {".aws", ".docker", ".env", ".git-credentials", ".kube", ".netrc", ".npmrc", ".pypirc", ".ssh", "credentials"}
)
SOURCE_INSPECTION_BENIGN_DOTFILES = frozenset({".nvmrc"})

_SECRET_FILE_NAMES = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials"
    r"|id_rsa|id_ed25519|id_ecdsa|credentials|wallet\.key|private[_-]?key\.pem|terraform\.tfvars)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_PIPE_TO_EXFIL = re.compile(
    r"[|;]\s*(?:curl|wget|nc|ncat|netcat|scp|rsync|aws\s+s3|gsutil|gcloud)\b",
    re.IGNORECASE,
)

_FIND_MUTATING_FLAGS = re.compile(
    r"(?:^|[\s])-(?:delete|exec\s+rm|exec\s+unlink|exec\s+shred|execdir\s+rm)\b"
    r"|(?:^|[\s])-exec\s+\S+[^\r\n;&|]{0,100}\{.*\}\s*(?:\\;|;|\+)",
    re.IGNORECASE,
)

_OUTPUT_REDIRECT_TO_EXFIL = re.compile(
    r">\s*(?:/proc/\S+|/dev/tcp/|/dev/udp/)",
    re.IGNORECASE,
)

_CLIPBOARD_PIPE = re.compile(
    r"[|;]\s*(?:pbcopy|xclip|xsel|wl-copy|clip)\b",
    re.IGNORECASE,
)

_LOCALHOST_HEALTH_PATTERN = re.compile(
    r"(?:^|[\s;&|])"
    r"(?:curl|wget|fetch|http\.get|requests\.get)"
    r"\b[^\r\n;&|]{0,80}"
    r"(?:localhost|127\.0\.0\.1|::1|\[::1\]|0\.0\.0\.0)"
    r"(?::\d{1,5})?"
    r"(?:/(?:healthz?|readiness|ready|liveness|live|ping|status|metrics|info|version))?"
    r"(?:\s|$|[;&|'\"])",
    re.IGNORECASE,
)
_CURL_READ_ONLY_HTTP_FETCH_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?P<tool>curl|curl\.exe)\b[^\r\n;&|]*https?://",
    re.IGNORECASE,
)
_WGET_READ_ONLY_HTTP_FETCH_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?P<tool>wget)\b(?=[^\r\n;&|]*(?<!\S)--spider\b)[^\r\n;&|]*https?://",
    re.IGNORECASE,
)
_NODE_READ_ONLY_HTTP_FETCH_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?P<tool>node)\b(?s:.*?)(?:\bfetch\s*\(|\bhttps?\.get\s*\()",
    re.IGNORECASE,
)
_PYTHON_READ_ONLY_HTTP_FETCH_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?P<tool>python|python3)\b(?s:.*?)(?:\brequests\.get\s*\(|\burllib\.request\.urlopen\s*\()",
    re.IGNORECASE,
)
_READ_ONLY_HTTP_FETCH_PATTERNS = (
    _CURL_READ_ONLY_HTTP_FETCH_PATTERN,
    _WGET_READ_ONLY_HTTP_FETCH_PATTERN,
    _NODE_READ_ONLY_HTTP_FETCH_PATTERN,
    _PYTHON_READ_ONLY_HTTP_FETCH_PATTERN,
)
_MUTATING_HTTP_FETCH_PATTERN = re.compile(
    r"\b(?:POST|PUT|PATCH|DELETE)\b|"
    r"\bmethod\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|"
    r"(?:^|[\s;&|])(?:--request|-X)\s*(?:POST|PUT|PATCH|DELETE)\b|"
    r"(?:^|[\s;&|])(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F|--json|--upload-file|-T)\b|"
    r"\b(?:body|data)\s*:",
    re.IGNORECASE,
)
_HTTP_FETCH_FILE_WRITE_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?:--output|-o|--remote-name|-O|--remote-header-name|--dump-header|-D)\b",
    re.IGNORECASE,
)
_LOCAL_FILE_READ_IN_HTTP_SCRIPT_PATTERN = re.compile(
    r"\b(?:readFileSync|open|createReadStream)\s*\(|"
    r"\bPath\s*\([^)]{0,240}\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(|"
    r"\bcat\s+",
    re.IGNORECASE,
)
_PIPE_TO_EXECUTION_PATTERN = re.compile(
    r"[|;]\s*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s|;]*\s+)*"
    r"(?:(?i:bash|sh|zsh|fish|python|python3|perl|ruby|php|powershell|pwsh|cmd|chmod|install)|node)\b",
)

_FAKE_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)(?:your[_-]?api[_-]?key|example[_-]?token|fake[_-]?(?:secret|token|key|credential)|"
        r"placeholder|<[A-Z_]{2,}(?:[_-][A-Z]+)*>|x{4,}|\b1234(?:5678)?\b|test[_-]?token|dummy[_-]?(?:key|secret|token)|"
        r"replace[_-]?me|insert[_-]?(?:your|token)|changeme|secret123|password123|"
        r"\babc123\b|my[_-]?(?:secret|key|token|api[_-]?key)|sample[_-]?(?:key|token|credential))"
    ),
    re.compile(r"(?i)\b(?:todo|fixme|hack|stub|mock|fake|demo|sample|example)\b.*?(?:key|token|secret|credential)"),
)

_DOCS_EXAMPLE_CONTEXT = re.compile(
    r"(?:README|CHANGELOG|CONTRIBUTING|SECURITY|LICENSE|NOTICE|\.md|\.rst|\.txt|\.adoc)"
    r"|(?:example|demo|tutorial|sample|docs?/|documentation/|spec/|test/fixtures?/)",
    re.IGNORECASE,
)

_VERSION_FILE_NAMES = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:\.nvmrc|\.node-version|\.python-version|\.ruby-version|\.tool-versions|\.java-version)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_PACKAGE_METADATA_FILES = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"requirements\.txt|setup\.py|setup\.cfg|pyproject\.toml|Pipfile(?:\.lock)?|"
    r"go\.(?:mod|sum)|Cargo\.(?:toml|lock)|composer\.json|Gemfile(?:\.lock)?)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SourceSearchClassification:
    """Result of classifying a shell command as a read-only source search."""

    is_source_search: bool
    reason: str | None
    tool: str | None


def classify_source_search_command(command: str) -> SourceSearchClassification:
    """Return whether *command* is a benign read-only code/filesystem search.

    A source search is a command that:
    - Uses known search tools (rg, grep, fd, find)
    - Does not target actual secret files
    - Does not pipe output to network, clipboard, or other exfiltration sinks
    - Does not use read-inline tools (jq, awk, sed) to extract and relay data
    """
    stripped = command.strip()
    if not stripped:
        return SourceSearchClassification(is_source_search=False, reason=None, tool=None)

    parts = stripped.split()
    if not parts:
        return SourceSearchClassification(is_source_search=False, reason=None, tool=None)

    tool = _leading_tool(parts)
    if tool is None:
        return SourceSearchClassification(is_source_search=False, reason=None, tool=None)

    if _PIPE_TO_EXFIL.search(command):
        return SourceSearchClassification(
            is_source_search=False,
            reason="piped to network tool",
            tool=tool,
        )

    if _OUTPUT_REDIRECT_TO_EXFIL.search(command):
        return SourceSearchClassification(
            is_source_search=False,
            reason="output redirected to device/proc",
            tool=tool,
        )

    if _CLIPBOARD_PIPE.search(command):
        return SourceSearchClassification(
            is_source_search=False,
            reason="piped to clipboard",
            tool=tool,
        )

    if _SECRET_FILE_NAMES.search(command):
        return SourceSearchClassification(
            is_source_search=False,
            reason="targets secret file",
            tool=tool,
        )

    if tool == "find" and _FIND_MUTATING_FLAGS.search(command):
        return SourceSearchClassification(
            is_source_search=False,
            reason="find with mutating action flag",
            tool=tool,
        )

    return SourceSearchClassification(
        is_source_search=True,
        reason="read-only code/filesystem search",
        tool=tool,
    )


def classify_fake_credential_pattern(text: str) -> bool:
    """Return True if *text* matches known fake/example/placeholder credential patterns."""
    return any(pattern.search(text) for pattern in _FAKE_CREDENTIAL_PATTERNS)


def classify_health_endpoint_fetch(command: str) -> bool:
    """Return True if *command* is a benign localhost health/readiness check."""
    return bool(_LOCALHOST_HEALTH_PATTERN.search(command))


def classify_read_only_http_fetch(command: str) -> str | None:
    """Return the read-only HTTP probe tool name when command has no upload or secret source."""
    match = None
    for pattern in _READ_ONLY_HTTP_FETCH_PATTERNS:
        match = pattern.search(command)
        if match is not None:
            break
    if match is None:
        return None
    if _MUTATING_HTTP_FETCH_PATTERN.search(command):
        return None
    if _HTTP_FETCH_FILE_WRITE_PATTERN.search(command):
        return None
    if _PIPE_TO_EXFIL.search(command):
        return None
    if _PIPE_TO_EXECUTION_PATTERN.search(command):
        return None
    if _OUTPUT_REDIRECT_TO_EXFIL.search(command):
        return None
    if _SECRET_FILE_NAMES.search(command):
        return None
    if _LOCAL_FILE_READ_IN_HTTP_SCRIPT_PATTERN.search(command):
        return None
    tool = match.group("tool").lower()
    if tool in {"curl.exe", "curl"}:
        return "curl"
    if tool in {"python3", "python"}:
        return "python"
    return tool


def classify_docs_example_source(source_hint: str) -> bool:
    """Return True if *source_hint* (path or context label) is a docs/example location."""
    return bool(_DOCS_EXAMPLE_CONTEXT.search(source_hint))


def classify_version_file_access(paths: Sequence[str]) -> bool:
    """Return True if all *paths* are benign version-pin files with no sensitive data."""
    if not paths:
        return False
    return all(_VERSION_FILE_NAMES.search(p) for p in paths)


def classify_package_metadata_access(paths: Sequence[str]) -> bool:
    """Return True if all *paths* are package manifest/lock files (no secrets in them)."""
    if not paths:
        return False
    return all(_PACKAGE_METADATA_FILES.search(p) for p in paths)


def _leading_tool(parts: list[str]) -> str | None:
    """Return the base command name if it is a known source-search tool, else None."""
    if not parts:
        return None
    base = _strip_path_prefix(parts[0]).lower()
    if base in _SOURCE_SEARCH_TOOLS:
        return base
    if base in _READ_ONLY_INLINE_TOOLS and _has_no_write_flags(parts):
        return base
    return None


def _strip_path_prefix(token: str) -> str:
    return token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _has_no_write_flags(parts: list[str]) -> bool:
    """Return True if awk/sed/jq are used read-only (no in-place or write flags).

    Handles suffixed in-place forms (``-i.bak``, ``-i ''``) and clustered
    short options that include ``i`` (e.g. ``-ni``).
    """
    write_flags = {"--in-place", "-w", "--write"}
    for p in parts[1:]:
        tok = p.split("=")[0]
        if tok in write_flags:
            return False
        if len(tok) >= 2 and tok[0] == "-" and tok[1] != "-" and "i" in tok[1:]:
            return False
    return True
