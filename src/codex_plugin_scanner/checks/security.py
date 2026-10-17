"""Security checks (20 points)."""

from __future__ import annotations

import bisect
import ipaddress
import json
import os
import re
import stat
from itertools import pairwise
from pathlib import Path
from urllib.parse import urlparse

from ..models import CheckResult, Finding, Severity
from ..path_support import (
    LICENSE_FILENAMES,
    path_entry_exists,
    read_text_file_within_root,
    resolves_within_root,
)
from .security_failures import ScanInputUnreadableError, unreadable_scan_input_failure
from .security_secret_patterns import (
    DOCUMENTATION_EXTS,
    SECRET_PATTERNS,
    SecretPattern,
    _field_name_map_spans,
    _is_generated_token_expression,
    _is_symbolic_reference_literal,
    _python_symbolic_reference_spans,
    _screen_route_map_spans,
)

EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__pycache__", ".venv", "venv"}

EXAMPLE_PATH_HINTS = {
    "docs",
    "doc",
    "skills",
    "skill",
    "prompts",
    "prompt",
    "instructions",
    "instruction",
    "examples",
    "example",
    "samples",
    "sample",
    "guides",
    "guide",
    "tutorials",
    "tutorial",
    "rules",
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "fixture",
}
TEST_FILE_RE = re.compile(r"(?:^test_|\.test\.[^.]+$|\.spec\.[^.]+$|_test\.[^.]+$)", re.I)
PLACEHOLDER_MARKERS = (
    "redacted",
    "changeme",
    "set-at-runtime",
    "set_at_runtime",
)
EXAMPLE_GENERIC_VALUES = {
    "admin123",
    "adminpass123",
    "mypassword123",
    "password123",
    "secret-value",
    "secure123",
    "securep@ss1",
    "testpass123",
}
ILLUSTRATIVE_PATH_HINTS = {"commands", "examples", "prompts", "rules", "skills"}
ILLUSTRATIVE_CONTEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:assert|fixture|mock|pytest|test\(|writeandstage|detectsecrets)\b", re.I),
    re.compile(r"\b(?:example|sample|demo|bad|wrong|good|correct|never|always)\b", re.I),
    re.compile(r"hardcoded secret|in source code|environment variable|env var|set via|\.env", re.I),
)
PROVIDER_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"^AKIA(?P<payload>[0-9A-Z]+)$"), 16),
    (re.compile(r"^(?:ghp_|gho_|ghu_|ghs_)(?P<payload>[A-Za-z0-9]+)$"), 36),
    (re.compile(r"^github_pat_(?P<payload>[A-Za-z0-9_]+)$"), 20),
    (re.compile(r"^glpat-(?P<payload>[A-Za-z0-9\-]+)$"), 20),
    (re.compile(r"^(?:xox[bpas]-|xoxe-|xoxr-|xapp-)(?P<payload>[A-Za-z0-9\-]+)$"), 10),
    (re.compile(r"^sk-(?:proj-|ant-)?(?P<payload>[A-Za-z0-9_-]+)$"), 20),
)
PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----")
PRIVATE_KEY_FOOTER_TEMPLATE = "-----END {label}-----"
MAX_SCAN_ENTRIES = 200_000
MAX_SCAN_FILES = 50_000
MAX_SCAN_FILE_BYTES = 16 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SECRET_MATCHES_PER_FILE = 10_000
MAX_SCAN_DEPTH = 64

BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".wasm",
    ".pyc",
    ".so",
    ".dylib",
}

DANGEROUS_MCP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"rm\s+-rf"),
    re.compile(r"\bsudo\b"),
    re.compile(r"curl\b.*\|\s*(ba)?sh"),
    re.compile(r"wget\b.*\|\s*(ba)?sh"),
    re.compile(r"bash\s+-c"),
    re.compile(r"\beval\b"),
    re.compile(r"\bexec\b"),
    re.compile(r"powershell\s+-c", re.I),
    re.compile(r"cmd\s*/c", re.I),
]

RISKY_APPROVAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"danger-full-access"),
    re.compile(r'approval[_ -]?policy["\']?\s*[:=]\s*["\']never["\']', re.I),
    re.compile(r'approvalMode["\']?\s*[:=]\s*["\']bypass["\']', re.I),
]
# Markdown can name a risky value without setting it, as a rule or a changelog
# does: "sandbox `danger-full-access`". Only a bare value alone in an inline code
# span, outside fenced and indented code and not after an assignment or a flag,
# counts as such a mention. Files that instruct an agent never qualify.
# Any indentation opens a fence: a fence nested in a list item sits deeper than
# three spaces, and an indented fence outside a list is code either way.
# A closing marker counts only when it is no deeper than the fence it opened,
# so a four-space marker does not close a top-level fence.
MARKDOWN_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
MARKDOWN_BLOCKQUOTE_PREFIX_RE = re.compile(r"^(?: {0,3}>[ \t]?)+")
MARKDOWN_LIST_MARKER_RE = re.compile(r"^ {0,3}(?:[-*+]|\d{1,9}[.)])[ \t]+")
# How much of a line before an inline code span is read for an assignment or a
# flag. A bounded window keeps long lines with many spans linear.
APPROVAL_CONTEXT_WINDOW = 256
# Prose that tells the reader to turn the value on, checked on the sentence
# before an inline code span. The last such verb before the span governs it.
# A negation governs that verb only when it sits immediately before it ("never
# enable", "do not use", "avoid using"). A risk word anywhere in the sentence
# also keeps the mention. Words such as "without", "instead", or "avoid" in
# front of a different phrase do not.
APPROVAL_INSTRUCTION_RE = re.compile(
    r"\b(?:select(?:ing|ed)?|set(?:ting)?|use|using|enable|enabling|switch(?:ing)? to|choose|choosing"
    r"|pick(?:ing)?|configure|configuring|pass(?:ing)?|turn(?:ing)? on|run(?:ning)? with|start(?:ing)? with"
    r"|launch(?:ing)? with|opt(?:ing)? (?:in|for)|change (?:it )?to|allow(?:ing)?)\b",
    re.I,
)
APPROVAL_NEGATION_RE = re.compile(r"\b(?:never|avoid|don'?t|do not|not)\s+$", re.I)
APPROVAL_RISK_RE = re.compile(r"\b(?:unsafe|insecure|dangerous|risky|risks?)\b", re.I)
APPROVAL_SENTENCE_END_RE = re.compile(r"[.!?;]")
APPROVAL_ASSIGNMENT_TAIL_RE = re.compile(r"(?:[=:]|(?:^|\s)--?[A-Za-z][\w-]*)\s*$")
AGENT_INSTRUCTION_FILENAMES = {"agent.md", "agents.md", "claude.md", "gemini.md", "skill.md"}
AGENT_INSTRUCTION_STEMS = {"context", "system-prompt", "system_prompt"}
AGENT_INSTRUCTION_PATH_HINTS = {
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".gemini",
    ".github",
    ".kiro",
    ".windsurf",
    "agent",
    "agents",
    "command",
    "commands",
    "instruction",
    "instructions",
    "prompt",
    "prompts",
    "skill",
    "skills",
}

APACHE_LICENSE_VERSION_RE = re.compile(r"apache\s+license\s*,?\s*version\s+2\.0", re.I)
LICENSE_URL_RE = re.compile(r"https?://[^\s<>()\"']+")


class ScanBudgetExceededError(RuntimeError):
    """Raised when analysis would be incomplete because a scan budget was exhausted."""


def _raise_walk_error(error: OSError) -> None:
    reason = error.strerror or type(error).__name__
    raise ScanInputUnreadableError(f"filesystem traversal failed: {reason}") from error


def _scan_all_files(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> list[Path]:
    """Recursively find all files, skipping excluded dirs."""
    if files is not None:
        discovered = []
        try:
            for path in files:
                metadata = path.lstat()
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and path.suffix.lower() not in BINARY_EXTS
                    and resolves_within_root(plugin_dir, path, require_exists=True)
                ):
                    discovered.append(path.resolve(strict=True))
        except OSError as error:
            reason = error.strerror or type(error).__name__
            raise ScanInputUnreadableError(f"explicit scan input unavailable: {reason}") from error
    else:
        discovered = []
        entries_seen = 0
        try:
            resolved_root = plugin_dir.resolve(strict=True)
        except OSError as error:
            reason = error.strerror or type(error).__name__
            raise ScanInputUnreadableError(f"plugin directory unavailable: {reason}") from error
        for root, dirs, names in os.walk(
            resolved_root,
            topdown=True,
            onerror=_raise_walk_error,
            followlinks=False,
        ):
            current = Path(root)
            depth = len(current.relative_to(resolved_root).parts)
            if depth > MAX_SCAN_DEPTH:
                raise ScanBudgetExceededError(f"directory depth exceeded {MAX_SCAN_DEPTH}")
            dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS and not (current / name).is_symlink())
            entries_seen += len(dirs) + len(names)
            if entries_seen > MAX_SCAN_ENTRIES:
                raise ScanBudgetExceededError(f"filesystem entries exceeded {MAX_SCAN_ENTRIES}")
            for name in sorted(names):
                path = current / name
                if path.is_symlink() or not path.is_file() or path.suffix.lower() in BINARY_EXTS:
                    continue
                if not resolves_within_root(resolved_root, path, require_exists=True):
                    continue
                discovered.append(path)

    if len(discovered) > MAX_SCAN_FILES:
        raise ScanBudgetExceededError(f"scannable files exceeded {MAX_SCAN_FILES}")
    total_bytes = 0
    for path in discovered:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_SCAN_FILE_BYTES:
            raise ScanBudgetExceededError(f"{path.name} exceeded {MAX_SCAN_FILE_BYTES} bytes")
        total_bytes += size
        if total_bytes > MAX_SCAN_TOTAL_BYTES:
            raise ScanBudgetExceededError(f"aggregate input exceeded {MAX_SCAN_TOTAL_BYTES} bytes")
    return discovered


def _is_example_surface(relative_path: Path) -> bool:
    path_parts = {part.lower() for part in relative_path.parts}
    return (
        relative_path.suffix.lower() in DOCUMENTATION_EXTS
        or bool(path_parts & EXAMPLE_PATH_HINTS)
        or bool(TEST_FILE_RE.search(relative_path.name))
    )


def _extract_secret_candidate(detector: SecretPattern, match: re.Match[str]) -> str:
    return match.group(detector.value_group).strip()


def _normalize_secret_candidate(value: str) -> str:
    normalized = value.strip().strip("\"'`")
    if normalized.lower().startswith("bearer "):
        normalized = normalized[7:].strip()
    return normalized


_PURE_SHELL_EXPANSION_RE = re.compile(
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*"
    r"(?:(?::-|-|:=|=|:\?|\?|:\+|\+)(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)?)?"
    r"\}$"
)
_PURE_TEMPLATE_EXPANSION_RE = re.compile(r"^\{\{[^}]+\}\}$")


def _looks_like_interpolated_secret(value: str) -> bool:
    """True only for complete env/template references with no literal payload."""
    normalized = _normalize_secret_candidate(value)
    return bool(_PURE_SHELL_EXPANSION_RE.fullmatch(normalized) or _PURE_TEMPLATE_EXPANSION_RE.fullmatch(normalized))


BRACKETED_PLACEHOLDER_RE = re.compile(
    r"^(?:<[A-Za-z][A-Za-z0-9 _.,:()/\-]{0,80}>|\[[A-Za-z][A-Za-z0-9 _.,:()/\-]{0,120}\])$"
)


def _is_bracketed_placeholder_text(candidate: str) -> bool:
    """True if a fully-captured string is an enclosed, word-like bracketed placeholder.

    Credential-shaped contents do not qualify: a bare alphanumeric token containing
    a digit (e.g. [hunter2hunter2]) or any alphanumeric run mixing case and digits
    (e.g. [Xk9q-2mZ7], <Prod_Db.Pass2024>) looks like a real secret, not wording.
    """
    if not BRACKETED_PLACEHOLDER_RE.fullmatch(candidate):
        return False
    inner = candidate[1:-1]
    segments = re.findall(r"[A-Za-z0-9]+", inner)
    return not any(
        re.search(r"[0-9]", segment)
        and (len(segments) == 1 or (re.search(r"[a-z]", segment) and re.search(r"[A-Z]", segment)))
        for segment in segments
    )


def _is_bracketed_placeholder_literal(content: str, detector: SecretPattern, match: re.Match[str]) -> bool:
    """True if the matched generic secret value is an enclosed bracketed placeholder.

    Valid placeholders must have matching delimiters (<...> or [...]) and word-like
    placeholder text (e.g. <password>, [redacted - retrieve token via auth]), preventing
    unclosed or real bracket-prefixed credentials from bypassing security checks.
    """
    start = match.start(detector.value_group)
    if start == 0 or content[start - 1] not in "\"'`":
        candidate = match.group(detector.value_group).strip().strip("\"'`")
        return _is_bracketed_placeholder_text(candidate)

    quote = content[start - 1]
    end = content.find(quote, start)
    if end == -1 or "\n" in content[start:end]:
        return False

    literal = content[start:end].strip()
    return _is_bracketed_placeholder_text(literal)


def _looks_like_placeholder_secret(value: str) -> bool:
    """Check if a candidate string matches placeholder heuristic markers on example surfaces."""
    normalized = _normalize_secret_candidate(value)
    lowered = normalized.lower()
    if not normalized:
        return True
    if _looks_like_interpolated_secret(normalized) or _is_bracketed_placeholder_text(normalized):
        return True
    if "..." in normalized or "…" in normalized:
        return True
    if lowered.startswith(("your-", "your_", "your", "example-", "sample-", "demo-")):
        return True
    if lowered.endswith(("-here", "_here", "example", "sample")):
        return True
    if lowered in PLACEHOLDER_MARKERS:
        return True
    return bool(re.search(r"(?i)(?:^|[-_])(x{4,}|\*{3,})(?:[-_]|$)", normalized))


def _normalized_alnum(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _normalize_secret_candidate(value).lower())


def _ascending_run_stats(value: str) -> tuple[int, int]:
    if not value:
        return 0, 0
    longest = 1
    current = 1
    coverage = 0
    for previous, token in pairwise(value):
        if ord(token) == ord(previous) + 1:
            current += 1
            longest = max(longest, current)
        else:
            if current >= 4:
                coverage += current
            current = 1
    if current >= 4:
        coverage += current
    return longest, coverage


def _provider_payload(value: str) -> tuple[str, int] | None:
    normalized = _normalize_secret_candidate(value)
    for pattern, minimum_length in PROVIDER_PREFIX_PATTERNS:
        match = pattern.fullmatch(normalized)
        if match:
            return match.group("payload"), minimum_length
    return None


def _looks_like_synthetic_provider_candidate(value: str) -> bool:
    provider_payload = _provider_payload(value)
    if provider_payload is None:
        return False
    payload, _minimum_length = provider_payload
    normalized = _normalized_alnum(payload)
    if len(normalized) < 8:
        return False
    longest_run, coverage = _ascending_run_stats(normalized)
    return longest_run >= 8 and coverage / len(normalized) >= 0.6


def _looks_like_incomplete_provider_candidate(value: str) -> bool:
    provider_payload = _provider_payload(value)
    if provider_payload is None:
        return False
    payload, minimum_length = provider_payload
    normalized = _normalized_alnum(payload)
    return len(normalized) < minimum_length


def _looks_like_example_generic_secret(value: str) -> bool:
    normalized = _normalize_secret_candidate(value).lower()
    return normalized in EXAMPLE_GENERIC_VALUES


def _newline_offsets(content: str) -> tuple[int, ...]:
    return tuple(match.start() for match in re.finditer("\n", content))


def _line_number_for_offset(content: str, offset: int, offsets: tuple[int, ...] | None = None) -> int:
    newline_offsets = offsets if offsets is not None else _newline_offsets(content)
    return bisect.bisect_left(newline_offsets, offset) + 1


def _has_illustrative_context(
    relative_path: Path,
    content: str,
    offset: int,
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
) -> bool:
    if {part.lower() for part in relative_path.parts} & ILLUSTRATIVE_PATH_HINTS:
        return True
    context_lines = lines if lines is not None else content.splitlines()
    line_number = _line_number_for_offset(content, offset, offsets)
    start = max(0, line_number - 3)
    end = min(len(context_lines), line_number + 2)
    context = "\n".join(context_lines[start:end])
    return any(pattern.search(context) for pattern in ILLUSTRATIVE_CONTEXT_PATTERNS)


def _private_key_looks_like_placeholder(body_lines: list[str]) -> bool:
    body_text = "\n".join(body_lines)
    if _looks_like_placeholder_secret(body_text):
        return True
    placeholder_lines = {"mii...", "[redacted]", "redacted", "secret-key-material"}
    lowered_lines = [line.lower() for line in body_lines]
    return any(line in placeholder_lines or "redacted" in line for line in lowered_lines)


def _extract_inline_private_key_body(line: str, header: str) -> list[str]:
    header_index = line.find(header)
    if header_index == -1:
        return []
    tail = line[header_index + len(header) :]
    if "\\n" not in tail:
        return []
    body_lines: list[str] = []
    for fragment in tail.split("\\n")[1:]:
        cleaned = fragment.strip().strip("\"'`),;}]")
        if cleaned:
            body_lines.append(cleaned)
    return body_lines


def _first_private_key_line(
    relative_path: Path,
    content: str,
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
) -> int | None:
    content_lines = lines if lines is not None else content.splitlines()
    example_surface = _is_example_surface(relative_path)
    for match in PRIVATE_KEY_HEADER_RE.finditer(content):
        line_number = _line_number_for_offset(content, match.start(), offsets)
        label = match.group("label")
        footer = PRIVATE_KEY_FOOTER_TEMPLATE.format(label=label)
        header = match.group(0)
        body_lines = _extract_inline_private_key_body(content_lines[line_number - 1], header)
        has_footer = False
        for candidate_line in content_lines[line_number:]:
            stripped = candidate_line.strip()
            if not stripped:
                if body_lines:
                    break
                continue
            if stripped == footer:
                has_footer = True
                break
            if stripped.startswith("-----END ") or stripped.startswith("-----BEGIN ") or stripped == "```":
                break
            body_lines.append(stripped)
        if not body_lines:
            continue
        body_text = "".join(body_lines)
        if example_surface and _private_key_looks_like_placeholder(body_lines):
            continue
        if len(body_text) >= 32:
            return line_number
        if has_footer:
            return line_number
    return None


def _should_skip_secret_match(
    relative_path: Path,
    content: str,
    detector: SecretPattern,
    match: re.Match[str],
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
    field_name_spans: tuple[tuple[int, int], ...] = (),
    python_reference_spans: frozenset[tuple[int, int]] = frozenset(),
) -> bool:
    """Decide whether a match qualifies for a scoped non-secret or example exemption."""
    candidate = _extract_secret_candidate(detector, match)
    if _looks_like_interpolated_secret(candidate):
        return True
    # Fully-enclosed bracketed placeholders (<password>, [redacted...]) are universal documentation
    # markers allowed across all scanned paths, but bare prefix unclosed credentials remain guarded.
    if detector.kind == "generic" and _is_bracketed_placeholder_literal(content, detector, match):
        return True
    if detector.kind == "generic" and _provider_payload(candidate) is None:
        if _is_symbolic_reference_literal(relative_path, content, match, python_reference_spans):
            return True
        if _is_generated_token_expression(relative_path, content, match):
            return True
        span_index = bisect.bisect_right(field_name_spans, (match.start(), len(content))) - 1
        if span_index >= 0:
            start, end = field_name_spans[span_index]
            if start <= match.start() and match.end() <= end:
                return True
    if not _is_example_surface(relative_path):
        return False
    if _looks_like_placeholder_secret(candidate):
        return True
    effective_kind = detector.kind
    if effective_kind == "generic" and _provider_payload(candidate) is not None:
        effective_kind = "provider"
    if effective_kind == "generic":
        return _looks_like_example_generic_secret(candidate)
    if effective_kind == "provider":
        if not _has_illustrative_context(relative_path, content, match.start(), lines=lines, offsets=offsets):
            return False
        return _looks_like_synthetic_provider_candidate(candidate) or _looks_like_incomplete_provider_candidate(
            candidate
        )
    return False


def _first_hardcoded_secret_line(relative_path: Path, content: str) -> int | None:
    """Find the first retained secret line while enforcing the per-file match budget."""
    offsets = _newline_offsets(content)
    lines = content.splitlines()
    python_reference_spans = _python_symbolic_reference_spans(relative_path, content)
    field_name_spans = tuple(
        sorted(_field_name_map_spans(relative_path, content) + _screen_route_map_spans(relative_path, content))
    )
    first_line = _first_private_key_line(relative_path, content, lines=lines, offsets=offsets)
    first_offset: int | None = None
    matches_seen = 0
    for detector in SECRET_PATTERNS:
        if detector.kind == "private_key":
            continue
        for match in detector.pattern.finditer(content):
            matches_seen += 1
            if matches_seen > MAX_SECRET_MATCHES_PER_FILE:
                raise ScanBudgetExceededError(
                    f"secret matches exceeded {MAX_SECRET_MATCHES_PER_FILE} in {relative_path}"
                )
            if first_offset is not None and match.start() >= first_offset:
                break
            if _should_skip_secret_match(
                relative_path,
                content,
                detector,
                match,
                lines=lines,
                offsets=offsets,
                field_name_spans=field_name_spans,
                python_reference_spans=python_reference_spans,
            ):
                continue
            first_offset = match.start()
            line_number = _line_number_for_offset(content, match.start(), offsets)
            if first_line is None or line_number < first_line:
                first_line = line_number
    return first_line


def _has_canonical_apache_license_reference(content: str) -> bool:
    for candidate in LICENSE_URL_RE.findall(content):
        parsed = urlparse(candidate.rstrip(".,;:"))
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        if hostname == "www.apache.org" and path == "/licenses/LICENSE-2.0":
            return True
    return False


def _resource_budget_failure(name: str, *, max_points: int, reason: str) -> CheckResult:
    return CheckResult(
        name=name,
        passed=False,
        points=0,
        max_points=max_points,
        message=f"Security analysis incomplete: {reason}.",
        findings=(
            Finding(
                rule_id="SCAN_RESOURCE_BUDGET_EXCEEDED",
                severity=Severity.MEDIUM,
                category="security",
                title="Security scan resource budget exceeded",
                description=f"The scanner stopped before complete analysis because {reason}.",
                remediation="Reduce generated or vendored scan input, or scan the intended plugin directory directly.",
            ),
        ),
    )


def check_security_md(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / "SECURITY.md").exists()
    return CheckResult(
        name="SECURITY.md found",
        passed=exists,
        points=3 if exists else 0,
        max_points=3,
        message="SECURITY.md found" if exists else "SECURITY.md not found",
        findings=()
        if exists
        else (
            Finding(
                rule_id="SECURITY_MD_MISSING",
                severity=Severity.LOW,
                category="security",
                title="SECURITY.md is missing",
                description=(
                    "Plugins should publish a SECURITY.md file for responsible disclosure and support guidance."
                ),
                remediation="Add a SECURITY.md file with reporting guidance and supported versions.",
                file_path="SECURITY.md",
            ),
        ),
    )


def check_license(plugin_dir: Path) -> CheckResult:
    lp: Path | None = None
    for filename in LICENSE_FILENAMES:
        candidate = plugin_dir / filename
        if path_entry_exists(candidate):
            lp = candidate
            break
    if lp is None:
        return CheckResult(
            name="LICENSE found",
            passed=False,
            points=0,
            max_points=3,
            message="LICENSE file not found",
            findings=(
                Finding(
                    rule_id="LICENSE_MISSING",
                    severity=Severity.LOW,
                    category="security",
                    title="LICENSE file is missing",
                    description="Plugins should ship a LICENSE file so consumers can review usage rights.",
                    remediation="Add a LICENSE or LICENSE.md file that matches the manifest license metadata.",
                    file_path="LICENSE",
                ),
            ),
        )
    try:
        content = read_text_file_within_root(
            plugin_dir.resolve(strict=True),
            lp,
            max_bytes=MAX_SCAN_FILE_BYTES,
            errors="ignore",
        )
        if "apache" in content.lower() and (
            APACHE_LICENSE_VERSION_RE.search(content) or _has_canonical_apache_license_reference(content)
        ):
            return CheckResult(
                name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (Apache-2.0)"
            )
        if "MIT" in content and "Permission is hereby granted" in content:
            return CheckResult(name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (MIT)")
        return CheckResult(name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found")
    except OSError:
        return CheckResult(
            name="LICENSE found", passed=False, points=0, max_points=3, message="LICENSE exists but could not be read"
        )


def check_no_hardcoded_secrets(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> CheckResult:
    findings: list[tuple[str, int]] = []
    resolved_plugin_dir = plugin_dir.resolve()
    try:
        for fpath in _scan_all_files(resolved_plugin_dir, files):
            relative_path = fpath.relative_to(resolved_plugin_dir)
            try:
                content = read_text_file_within_root(
                    resolved_plugin_dir,
                    fpath,
                    max_bytes=MAX_SCAN_FILE_BYTES,
                    errors="ignore",
                )
            except (OSError, UnicodeError):
                return unreadable_scan_input_failure(
                    "No hardcoded secrets", max_points=7, path=relative_path.as_posix()
                )
            line_number = _first_hardcoded_secret_line(relative_path, content)
            if line_number is not None:
                findings.append((relative_path.as_posix(), line_number))
    except ScanInputUnreadableError as exc:
        return unreadable_scan_input_failure(
            "No hardcoded secrets",
            max_points=7,
            reason=str(exc),
        )
    except ScanBudgetExceededError as exc:
        return _resource_budget_failure("No hardcoded secrets", max_points=7, reason=str(exc))
    if not findings:
        return CheckResult(
            name="No hardcoded secrets", passed=True, points=7, max_points=7, message="No hardcoded secrets detected"
        )
    shown = [path for path, _line_number in findings[:5]]
    suffix = f" and {len(findings) - 5} more" if len(findings) > 5 else ""
    return CheckResult(
        name="No hardcoded secrets",
        passed=False,
        points=0,
        max_points=7,
        message=f"Hardcoded secrets found in: {', '.join(shown)}{suffix}",
        findings=tuple(
            Finding(
                rule_id="HARDCODED_SECRET",
                severity=Severity.HIGH,
                category="security",
                title="Hardcoded secret detected",
                description=f"Potential secret material was detected in {path}.",
                remediation="Remove the secret from source control and load it securely at runtime.",
                file_path=path,
                line_number=line_number,
            )
            for path, line_number in findings
        ),
    )


def check_no_dangerous_mcp(plugin_dir: Path) -> CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not path_entry_exists(mcp_path):
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping check",
            applicable=False,
        )
    try:
        content = read_text_file_within_root(
            plugin_dir.resolve(strict=True),
            mcp_path,
            max_bytes=MAX_SCAN_FILE_BYTES,
        )
    except (OSError, UnicodeError):
        return CheckResult(
            name="No dangerous MCP commands",
            passed=False,
            points=0,
            max_points=4,
            message="Could not safely read .mcp.json",
            findings=(
                Finding(
                    rule_id="MCP_CONFIG_UNREADABLE",
                    severity=Severity.MEDIUM,
                    category="security",
                    title="MCP configuration could not be safely read",
                    description="The MCP configuration is not a bounded regular file inside the plugin.",
                    remediation="Replace links or special files with a regular, repository-contained .mcp.json file.",
                    file_path=".mcp.json",
                ),
            ),
        )
    found: list[str] = []
    for pattern in DANGEROUS_MCP_PATTERNS:
        if pattern.search(content):
            found.append(pattern.pattern)
    if not found:
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=4,
            max_points=4,
            message="No dangerous commands found in .mcp.json",
        )
    return CheckResult(
        name="No dangerous MCP commands",
        passed=False,
        points=0,
        max_points=4,
        message=f"Dangerous patterns in .mcp.json: {', '.join(found)}",
        findings=tuple(
            Finding(
                rule_id="DANGEROUS_MCP_COMMAND",
                severity=Severity.HIGH,
                category="security",
                title="Dangerous MCP command pattern detected",
                description=f'The MCP configuration matches the risky pattern "{pattern}".',
                remediation="Remove destructive commands and require explicit user approval before high-risk actions.",
                file_path=".mcp.json",
            )
            for pattern in found
        ),
    )


IGNORED_MCP_URL_CONTEXT = {"metadata", "description", "homepage", "website", "docs", "documentation"}
MCP_URL_KEYS = {"url", "endpoint", "server_url"}


def _collect_mcp_urls(node: object, urls: list[str], path: tuple[str, ...] = ()) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered_key = key.lower()
            next_path = (*path, lowered_key)
            if lowered_key in IGNORED_MCP_URL_CONTEXT:
                continue
            if isinstance(value, str) and lowered_key in MCP_URL_KEYS:
                urls.append(value)
                continue
            if isinstance(value, (dict, list)):
                _collect_mcp_urls(value, urls, next_path)
        return
    if isinstance(node, list):
        for item in node:
            _collect_mcp_urls(item, urls, path)


def _extract_mcp_urls(payload: object) -> list[str]:
    urls: list[str] = []
    if isinstance(payload, dict):
        targeted = False
        for key in ("mcpServers", "servers"):
            value = payload.get(key)
            if isinstance(value, (dict, list)):
                targeted = True
                _collect_mcp_urls(value, urls, (key.lower(),))
        if targeted:
            return urls
    _collect_mcp_urls(payload, urls)
    return urls


def _is_loopback_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def check_mcp_transport_security(plugin_dir: Path) -> CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not path_entry_exists(mcp_path):
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping transport hardening checks.",
            applicable=False,
        )

    try:
        payload = json.loads(
            read_text_file_within_root(
                plugin_dir.resolve(strict=True),
                mcp_path,
                max_bytes=MAX_SCAN_FILE_BYTES,
            )
        )
    except (json.JSONDecodeError, OSError, UnicodeError, ValueError):
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=False,
            points=0,
            max_points=4,
            message="Could not parse .mcp.json for transport URLs.",
            findings=(
                Finding(
                    rule_id="MCP_CONFIG_INVALID_JSON",
                    severity=Severity.MEDIUM,
                    category="security",
                    title="MCP configuration is not valid JSON",
                    description="The .mcp.json file exists but could not be parsed.",
                    remediation="Fix the .mcp.json syntax so transport settings can be validated.",
                    file_path=".mcp.json",
                ),
            ),
        )

    urls = _extract_mcp_urls(payload)
    if not urls:
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No remote MCP URLs declared; stdio-only configuration is not applicable here.",
            applicable=False,
        )

    issues = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            continue
        if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
            continue
        issues.append(url)

    if not issues:
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=4,
            max_points=4,
            message="Remote MCP URLs use hardened transports or stay on loopback for local development.",
        )

    return CheckResult(
        name="MCP remote transports are hardened",
        passed=False,
        points=0,
        max_points=4,
        message=f"Insecure MCP remote URLs detected: {', '.join(issues)}",
        findings=tuple(
            Finding(
                rule_id="MCP_REMOTE_URL_INSECURE",
                severity=Severity.HIGH,
                category="security",
                title="MCP remote transport uses an insecure URL",
                description=f'The remote MCP endpoint "{url}" is not HTTPS or loopback-only HTTP.',
                remediation="Use HTTPS for remote MCP servers and reserve plain HTTP for localhost development only.",
                file_path=".mcp.json",
            )
            for url in issues
        ),
    )


def _is_agent_instruction_surface(relative_path: Path) -> bool:
    """Whether an agent loads this file as instructions, judged by its name and directories."""
    directories = {part.lower() for part in relative_path.parts[:-1]}
    if relative_path.name.lower() in AGENT_INSTRUCTION_FILENAMES:
        return True
    stem = relative_path.stem.lower()
    if stem in AGENT_INSTRUCTION_STEMS or stem in AGENT_INSTRUCTION_PATH_HINTS:
        return True
    return bool(directories & AGENT_INSTRUCTION_PATH_HINTS)


def _is_documented_approval_value(line: str, start: int, end: int) -> bool:
    """Whether line[start:end] is a bare value quoted alone in an inline code span of prose.

    An assignment or a flag right before the span, in prose or at the end of an
    earlier code span, makes it a setting rather than a mention. So does a
    sentence that tells the reader to select or enable the value, unless a
    negation governs that verb or the sentence names the risk.
    """
    if any(separator in line[start:end] for separator in "=:"):
        return False
    opens_span = start >= 1 and line[start - 1] == "`" and (start < 2 or line[start - 2] != "`")
    closes_span = line[end : end + 1] == "`" and line[end + 1 : end + 2] != "`"
    if not (opens_span and closes_span):
        return False
    # Step back over the padding and an earlier span's closing backticks first,
    # then read a bounded window: padding cannot push a flag out of it, and
    # each step covers only the gap since the previous span.
    cut = start - 1
    while cut > 0 and line[cut - 1] in " \t":
        cut -= 1
    while cut > 0 and line[cut - 1] == "`":
        cut -= 1
    while cut > 0 and line[cut - 1] in " \t":
        cut -= 1
    before = line[max(0, cut - APPROVAL_CONTEXT_WINDOW) : cut]
    if APPROVAL_ASSIGNMENT_TAIL_RE.search(before):
        return False
    sentence_start = max(before.rfind(mark) for mark in ".!?;") + 1
    prefix = before[sentence_start:]
    suffix = APPROVAL_SENTENCE_END_RE.split(line[end + 1 : end + 1 + APPROVAL_CONTEXT_WINDOW], maxsplit=1)[0]
    verbs = list(APPROVAL_INSTRUCTION_RE.finditer(prefix))
    if not verbs:
        return True
    negated = APPROVAL_NEGATION_RE.search(prefix[: verbs[-1].start()]) is not None
    risky = APPROVAL_RISK_RE.search(f"{prefix} {suffix}") is not None
    return negated or risky


def _markdown_fence_marker(line: str) -> tuple[str, int] | None:
    """The fence token and the column of its first character, if this line is a fence.

    A list marker on the same line is skipped, so ``- ```bash`` is a fence at the
    token's column. Closing compares that column with the opening fence.
    """
    match = MARKDOWN_FENCE_RE.match(line)
    if match:
        return match.group(1), match.start(1)
    without_list_marker = MARKDOWN_LIST_MARKER_RE.sub("", line, count=1)
    if without_list_marker == line:
        return None
    match = MARKDOWN_FENCE_RE.match(without_list_marker)
    if match is None:
        return None
    column = len(line) - len(without_list_marker) + match.start(1)
    return match.group(1), column


def _markdown_code_lines(lines: list[str]) -> list[bool]:
    """Mark the lines of fenced or indented code, fence lines included.

    Block-quote prefixes are removed first, and a list marker on the fence line
    is skipped, so a fence inside a quote or a list item still counts. A closing
    marker ends the fence only when it sits under the same number of quote
    markers as the opening fence and is indented no deeper, so a marker one
    quote level deeper, or quoted inside an unquoted fence, is text. An
    indented line starts a code block only after a blank line or a heading, or
    continues one, because indented code cannot interrupt a paragraph.
    """
    code_lines: list[bool] = []
    fence: str | None = None
    fence_column = 0
    fence_quote_depth = 0
    can_start_indented_code = True
    for raw_line in lines:
        quote_match = MARKDOWN_BLOCKQUOTE_PREFIX_RE.match(raw_line)
        quote_depth = quote_match.group(0).count(">") if quote_match else 0
        line = raw_line[quote_match.end() :] if quote_match else raw_line
        marker = _markdown_fence_marker(line)
        if fence is not None:
            is_code = True
            if marker is not None:
                token, column = marker
                remainder = line[column + len(token) :]
                if (
                    quote_depth == fence_quote_depth
                    and column <= fence_column
                    and token[0] == fence[0]
                    and len(token) >= len(fence)
                    and not remainder.strip()
                ):
                    fence = None
        elif marker is not None:
            fence, fence_column = marker
            fence_quote_depth = quote_depth
            is_code = True
        else:
            is_code = line.startswith(("    ", "\t")) and can_start_indented_code
        code_lines.append(is_code)
        stripped = line.strip()
        can_start_indented_code = is_code or not stripped or stripped.startswith("#")
    return code_lines


def _has_risky_approval_default(relative_path: Path, content: str, *, declared: bool = False) -> bool:
    """Whether the file sets a risky approval or sandbox default.

    Documentation may name a value in an inline code span without setting it.
    A file an ecosystem declares as package content (``declared``), an agent
    instruction file, and every non-Markdown file are matched as before.
    """
    if (
        declared
        or relative_path.suffix.lower() not in DOCUMENTATION_EXTS
        or _is_agent_instruction_surface(relative_path)
    ):
        return any(pattern.search(content) for pattern in RISKY_APPROVAL_PATTERNS)
    lines = content.split("\n")
    line_starts = [0]
    for line in lines[:-1]:
        line_starts.append(line_starts[-1] + len(line) + 1)
    code_lines = _markdown_code_lines(lines)
    for pattern in RISKY_APPROVAL_PATTERNS:
        for match in pattern.finditer(content):
            index = bisect.bisect_right(line_starts, match.start()) - 1
            line_start = line_starts[index]
            if "\n" in match.group(0) or code_lines[index]:
                return True
            if not _is_documented_approval_value(lines[index], match.start() - line_start, match.end() - line_start):
                return True
    return False


def _instruction_file_keys(
    plugin_dir: Path, resolved_plugin_dir: Path, instruction_files: tuple[Path, ...]
) -> frozenset[str]:
    """The relative paths of ``instruction_files`` under the plugin directory, as the scan reports them."""
    keys: set[str] = set()
    for path in instruction_files:
        relative = path
        if path.is_absolute():
            for root in (resolved_plugin_dir, plugin_dir):
                try:
                    relative = path.relative_to(root)
                    break
                except ValueError:
                    continue
            else:
                continue
        normalized = os.path.normpath(relative.as_posix())
        if normalized.startswith("..") or os.path.isabs(normalized):
            continue
        keys.add(Path(normalized).as_posix())
    return frozenset(keys)


def check_no_approval_bypass_defaults(
    plugin_dir: Path, files: tuple[Path, ...] | None = None, *, instruction_files: tuple[Path, ...] = ()
) -> CheckResult:
    """Report files that default to bypassed approvals or an unrestricted sandbox.

    ``files`` limits the scan to the package content an ecosystem declared,
    such as a manifest's system prompt or commands, read as instructions.
    ``instruction_files`` names files an agent loads as instructions, such as
    a manifest's context file: the whole directory is still scanned, and those
    files get no documentation exception.
    """
    findings: list[str] = []
    resolved_plugin_dir = plugin_dir.resolve()
    strict_paths = _instruction_file_keys(plugin_dir, resolved_plugin_dir, instruction_files)
    try:
        for file_path in _scan_all_files(resolved_plugin_dir, files):
            relative_path = file_path.relative_to(resolved_plugin_dir)
            if not file_path.name.endswith((".json", ".md", ".yaml", ".yml", ".toml")):
                continue
            try:
                content = read_text_file_within_root(
                    resolved_plugin_dir,
                    file_path,
                    max_bytes=MAX_SCAN_FILE_BYTES,
                    errors="ignore",
                )
            except (OSError, UnicodeError):
                return unreadable_scan_input_failure(
                    "No approval bypass defaults",
                    max_points=3,
                    path=relative_path.as_posix(),
                )
            declared = files is not None or relative_path.as_posix() in strict_paths
            if _has_risky_approval_default(relative_path, content, declared=declared):
                findings.append(relative_path.as_posix())
    except ScanInputUnreadableError as exc:
        return unreadable_scan_input_failure(
            "No approval bypass defaults",
            max_points=3,
            reason=str(exc),
        )
    except ScanBudgetExceededError as exc:
        return _resource_budget_failure("No approval bypass defaults", max_points=3, reason=str(exc))

    if not findings:
        return CheckResult(
            name="No approval bypass defaults",
            passed=True,
            points=3,
            max_points=3,
            message="No risky approval or sandbox defaults detected.",
        )

    return CheckResult(
        name="No approval bypass defaults",
        passed=False,
        points=0,
        max_points=3,
        message=f"Risky approval defaults found in: {', '.join(findings)}",
        findings=tuple(
            Finding(
                rule_id="RISKY_APPROVAL_DEFAULT",
                severity=Severity.MEDIUM,
                category="security",
                title="Risky approval or sandbox default detected",
                description=f"{path} contains a dangerous approval or sandbox default.",
                remediation=(
                    "Avoid shipping configurations that default to bypassed approvals or unrestricted sandboxes."
                ),
                file_path=path,
            )
            for path in findings
        ),
    )


def run_security_checks(plugin_dir: Path, *, instruction_files: tuple[Path, ...] = ()) -> tuple[CheckResult, ...]:
    """Run the security checks; ``instruction_files`` are read as agent instructions by the approval check."""
    return (
        check_security_md(plugin_dir),
        check_license(plugin_dir),
        check_no_hardcoded_secrets(plugin_dir),
        check_no_dangerous_mcp(plugin_dir),
        check_mcp_transport_security(plugin_dir),
        check_no_approval_bypass_defaults(plugin_dir, instruction_files=instruction_files),
    )
