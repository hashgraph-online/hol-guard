"""Secret detectors and bounded recognition of non-secret token expressions."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SecretPattern:
    pattern: re.Pattern[str]
    kind: str = "provider"
    value_group: int = 0


# Patterns for hardcoded secrets
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern(re.compile(r"aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", re.I), value_group=1),
    SecretPattern(
        re.compile(
            r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----"
            r"[\s\S]{32,}?"
            r"-----END (?P=label)-----"
        ),
        kind="private_key",
    ),
    SecretPattern(re.compile(r"password\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"secret\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"token\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"api_?key\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"API_KEY\s*[=:]\s*[\"']([^\s\"']{8,})"), kind="generic", value_group=1),
    SecretPattern(re.compile(r"PRIVATE_KEY\s*[=:]\s*[\"']([^\s\"']{8,})"), kind="generic", value_group=1),
    SecretPattern(re.compile(r"ghp_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"gho_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"ghu_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"ghs_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    SecretPattern(re.compile(r"glpat-[A-Za-z0-9\-]{20}")),
    SecretPattern(re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xoxe-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xoxr-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xapp-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
)

DOCUMENTATION_EXTS = {".md", ".mdx", ".markdown", ".rst", ".adoc", ".asciidoc"}

# A bounded TypeScript field-name dictionary is metadata, not credential values.
# The safety invariant is that EVERY value is derivable from its key by case
# conversion (or the inverse); the type/count checks only constrain scope.
# Arbitrary uppercase strings and ordinary credential objects do not
# qualify. Compute spans once per file rather than rescanning for every match.
FIELD_NAME_MAP_RE = re.compile(
    r"(?m)^[ \t]*const [A-Za-z_$][\w$]*[ \t]*:[ \t]*Record<[^;\n{}]{1,160}>"
    r"[ \t]*=[ \t]*\{(?P<body>[^{}]{1,4096})\}[ \t]*;"
)
FIELD_NAME_ENTRY_RE = re.compile(r"""\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*(["'])([A-Za-z][A-Za-z0-9_]*)\2\s*""")
GENERATED_TOKEN_RE = re.compile(r'\$\(openssl rand -(?:hex|base64) [1-9][0-9]{0,3}\)"(?=$|[\s;])')
SYMBOLIC_REFERENCE_RE = re.compile(r"\$[A-Z_][A-Z0-9_]*")
KNOWN_TEMPLATE_MARKERS = frozenset({"$ARGUMENTS"})
PASSWORD_NAVIGATION_KEYS = frozenset({"ForgotPassword", "ResetPassword", "ChangePassword"})
LITERAL_END_RE = re.compile(r"[ \t]*(?=$|[;\r\n])")
TRAILING_WHITESPACE_RE = re.compile(r"\s*\Z")
SHELL_OPTION_PREFIX_RE = re.compile(
    r"[ \t]*(?:-[ \t]+)?[A-Za-z0-9_./-]+(?:[ \t]+[A-Za-z0-9_./-]+)*[ \t]+--[A-Za-z0-9_-]*"
)
SCREEN_ROUTE_MAP_RE = re.compile(r"\bscreens\s*:\s*\{(?P<body>[^{}]{1,4096})\}")
SCREEN_ROUTE_ENTRY_RE = re.compile(r"""\s*([A-Z][A-Za-z]*)\s*:\s*(["'])([a-z]+(?:-[a-z]+)*)\2\s*""")


def _python_symbolic_reference_spans(relative_path: Path, content: str) -> frozenset[tuple[int, int]]:
    """Prove complete Python assignment values before allowing newline termination."""
    if relative_path.suffix.lower() != ".py" or "$ARGUMENTS" not in content or len(content) > 1_048_576:
        return frozenset()
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, UnicodeError):
        return frozenset()
    # AST positions use physical universal newlines, not Unicode separators
    # that str.splitlines() also treats as line boundaries inside strings.
    offsets = [0, *(match.end() for match in re.finditer(r"\r\n|\r|\n", content))]
    spans = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value in KNOWN_TEMPLATE_MARKERS
            and value.lineno == value.end_lineno
            and value.end_col_offset is not None
        ):
            continue
        if not 1 <= value.lineno <= len(offsets):
            continue
        line_start = offsets[value.lineno - 1]
        line_end = offsets[value.lineno] if value.lineno < len(offsets) else len(content)
        line = content[line_start:line_end].encode("utf-8")
        if not 0 <= value.col_offset <= value.end_col_offset <= len(line):
            continue
        try:
            start = line_start + len(line[: value.col_offset].decode("utf-8"))
            end = line_start + len(line[: value.end_col_offset].decode("utf-8"))
        except UnicodeDecodeError:
            continue
        spans.add((start, end))
    return frozenset(spans)


def _is_symbolic_reference_literal(
    relative_path: Path,
    content: str,
    match: re.Match[str],
    python_reference_spans: frozenset[tuple[int, int]] = frozenset(),
) -> bool:
    """Recognize shell expansions or a reserved template marker, never arbitrary passwords."""
    start = match.start(1)
    if start == 0 or content[start - 1] not in "\"'":
        return False
    quote = content[start - 1]
    if quote == "'" and relative_path.suffix.lower() in DOCUMENTATION_EXTS | {".sh", ".bash"}:
        return False
    end = content.find(quote, start)
    if end == -1 or match.end(1) > end or not SYMBOLIC_REFERENCE_RE.fullmatch(content, start, end):
        return False
    suffix = relative_path.suffix.lower()
    line_start = content.rfind("\n", 0, match.start()) + 1
    shell_option = SHELL_OPTION_PREFIX_RE.fullmatch(content, line_start, match.start()) is not None
    if (
        content[start:end] not in KNOWN_TEMPLATE_MARKERS
        and suffix not in {".sh", ".bash"}
        and not (suffix in DOCUMENTATION_EXTS and shell_option)
    ):
        return False
    if suffix == ".py":
        return (start - 1, end + 1) in python_reference_spans
    after = end + 1
    terminator = LITERAL_END_RE.match(content, after)
    if terminator is None:
        return False
    after = terminator.end()
    if after == len(content) or content[after] == ";":
        return True
    if TRAILING_WHITESPACE_RE.match(content, after) or (start - 1, end + 1) in python_reference_spans:
        return True
    # A documentation suffix is not a language guarantee: JavaScript examples
    # can continue after a newline. Only recognize a simple shell option here.
    if relative_path.suffix.lower() in DOCUMENTATION_EXTS | {".sh", ".bash"}:
        line_start = content.rfind("\n", 0, match.start()) + 1
        return SHELL_OPTION_PREFIX_RE.fullmatch(content, line_start, match.start()) is not None
    return False


def _screen_route_map_spans(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    """Exempt known password-navigation entries, never an entire credential-shaped map."""
    if relative_path.suffix.lower() not in DOCUMENTATION_EXTS | {".js", ".jsx", ".ts", ".tsx"}:
        return ()
    spans = []
    for mapping in SCREEN_ROUTE_MAP_RE.finditer(content):
        entries = mapping.group("body").strip().rstrip(",").split(",")
        if len(entries) < 2:
            continue
        for entry in entries:
            pair = SCREEN_ROUTE_ENTRY_RE.fullmatch(entry)
            if pair is None:
                break
            key, _, value = pair.groups()
            if value != re.sub(r"([a-z])([A-Z])", r"\1-\2", key).lower():
                break
        else:
            for pair in SCREEN_ROUTE_ENTRY_RE.finditer(mapping.group("body")):
                if pair.group(1) in PASSWORD_NAVIGATION_KEYS:
                    origin = mapping.start("body")
                    spans.append((origin + pair.start(), origin + pair.end()))
    return tuple(spans)


def _field_name_map_spans(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    """Index bounded TS field maps only when every value is case-derived from its key."""
    if relative_path.suffix.lower() not in {".ts", ".tsx"}:
        return ()
    spans = []
    for mapping in FIELD_NAME_MAP_RE.finditer(content):
        entries = mapping.group("body").strip().rstrip(",").split(",")
        if len(entries) < 2:
            continue
        for entry in entries:
            pair = FIELD_NAME_ENTRY_RE.fullmatch(entry)
            if pair is None:
                break
            key, _, value = pair.groups()
            if key[0].isupper():
                key, value = value, key
            snake_key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).upper()
            if not re.fullmatch(r"[a-z][A-Za-z0-9]*", key) or value != snake_key:
                break
        else:
            spans.append(mapping.span("body"))
    return tuple(spans)


def _is_generated_token_expression(relative_path: Path, content: str, match: re.Match[str]) -> bool:
    """Recognize a complete double-quoted OpenSSL token generator in shell or docs."""
    if relative_path.suffix.lower() not in DOCUMENTATION_EXTS | {".sh", ".bash"}:
        return False
    start = match.start(1)
    # Single-quoted shell values are literal; arbitrary substitutions may carry
    # credentials. Accept only the complete double-quoted random generator.
    generated = GENERATED_TOKEN_RE.match(content, start)
    return start > 0 and content[start - 1] == '"' and generated is not None and match.end(1) <= generated.end()
