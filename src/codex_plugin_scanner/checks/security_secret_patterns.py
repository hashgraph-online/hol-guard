"""Secret detectors and bounded recognition of non-secret token expressions."""

from __future__ import annotations

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
