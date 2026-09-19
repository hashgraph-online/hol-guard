"""Security checks (20 points)."""

from __future__ import annotations

# Keep dependency imports and facade bindings in their original evaluation order.
# ruff: noqa: I001

import bisect as bisect
import ipaddress as ipaddress
import json as json
import os as os
import re as re
import stat as stat
from itertools import pairwise as pairwise
from pathlib import Path as Path
from urllib.parse import urlparse as urlparse

from ..models import CheckResult as CheckResult, Finding as Finding, Severity as Severity
from ..path_support import (
    path_entry_exists as path_entry_exists,
    read_text_file_within_root as read_text_file_within_root,
    resolves_within_root as resolves_within_root,
)
from .security_failures import (
    ScanInputUnreadableError as ScanInputUnreadableError,
    unreadable_scan_input_failure as unreadable_scan_input_failure,
)
from .security_secret_patterns import (
    DOCUMENTATION_EXTS as DOCUMENTATION_EXTS,
    SECRET_PATTERNS as SECRET_PATTERNS,
    SecretPattern as SecretPattern,
    _field_name_map_spans as _field_name_map_spans,
    _is_generated_token_expression as _is_generated_token_expression,
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

APACHE_LICENSE_VERSION_RE = re.compile(r"apache\s+license\s*,?\s*version\s+2\.0", re.I)
LICENSE_URL_RE = re.compile(r"https?://[^\s<>()\"']+")


class ScanBudgetExceededError(RuntimeError):
    """Raised when analysis would be incomplete because a scan budget was exhausted."""


from .security_content import _raise_walk_error as _raise_walk_error  # noqa: E402


from .security_content import _scan_all_files as _scan_all_files  # noqa: E402


from .security_secret_detection import _is_example_surface as _is_example_surface  # noqa: E402


from .security_secret_detection import _extract_secret_candidate as _extract_secret_candidate  # noqa: E402


from .security_secret_detection import _normalize_secret_candidate as _normalize_secret_candidate  # noqa: E402


_PURE_SHELL_EXPANSION_RE = re.compile(
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*"
    r"(?:(?::-|-|:=|=|:\?|\?|:\+|\+)(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)?)?"
    r"\}$"
)
_PURE_TEMPLATE_EXPANSION_RE = re.compile(r"^\{\{[^}]+\}\}$")


from .security_secret_detection import _looks_like_interpolated_secret as _looks_like_interpolated_secret  # noqa: E402


from .security_secret_detection import _looks_like_placeholder_secret as _looks_like_placeholder_secret  # noqa: E402


from .security_secret_detection import _normalized_alnum as _normalized_alnum  # noqa: E402


from .security_secret_detection import _ascending_run_stats as _ascending_run_stats  # noqa: E402


from .security_secret_detection import _provider_payload as _provider_payload  # noqa: E402


from .security_secret_detection import (  # noqa: E402
    _looks_like_synthetic_provider_candidate as _looks_like_synthetic_provider_candidate,
)


from .security_secret_detection import (  # noqa: E402
    _looks_like_incomplete_provider_candidate as _looks_like_incomplete_provider_candidate,
)


from .security_secret_detection import _looks_like_example_generic_secret as _looks_like_example_generic_secret  # noqa: E402


from .security_secret_detection import _newline_offsets as _newline_offsets  # noqa: E402


from .security_secret_detection import _line_number_for_offset as _line_number_for_offset  # noqa: E402


from .security_secret_detection import _has_illustrative_context as _has_illustrative_context  # noqa: E402


from .security_secret_detection import _private_key_looks_like_placeholder as _private_key_looks_like_placeholder  # noqa: E402


from .security_secret_detection import _extract_inline_private_key_body as _extract_inline_private_key_body  # noqa: E402


from .security_secret_detection import _first_private_key_line as _first_private_key_line  # noqa: E402


from .security_secret_detection import _should_skip_secret_match as _should_skip_secret_match  # noqa: E402


from .security_secret_detection import _first_hardcoded_secret_line as _first_hardcoded_secret_line  # noqa: E402


from .security_content import _has_canonical_apache_license_reference as _has_canonical_apache_license_reference  # noqa: E402


from .security_content import _resource_budget_failure as _resource_budget_failure  # noqa: E402


from .security_content import check_security_md as check_security_md  # noqa: E402


from .security_content import check_license as check_license  # noqa: E402


from .security_content import _hardcoded_secret_result as _hardcoded_secret_result  # noqa: E402


from .security_mcp import check_no_dangerous_mcp as check_no_dangerous_mcp  # noqa: E402


IGNORED_MCP_URL_CONTEXT = {"metadata", "description", "homepage", "website", "docs", "documentation"}
MCP_URL_KEYS = {"url", "endpoint", "server_url"}


from .security_mcp import _collect_mcp_urls as _collect_mcp_urls  # noqa: E402


from .security_mcp import _extract_mcp_urls as _extract_mcp_urls  # noqa: E402


from .security_mcp import _is_loopback_host as _is_loopback_host  # noqa: E402


from .security_mcp import check_mcp_transport_security as check_mcp_transport_security  # noqa: E402


from .security_content import _approval_bypass_result as _approval_bypass_result  # noqa: E402


from .security_content import _scan_content_checks as _scan_content_checks  # noqa: E402


from .security_content import check_no_hardcoded_secrets as check_no_hardcoded_secrets  # noqa: E402


from .security_content import check_no_approval_bypass_defaults as check_no_approval_bypass_defaults  # noqa: E402


from .security_content import run_security_checks as run_security_checks  # noqa: E402
