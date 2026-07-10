"""Safe, non-content evidence derived from primary skill documents."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

MAX_SKILL_DOCUMENT_BYTES = 256 * 1024
_ANALYSIS_VERSION = "1"
_HEADING_RE = re.compile(r"^#{1,6}\s+\S")
_NEGATION_RE = re.compile(
    r"\b(?:avoid|do\s+not|does\s+not|don't|doesn't|must\s+not|never|no\s+need\s+to|without)\b",
    re.IGNORECASE,
)
_COUNTEREXAMPLE_RE = re.compile(r"\b(?:counterexample|non-example|not\s+an?\s+example)\b", re.IGNORECASE)
_EXAMPLE_PREFIX_RE = re.compile(r"^\s*(?:for\s+example|example)\s*:", re.IGNORECASE)
_INLINE_QUOTED_RE = re.compile(r"""(?:"[^"]*"|'[^']*')""")
_HTTP_CLIENT_RE = re.compile(
    r"(?:"
    r"\b(?:curl|wget)\b[^\n]*"
    r"|\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|"
    r"httpx\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen)\s*\([^\n]*"
    r"|\bInvoke-WebRequest\b[^\n]*"
    r")",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s)'\"<>`]+", re.IGNORECASE)
_ACTIVE_REMOTE_BEHAVIOR_RE = re.compile(
    r"\b(?:this\s+skill|the\s+skill|this\s+workflow|the\s+workflow|the\s+agent|"
    r"this\s+tool|the\s+tool|the\s+client|it)\s+"
    r"(?:calls?|contacts?|connects?\s+to|fetches?(?:\s+\w+){0,3}\s+from|queries|"
    r"requests?(?:\s+\w+){0,3}\s+from|sends?(?:\s+\w+){0,3}\s+to|"
    r"uploads?(?:\s+\w+){0,3}\s+to)\b"
    r"[^.!?\n]{0,160}\b(?:api|endpoint|remote\s+service|external\s+service|cloud\s+service)\b",
    re.IGNORECASE,
)


def enrich_skill_document_metadata(
    config_path: object,
    metadata: dict[str, object],
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> dict[str, object]:
    """Add bounded evidence for a primary SKILL.md without retaining its content."""

    enriched = dict(metadata)
    enriched.pop("skillDocumentEvidence", None)
    enriched.pop("contentEvidence", None)
    enriched.pop("documentedCapabilities", None)
    evidence, documented_capabilities = _analyze_skill_document(
        config_path,
        safe_roots=(home_dir, workspace_dir),
    )
    enriched["contentEvidence"] = evidence
    if documented_capabilities:
        enriched["documentedCapabilities"] = documented_capabilities
    return enriched


def _analyze_skill_document(
    config_path: object,
    *,
    safe_roots: tuple[Path | None, ...],
) -> tuple[dict[str, object], list[dict[str, str]]]:
    evidence: dict[str, object] = {
        "analysisVersion": _ANALYSIS_VERSION,
        "readabilityStatus": "unavailable",
    }
    if not isinstance(config_path, str) or not config_path:
        return evidence, []

    path = Path(config_path)
    if path.name.casefold() != "skill.md":
        evidence["readabilityStatus"] = "not_primary_skill_document"
        return evidence, []
    skills_root = next(
        (parent for parent in path.parents if parent.name.casefold() == "skills"),
        None,
    )
    if skills_root is None:
        evidence["readabilityStatus"] = "not_primary_skill_document"
        return evidence, []
    try:
        relative = path.relative_to(skills_root)
    except ValueError:
        evidence["readabilityStatus"] = "not_primary_skill_document"
        return evidence, []
    if len(relative.parts) < 2:
        evidence["readabilityStatus"] = "not_primary_skill_document"
        return evidence, []
    if _has_symlink_component(path, allowed_root=skills_root):
        evidence["readabilityStatus"] = "symlink_rejected"
        return evidence, []
    try:
        if path.is_symlink():
            evidence["readabilityStatus"] = "symlink_rejected"
            return evidence, []
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        evidence["readabilityStatus"] = "unreadable"
        return evidence, []

    resolved_roots = _resolved_safe_roots(safe_roots)
    try:
        resolved_skills_root = skills_root.resolve(strict=True)
    except (OSError, RuntimeError):
        evidence["readabilityStatus"] = "unreadable"
        return evidence, []
    if not any(_is_relative_to(resolved_skills_root, root) for root in resolved_roots):
        evidence["readabilityStatus"] = "outside_safe_roots"
        return evidence, []

    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
        try:
            file_stat = os.fstat(descriptor)
            evidence["byteLength"] = file_stat.st_size
            if not stat.S_ISREG(file_stat.st_mode):
                evidence["readabilityStatus"] = "not_regular_file"
                return evidence, []
            if file_stat.st_size > MAX_SKILL_DOCUMENT_BYTES:
                evidence["readabilityStatus"] = "too_large"
                return evidence, []
            content = _read_bounded(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        evidence["readabilityStatus"] = "unreadable"
        return evidence, []

    if len(content) > MAX_SKILL_DOCUMENT_BYTES:
        evidence["readabilityStatus"] = "too_large"
        evidence["byteLength"] = len(content)
        return evidence, []
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        evidence["readabilityStatus"] = "invalid_utf8"
        return evidence, []

    lines = text.splitlines()
    evidence.update(
        {
            "readabilityStatus": "readable",
            "schemaVersion": "guard.skill.content-evidence.v1",
            "contentHash": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "lineCount": len(lines),
            "headingCount": sum(bool(_HEADING_RE.match(line)) for line in lines),
            "frontmatterPresent": _has_frontmatter(lines),
            "truncatedForAnalysis": False,
        }
    )
    capability = _documented_network_capability(lines)
    return evidence, [capability] if capability is not None else []


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_SKILL_DOCUMENT_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _resolved_safe_roots(safe_roots: tuple[Path | None, ...]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for root in safe_roots:
        if root is None:
            continue
        try:
            roots.append(root.resolve(strict=True))
        except OSError:
            continue
    return tuple(roots)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_symlink_component(path: Path, *, allowed_root: Path) -> bool:
    try:
        relative = path.relative_to(allowed_root)
    except ValueError:
        return True
    current = allowed_root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _has_frontmatter(lines: list[str]) -> bool:
    return bool(lines) and lines[0].strip() == "---" and any(line.strip() == "---" for line in lines[1:])


def _documented_network_capability(lines: list[str]) -> dict[str, str] | None:
    section_heading = ""
    for index, line in enumerate(lines):
        if _HEADING_RE.match(line):
            section_heading = line
            continue
        if line.lstrip().startswith(">"):
            continue
        if _EXAMPLE_PREFIX_RE.match(line):
            continue
        behavior_line = _INLINE_QUOTED_RE.sub("", line)
        context = line
        if index > 0 and lines[index - 1].rstrip().endswith(":"):
            context = f"{lines[index - 1]} {line}"
        if section_heading:
            context = f"{section_heading} {context}"
        if _is_negative_context(context):
            continue
        client_match = _HTTP_CLIENT_RE.search(line)
        if (
            client_match
            and not _is_inside_prose_quote(line, client_match.start())
            and any(_is_remote_url(url) for url in _URL_RE.findall(line))
        ):
            return _network_capability("explicit_http_client")
        if _ACTIVE_REMOTE_BEHAVIOR_RE.search(behavior_line):
            return _network_capability("explicit_remote_api_statement")
    return None


def _is_negative_context(value: str) -> bool:
    return bool(_NEGATION_RE.search(value) or _COUNTEREXAMPLE_RE.search(value))


def _is_inside_prose_quote(value: str, offset: int) -> bool:
    double_open = False
    single_open = False
    for index, character in enumerate(value[:offset]):
        if index > 0 and value[index - 1] == "\\":
            continue
        if character == '"' and not single_open:
            double_open = not double_open
            continue
        if character != "'" or double_open:
            continue
        previous = value[index - 1] if index > 0 else ""
        following = value[index + 1] if index + 1 < len(value) else ""
        if previous.isalnum():
            if single_open:
                single_open = False
            continue
        if following.isalnum():
            single_open = True
    return double_open or single_open


def _is_remote_url(value: str) -> bool:
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return False
    if not host:
        return False
    normalized = host.casefold().rstrip(".")
    return normalized not in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} and not normalized.endswith(".localhost")


def _network_capability(evidence_code: str) -> dict[str, str]:
    return {
        "capability": "network_egress",
        "source": "skill_documentation",
        "confidence": "high",
        "evidenceCode": evidence_code,
        "inferenceVersion": _ANALYSIS_VERSION,
    }
