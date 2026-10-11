"""Bounded shell credential reads are references, not embedded secret values."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..models import Finding, Severity
from .security_secret_patterns import SECRET_PATTERNS

_VARIABLE = r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})"
_ENV_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_ENV_ARG = rf"(?:{_VARIABLE}|{_ENV_NAME}|\"(?:{_VARIABLE}|{_ENV_NAME})\")"
_SCOPE_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.:@-]*"
_SCOPE_ARG = rf"(?:{_VARIABLE}|{_SCOPE_NAME}|\"(?:{_VARIABLE}|{_SCOPE_NAME})\")"
_SCOPE_OPTION = rf"[ \t]+--(?:project|configuration|account|impersonate-service-account)(?:=|[ \t]+){_SCOPE_ARG}"
_GCLOUD_READ = (
    rf"gcloud(?:{_SCOPE_OPTION})*[ \t]+auth[ \t]+(?:application-default[ \t]+)?print-access-token(?:{_SCOPE_OPTION})*"
)
_READ = rf"(?:printenv[ \t]+{_ENV_ARG}|{_GCLOUD_READ})"
_QUIET_FAILURE = r"(?:[ \t]+2>/dev/null)?(?:[ \t]+\|\|[ \t]+true)?"
_ASSIGNMENT_RE = re.compile(
    rf"(?:^|;)[ \t]*(?:(?:then|else|do)[ \t]+)?(?:export[ \t]+)?"
    rf"(?P<name>{_ENV_NAME})=\"(?P<value>\$\({_READ}{_QUIET_FAILURE}\))\""
    r"(?=[ \t]*(?:$|;)|[ \t]+#)",
    re.MULTILINE,
)
_FENCE_RE = re.compile(r"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})(?P<info>[^\r\n]*)$", re.MULTILINE)
_SHELL_LANGUAGES = frozenset({"bash", "sh", "shell"})
_CONDITIONAL_PARAMETER = re.compile(rf"\$\{{{_ENV_NAME}:[+-]")
_UNBRACED_VARIABLE = re.compile(rf"\${_ENV_NAME}")
_CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:token|secret|password|passwd|credentials?|api_?key|private_?key|access_?key)(?:_|$)",
    re.IGNORECASE,
)
_NAME_METADATA_SUFFIXES = ("_NAME", "_VAR", "_ENV", "_FILE", "_PATH")
_IMPERSONATION_OPTION = re.compile(r"[ \t]+--impersonate-service-account(?:=|[ \t]+)")


@dataclass(frozen=True, slots=True)
class ShellCredentialRead:
    """A recognized assignment; no command execution or credential values."""

    span: tuple[int, int]
    kind: Literal["environment", "gcloud", "gcloud_impersonation"]
    credential_related: bool


def _credential_name(name: str, *, indirect: bool = False) -> bool:
    if not indirect and name.upper().endswith(_NAME_METADATA_SUFFIXES):
        return False
    return _CREDENTIAL_NAME.search(name) is not None


def _assignment_read(match: re.Match[str]) -> ShellCredentialRead:
    value = match.group("value")
    span = (match.start("name"), match.end("value") + 1)
    if value.startswith("$(gcloud"):
        kind = "gcloud_impersonation" if _IMPERSONATION_OPTION.search(value) else "gcloud"
        return ShellCredentialRead(span, kind, True)
    # The assignment regex already proved this is a single allowlisted printenv
    # argument. A variable argument identifies the name to read indirectly.
    argument = re.match(rf"\$\(printenv[ \t]+({_ENV_ARG})", value)
    assert argument is not None
    name = argument.group(1).strip('"')
    credential_related = (
        _credential_name(match.group("name"))
        or _credential_name(name.strip("${}"), indirect=name.startswith("$"))
        # Every generic match removed by this assignment's exemption must retain
        # a capability signal, including authToken/clientSecret-style names.
        or any(
            detector.kind == "generic" and detector.pattern.search(match.group(0)) is not None
            for detector in SECRET_PATTERNS
        )
    )
    return ShellCredentialRead(span, "environment", credential_related)


@dataclass
class _ShellContext:
    quote: str | None = None
    parentheses: int = 0
    word_start: bool = True
    parameter: bool = False


def _statement_reads(content: str, start: int, end: int) -> list[ShellCredentialRead]:
    """Accept candidates only at unquoted, unescaped shell statement boundaries.

    Track nested command substitutions separately from their containing quotes.
    Unsupported here-documents, backticks and extended quoting stop exemptions
    for the rest of this range; the ordinary secret detectors still inspect it.
    This lexical check does not execute or interpret any shell command.
    """
    candidates = {match.start(): match for match in _ASSIGNMENT_RE.finditer(content, start, end)}
    if not candidates:
        return []
    contexts = [_ShellContext()]
    statement_start = start
    reads: list[ShellCredentialRead] = []
    index = start
    while index < end:
        context = contexts[-1]
        char = content[index]
        top_level = len(contexts) == 1 and context.quote is None and context.parentheses == 0
        if top_level and (index == statement_start or char == ";") and index in candidates:
            match = candidates[index]
            reads.append(_assignment_read(match))
        if context.quote == "'":
            if char == "'":
                context.quote = None
            index += 1
            continue
        if context.parameter and (char in "'\\" or content.startswith("$(", index)):
            break
        if char == "\\":
            # A continued physical line or escaped semicolon is not a boundary.
            if index + 1 < end and content[index + 1] != "\n":
                context.word_start = False
            index += 2
            continue
        if char == "#" and context.quote is None and context.word_start and not context.parameter:
            newline = content.find("\n", index, end)
            index = newline if newline >= 0 else end
            continue
        if char == "`" or (context.quote is None and content.startswith(("$'", '$"', "<<"), index)):
            break
        if context.parameter and char == "$" and not content.startswith("${", index):
            variable = _UNBRACED_VARIABLE.match(content, index)
            if variable is None:
                break
            index = variable.end()
            continue
        if content.startswith("${", index):
            closing = content.find("}", index + 2, end)
            if closing < 0:
                break
            parameter_text = _UNBRACED_VARIABLE.sub("", content[index + 2 : closing])
            if any(symbol in parameter_text for symbol in "'\"`{}\\$"):
                # A closed, unquoted conditional parameter can contain quoted
                # text and nested simple references. No assignment inside it
                # qualifies. Other expansion grammar remains conservative.
                if context.quote is not None or len(contexts) >= 64 or not _CONDITIONAL_PARAMETER.match(content, index):
                    break
                context.word_start = False
                contexts.append(_ShellContext(parameter=True))
                index += 2
                continue
            context.word_start = False
            index = closing + 1
            continue
        if content.startswith("$(", index):
            if len(contexts) >= 64:
                break
            context.word_start = False
            contexts.append(_ShellContext())
            index += 2
            continue
        if char == '"':
            context.quote = None if context.quote == '"' else '"'
            context.word_start = False
        elif char == "'" and context.quote is None:
            context.quote = "'"
            context.word_start = False
        elif context.quote is None:
            if char == "}" and context.parameter:
                _ = contexts.pop()
            elif char == "(" and not context.parameter:
                context.parentheses += 1
            elif char == ")" and not context.parameter:
                if context.parentheses:
                    context.parentheses -= 1
                elif len(contexts) > 1:
                    _ = contexts.pop()
            if char == "\n" and top_level:
                statement_start = index + 1
            context.word_start = char in " \t\n;|&()<>"
        index += 1
    return reads


def _shell_code_ranges(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    """Require a shell file or a closed, explicitly shell-tagged Markdown fence."""
    suffix = relative_path.suffix.lower()
    if suffix in {".sh", ".bash"}:
        return ((0, len(content)),)
    if suffix not in {".md", ".mdx", ".markdown"}:
        return ()
    ranges: list[tuple[int, int]] = []
    opened: tuple[str, int, int, bool] | None = None
    for fence in _FENCE_RE.finditer(content):
        marker = fence.group("marker")
        info = fence.group("info").strip()
        if opened is None:
            language = info.split(maxsplit=1)[0] if info else ""
            opened = (marker[0], len(marker), fence.end(), language in _SHELL_LANGUAGES)
        elif not info and marker[0] == opened[0] and len(marker) >= opened[1]:
            if opened[3]:
                ranges.append((opened[2], fence.start()))
            opened = None
    return tuple(ranges)


def _shell_credential_reads(relative_path: Path, content: str) -> tuple[ShellCredentialRead, ...]:
    """Prove complete assignments before exempting any generic detector match.

    This is a small allowlist, not a shell evaluator. It admits one environment
    lookup or one access-token command, optional stderr suppression and an empty
    failure result. Extra commands, literal prefixes/suffixes, defaults and
    arbitrary cloud flags do not qualify. Provider-secret detectors still scan
    the same text independently.
    """
    if "$(" not in content:
        return ()
    return tuple(
        read
        for start, end in _shell_code_ranges(relative_path, content)
        for read in _statement_reads(content, start, end)
    )


def _shell_credential_read_spans(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    return tuple(read.span for read in _shell_credential_reads(relative_path, content))


def _runtime_credential_findings(
    relative_path: Path, content: str, reads: tuple[ShellCredentialRead, ...]
) -> tuple[Finding, ...]:
    """Keep credential capabilities visible independently of literal detection.

    LOW marks ordinary credential access for review, without asserting a leak.
    Explicit impersonation is MEDIUM because it requests another identity.
    Effective permissions/scope are unknown; documentation or project flags do
    not establish least privilege. Findings never include values or commands.
    """
    offsets = tuple(match.start() for match in re.finditer("\n", content))
    findings: list[Finding] = []
    for read in reads:
        if not read.credential_related:
            continue
        impersonation = read.kind == "gcloud_impersonation"
        if impersonation:
            description = (
                "A supported gcloud command requests an access token for another service account. "
                "Token minting requires the caller's impersonation permissions; those permissions, "
                "the target account's access and successful execution have not been verified."
            )
        elif read.kind == "gcloud":
            description = (
                "A supported gcloud command requests an access token using the runtime identity. "
                "Available credentials, effective permissions and token scope have not been verified."
            )
        else:
            description = (
                "A supported shell assignment reads an environment variable with a credential-related "
                "source or destination name. Runtime contents and effective permissions have not been verified."
            )
        findings.append(
            Finding(
                rule_id="GCLOUD_SERVICE_ACCOUNT_IMPERSONATION" if impersonation else "RUNTIME_CREDENTIAL_ACCESS",
                severity=Severity.MEDIUM if impersonation else Severity.LOW,
                category="security",
                title="Service-account impersonation requested" if impersonation else "Runtime credential access",
                description=description,
                remediation=(
                    "Review the agent's shell access, credential handling, identity grants and effective scope. "
                    "Use the least privilege required; a clean embedded-secret check does not prove limited access."
                ),
                file_path=relative_path.as_posix(),
                line_number=bisect.bisect_left(offsets, read.span[0]) + 1,
            )
        )
    # Equivalent branches on one line can expose the same capability twice.
    # Preserve distinct kinds and locations without repeating identical output.
    return tuple(dict.fromkeys(findings))
