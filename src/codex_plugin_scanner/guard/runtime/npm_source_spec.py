"""Canonical, credential-free npm source specification identities."""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Literal

SourceKind = Literal["git", "url", "local", "invalid"]
RevisionKind = Literal["immutable_commit", "mutable_ref", "missing", "not_applicable"]

_HOSTED = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}
_GIT_SCHEMES = frozenset({"git", "git+https", "git+ssh", "ssh"})
_URL_SCHEMES = frozenset({"http", "https", *_GIT_SCHEMES})
_DEFAULT_PORTS = {"http": 80, "https": 443, "git+https": 443, "ssh": 22, "git+ssh": 22, "git": 9418}
_SCP_RE = re.compile(r"^(?P<user>[^@/:]+)@(?P<host>[^/:]+):(?P<path>[^#]+)(?:#(?P<fragment>.*))?$")
_COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:00|2f|5c)", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


@dataclass(frozen=True, slots=True)
class NpmSourceSpec:
    source_kind: SourceKind
    canonical_repository: str | None
    revision: str | None
    revision_kind: RevisionKind
    identity: str
    redacted: str
    valid: bool = True
    reason: str | None = None

    @property
    def is_git(self) -> bool:
        return self.source_kind == "git" and self.valid


def parse_npm_source_spec(value: str | None) -> NpmSourceSpec | None:
    """Return one canonical source identity, or ``None`` for registry syntax."""

    if value is None or not (source := value.strip()):
        return None
    lowered = source.lower()
    alias_depth = 0
    while lowered.startswith("npm:"):
        alias_depth += 1
        if alias_depth > 32:
            return _invalid(source, "npm_source_alias_depth_exceeded")
        source = source[4:].strip()
        if not source:
            return _invalid(value, "npm_source_alias_invalid")
        lowered = source.lower()
    if lowered.startswith("file:"):
        parsed_file = urllib.parse.urlsplit(source)
        if parsed_file.netloc or parsed_file.query or parsed_file.fragment:
            return _invalid(source, "npm_source_local_url_invalid")
        return _non_git_source("local", source, redacted="file:<local-source>")
    for prefix, host in _HOSTED.items():
        marker = f"{prefix}:"
        if lowered.startswith(marker):
            return _git_from_host_path(host, source[len(marker) :], None)
    scp = _SCP_RE.fullmatch(source)
    if scp is not None:
        if scp.group("user").lower() != "git":
            return _invalid(source, "npm_source_ambiguous_userinfo")
        return _git_from_host_path(scp.group("host"), scp.group("path"), scp.group("fragment"))
    if "://" in source or _SCHEME_RE.match(source) is not None:
        return _url_source(source)
    if source.startswith(("@", "./", "../", "/", "~", "\\")) or ":" in source:
        return None
    parts = source.split("#", 1)
    path = parts[0]
    fragment = parts[1] if len(parts) == 2 else None
    if path.count("/") == 1 and all(part.strip() for part in path.split("/")):
        return _git_from_host_path("github.com", path, fragment)
    return None


def _url_source(source: str) -> NpmSourceSpec:
    try:
        parsed = urllib.parse.urlsplit(source)
        port = parsed.port
    except ValueError:
        return _invalid(source, "npm_source_malformed_port")
    scheme = parsed.scheme.lower()
    if scheme not in _URL_SCHEMES:
        return _invalid(source, "npm_source_protocol_unsupported")
    if parsed.hostname is None:
        return _invalid(source, "npm_source_host_missing")
    if parsed.password is not None or parsed.username not in {None, "git"}:
        return _invalid(source, "npm_source_ambiguous_userinfo")
    if parsed.username == "git" and scheme not in {"ssh", "git+ssh"}:
        return _invalid(source, "npm_source_ambiguous_userinfo")
    host = _canonical_host(parsed.hostname)
    if host is None:
        return _invalid(source, "npm_source_host_invalid")
    rendered_host = _host_with_port(host, scheme, port)
    git_hosted = host in set(_HOSTED.values())
    if scheme in _GIT_SCHEMES:
        return _git_from_host_path(rendered_host, parsed.path, parsed.fragment)
    if git_hosted:
        git_source = _git_from_host_path(rendered_host, parsed.path, parsed.fragment)
        if git_source.valid or git_source.reason != "npm_source_path_invalid":
            return git_source
    normalized_path = _canonical_path(parsed.path, minimum_parts=1)
    if normalized_path is None:
        return _invalid(source, "npm_source_path_invalid")
    canonical = f"{scheme}://{rendered_host}/{normalized_path}"
    digest = _digest(canonical)
    return NpmSourceSpec(
        source_kind="url",
        canonical_repository=None,
        revision=None,
        revision_kind="not_applicable",
        identity=f"url:{digest}",
        redacted=canonical,
    )


def _git_from_host_path(host_value: str, path_value: str, fragment: str | None) -> NpmSourceSpec:
    if fragment is None and "#" in path_value:
        path_value, fragment = path_value.split("#", 1)
    host, separator, port_text = host_value.partition(":")
    canonical_host = _canonical_host(host)
    if canonical_host is None:
        return _invalid(f"{host_value}/{path_value}", "npm_source_host_invalid")
    if separator:
        try:
            port = int(port_text)
        except ValueError:
            return _invalid(f"{host_value}/{path_value}", "npm_source_malformed_port")
        if not 1 <= port <= 65535:
            return _invalid(f"{host_value}/{path_value}", "npm_source_malformed_port")
        rendered_host = f"{canonical_host}:{port}"
    else:
        rendered_host = canonical_host
    if "?" in path_value or "\\" in path_value or _ENCODED_SEPARATOR_RE.search(path_value):
        return _invalid(f"{host_value}/{path_value}", "npm_source_path_invalid")
    path, archive_revision = _repository_path(canonical_host, path_value)
    if path is None:
        return _invalid(f"{host_value}/{path_value}", "npm_source_path_invalid")
    revision = fragment.strip() if fragment is not None and fragment.strip() else archive_revision
    if revision is not None:
        revision = _canonical_revision(revision)
        if revision is None:
            return _invalid(f"{host_value}/{path_value}", "npm_source_revision_invalid")
    revision_kind: RevisionKind
    if revision is None:
        revision_kind = "missing"
        revision_identity = "missing"
        revision_display = ""
    elif _COMMIT_RE.fullmatch(revision):
        revision = revision.lower()
        revision_kind = "immutable_commit"
        revision_identity = f"commit:{revision}"
        revision_display = "#<immutable-commit>"
    else:
        revision_kind = "mutable_ref"
        revision_identity = f"mutable:{_digest(revision)}"
        revision_display = "#<mutable-ref>"
    repository = f"git:{rendered_host}/{path}"
    return NpmSourceSpec(
        source_kind="git",
        canonical_repository=repository,
        revision=revision,
        revision_kind=revision_kind,
        identity=f"{repository}#{revision_identity}",
        redacted=f"{repository}{revision_display}",
    )


def _repository_path(host: str, raw_path: str) -> tuple[str | None, str | None]:
    minimum_parts = 2 if host in _HOSTED.values() else 1
    normalized = _canonical_path(raw_path, minimum_parts=minimum_parts)
    if normalized is None:
        return None, None
    parts = normalized.split("/")
    revision: str | None = None
    if host == "github.com" and len(parts) > 2:
        marker = parts[2].lower()
        if marker in {"archive", "tarball", "zipball"}:
            revision = "/".join(parts[3:]) or None
            if revision is not None:
                revision = _strip_archive_suffix(revision)
            parts = parts[:2]
        else:
            return None, None
    elif host == "gitlab.com" and "-" in parts:
        marker_index = parts.index("-")
        if marker_index + 1 < len(parts) and parts[marker_index + 1].lower() == "archive":
            revision_parts = parts[marker_index + 2 :]
            if revision_parts and _looks_like_archive_filename(revision_parts[-1]):
                revision_parts = revision_parts[:-1]
            revision = "/".join(revision_parts) or None
            parts = parts[:marker_index]
    elif host == "bitbucket.org" and len(parts) > 2:
        if parts[2].lower() != "get":
            return None, None
        revision = _strip_archive_suffix("/".join(parts[3:])) or None
        parts = parts[:2]
    if len(parts) < minimum_parts:
        return None, None
    if host in _HOSTED.values():
        parts = [part.lower() for part in parts]
    if parts[-1].lower().endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if not parts[-1]:
        return None, None
    return "/".join(parts), revision


def _strip_archive_suffix(value: str) -> str:
    lowered = value.lower()
    for suffix in (".tar.gz", ".tgz", ".tar", ".zip"):
        if lowered.endswith(suffix):
            return value[: -len(suffix)]
    return value


def _looks_like_archive_filename(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith((".tar.gz", ".tgz", ".tar", ".zip"))


def _canonical_path(raw_path: str, *, minimum_parts: int) -> str | None:
    if _ENCODED_SEPARATOR_RE.search(raw_path) or "\\" in raw_path:
        return None
    raw_parts = [part for part in raw_path.strip("/").split("/") if part]
    if len(raw_parts) < minimum_parts:
        return None
    normalized: list[str] = []
    for part in raw_parts:
        try:
            decoded = urllib.parse.unquote(part, errors="strict")
        except UnicodeError:
            return None
        if decoded in {".", ".."} or not decoded or "/" in decoded or "\\" in decoded or "\x00" in decoded:
            return None
        normalized.append(urllib.parse.quote(decoded, safe="!$&'()+,;=@._~-"))
    return "/".join(normalized)


def _canonical_revision(raw_revision: str) -> str | None:
    if _ENCODED_SEPARATOR_RE.search(raw_revision) or "\\" in raw_revision or "?" in raw_revision:
        return None
    try:
        revision = urllib.parse.unquote(raw_revision, errors="strict").strip()
    except UnicodeError:
        return None
    if not revision or "\x00" in revision or any(character.isspace() for character in revision):
        return None
    return revision


def _canonical_host(host: str) -> str | None:
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower() or None
    except UnicodeError:
        return None


def _host_with_port(host: str, scheme: str, port: int | None) -> str:
    return host if port is None or _DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"


def _non_git_source(kind: Literal["local"], source: str, *, redacted: str) -> NpmSourceSpec:
    return NpmSourceSpec(
        source_kind=kind,
        canonical_repository=None,
        revision=None,
        revision_kind="not_applicable",
        identity=f"{kind}:{_digest(source)}",
        redacted=redacted,
    )


def _invalid(source: str, reason: str) -> NpmSourceSpec:
    return NpmSourceSpec(
        source_kind="invalid",
        canonical_repository=None,
        revision=None,
        revision_kind="not_applicable",
        identity=f"invalid:{reason}:{_digest(source)}",
        redacted="<invalid-source>",
        valid=False,
        reason=reason,
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["NpmSourceSpec", "parse_npm_source_spec"]
