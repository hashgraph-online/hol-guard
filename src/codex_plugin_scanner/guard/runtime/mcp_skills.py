"""Declared MCP Skills metadata and origin-bound, lazy content verification.

This client inspects resources; it does not activate skills, execute scripts,
or honor permission-widening frontmatter. Host activation needs its own gate.
"""

from __future__ import annotations

import base64
import json
import re
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from urllib.parse import unquote, urlsplit

from ..adapters.hermes_file_inspection import parse_hermes_yaml_mapping

_EXTENSION = "io.modelcontextprotocol/skills"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ORIGIN = re.compile(r"[0-9a-f]{64}\Z")
_PROTOCOL_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_MIN_SKILLS_VERSION = date(2026, 7, 28)
_MAX_BYTES = 16_777_216
McpSkillsRequest = Callable[[str, dict[str, object]], dict[str, object]]


class McpSkillError(ValueError):
    """Static diagnostic codes only; no provider text in error messages."""


@dataclass(frozen=True)
class McpSkillResource:
    uri: str
    digest: str
    size: int


@dataclass(frozen=True)
class McpSkillEntry:
    origin: str
    uri: str
    frontmatter_json: str
    resources: tuple[McpSkillResource, ...] | None

    @property
    def frontmatter(self) -> dict[str, object]:
        return json.loads(self.frontmatter_json)

    @property
    def manifest_digest(self) -> str | None:
        if self.resources is None:
            return None
        payload = {
            "origin": self.origin,
            "uri": self.uri,
            "frontmatter": self.frontmatter,
            "resources": sorted((entry.uri, entry.digest, entry.size) for entry in self.resources),
        }
        return "sha256:" + sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def public_metadata(self) -> dict[str, object]:
        return {
            "origin": "mcp-served-skill",
            "connection_identity_hash": self.origin,
            "uri": self.uri,
            "name": self.frontmatter["name"],
            "description": self.frontmatter["description"],
            "manifest_digest": self.manifest_digest,
            "dynamic": self.resources is None,
            "resource_count": None if self.resources is None else len(self.resources),
            "activation_supported": False,
            "permissions_granted": False,
        }


def mcp_skills_declared(capabilities: object, *, protocol_version: str) -> bool:
    if not isinstance(protocol_version, str) or not _PROTOCOL_VERSION.fullmatch(protocol_version):
        return False
    try:
        if date.fromisoformat(protocol_version) < _MIN_SKILLS_VERSION:
            return False
    except ValueError:
        return False
    if not isinstance(capabilities, dict):
        return False
    extensions = capabilities.get("extensions")
    declaration = extensions.get(_EXTENSION) if isinstance(extensions, dict) else None
    return isinstance(capabilities.get("resources"), dict) and isinstance(declaration, dict)


def parse_mcp_skill_entry(value: object, *, origin: str) -> McpSkillEntry:
    if not _ORIGIN.fullmatch(origin) or not isinstance(value, dict):
        raise McpSkillError("invalid_skill_origin_or_entry")
    uri, frontmatter = value.get("uri"), value.get("frontmatter")
    if not isinstance(uri, str) or not _resource_uri(uri) or not uri.endswith("/SKILL.md"):
        raise McpSkillError("invalid_skill_uri")
    if not isinstance(frontmatter, dict):
        raise McpSkillError("invalid_skill_frontmatter")
    name, description = frontmatter.get("name"), frontmatter.get("description")
    path_name = unquote(uri[: -len("/SKILL.md")].rsplit("/", 1)[-1])
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 64
        or name != path_name
        or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
        or not isinstance(description, str)
        or not 1 <= len(description) <= 1024
    ):
        raise McpSkillError("invalid_skill_frontmatter")
    try:
        raw_frontmatter = json.dumps(frontmatter, sort_keys=True, allow_nan=False, separators=(",", ":"))
        encoded_size = len(raw_frontmatter.encode())
    except (TypeError, ValueError, RecursionError, UnicodeError) as error:
        raise McpSkillError("invalid_skill_frontmatter") from error
    if encoded_size > 262_144:
        raise McpSkillError("skill_metadata_limit")
    resources = value.get("resources")
    if resources == "dynamic":
        return McpSkillEntry(origin, uri, raw_frontmatter, None)
    if not isinstance(resources, list) or not 1 <= len(resources) <= 512:
        raise McpSkillError("skill_manifest_resource_limit")
    root, total, seen = uri[: -len("SKILL.md")], 0, set()
    entries: list[McpSkillResource] = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise McpSkillError("invalid_skill_resource")
        resource_uri, digest, size = resource.get("uri"), resource.get("digest"), resource.get("size")
        if (
            not isinstance(resource_uri, str)
            or not _resource_uri(resource_uri)
            or not resource_uri.startswith(root)
            or resource_uri in seen
            or resource_uri == root
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            or type(size) is not int
            or size < 0
        ):
            raise McpSkillError("invalid_skill_resource")
        total += size
        if total > _MAX_BYTES:
            raise McpSkillError("skill_manifest_size_limit")
        seen.add(resource_uri)
        entries.append(McpSkillResource(resource_uri, digest, size))
    if uri not in seen:
        raise McpSkillError("skill_primary_missing")
    return McpSkillEntry(origin, uri, raw_frontmatter, tuple(entries))


class McpSkillsClient:
    """A client for one host-assigned connection and authorization context.

    The owner supplies a bounded RPC callback for its existing session. No URI
    chooses a network destination or a different server. All reads are data.
    """

    def __init__(self, *, origin: str, capabilities: object, protocol_version: str, request: McpSkillsRequest) -> None:
        if not _ORIGIN.fullmatch(origin) or not mcp_skills_declared(capabilities, protocol_version=protocol_version):
            raise McpSkillError("skills_extension_not_declared")
        self.origin = origin
        self._protocol_version = protocol_version
        self._request = request
        self._entries: dict[str, McpSkillEntry] = {}
        self._cache: OrderedDict[tuple[str, str], bytes] = OrderedDict()
        self._cache_bytes = 0

    def list_metadata(self) -> tuple[tuple[McpSkillEntry, ...], bool, str | None]:
        entries: dict[str, McpSkillEntry] = {}
        cursor: str | None = None
        cursors: set[str] = set()
        try:
            for _page in range(8):
                result = self._call("skills/list", {} if cursor is None else {"cursor": cursor})
                skills = result.get("skills")
                if not isinstance(skills, list):
                    raise McpSkillError("invalid_skills_page")
                for value in skills:
                    entry = parse_mcp_skill_entry(value, origin=self.origin)
                    if entry.uri in entries:
                        raise McpSkillError("duplicate_skill_uri")
                    if len(entries) >= 256:
                        raise McpSkillError("skill_catalog_limit")
                    entries[entry.uri] = entry
                    self._remember_entry(entry)
                next_cursor = result.get("nextCursor")
                if next_cursor is None:
                    return tuple(entries.values()), True, None
                if not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 4096:
                    raise McpSkillError("invalid_skills_cursor")
                if next_cursor in cursors:
                    raise McpSkillError("repeated_skills_cursor")
                cursors.add(next_cursor)
                cursor = next_cursor
            raise McpSkillError("skill_page_limit")
        except McpSkillError as error:
            return tuple(entries.values()), False, str(error)

    def get_metadata(self, uri: str) -> McpSkillEntry:
        if not _resource_uri(uri) or not uri.endswith("/SKILL.md"):
            raise McpSkillError("invalid_skill_uri")
        result = self._call("skills/get", {"uri": uri})
        entry = parse_mcp_skill_entry(result.get("skill"), origin=self.origin)
        if entry.uri != uri:
            raise McpSkillError("skill_identity_changed")
        self._remember_entry(entry)
        return entry

    def inspect_content(self, entry: McpSkillEntry, uri: str) -> bytes:
        """Lazy inspection only; even a nested SKILL.md stays ordinary data."""
        if entry.origin != self.origin:
            raise McpSkillError("cross_origin_skill_read")
        if self._entries.get(entry.uri) != entry:
            raise McpSkillError("skill_entry_changed")
        if entry.resources is None:
            raise McpSkillError("dynamic_skill_cannot_be_content_bound")
        resource = next((resource for resource in entry.resources if resource.uri == uri), None)
        if resource is None:
            self.invalidate(entry.uri)
            raise McpSkillError("unlisted_skill_resource")
        key = (uri, resource.digest)
        try:
            content = self._cache.get(key)
            if content is None:
                result = self._call("resources/read", {"uri": uri})
                content = _read_resource_bytes(result, uri)
            if len(content) != resource.size or "sha256:" + sha256(content).hexdigest() != resource.digest:
                raise McpSkillError("skill_content_changed")
            if uri == entry.uri and _read_frontmatter(content) != entry.frontmatter:
                raise McpSkillError("skill_frontmatter_changed")
        except McpSkillError:
            self.invalidate(entry.uri)
            raise
        if key not in self._cache:
            while self._cache and self._cache_bytes + len(content) > 32 * 1024 * 1024:
                _, evicted = self._cache.popitem(last=False)
                self._cache_bytes -= len(evicted)
            self._cache[key] = content
            self._cache_bytes += len(content)
        self._cache.move_to_end(key)
        return content

    def invalidate(self, uri: str) -> None:
        self._entries.pop(uri, None)
        root = uri[: -len("SKILL.md")]
        for key in tuple(self._cache):
            if key[0].startswith(root):
                self._cache_bytes -= len(self._cache.pop(key))

    def _remember_entry(self, entry: McpSkillEntry) -> None:
        old = self._entries.get(entry.uri)
        if old is not None and old.manifest_digest != entry.manifest_digest:
            self.invalidate(entry.uri)
        if len(self._entries) >= 256 and entry.uri not in self._entries:
            self.invalidate(next(iter(self._entries)))
        self._entries[entry.uri] = entry

    def _call(self, method: str, params: dict[str, object]) -> dict[str, object]:
        params = {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": self._protocol_version,
                "io.modelcontextprotocol/clientInfo": {"name": "hol-guard", "version": "3.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        }
        result = self._request(method, params)
        if (
            not isinstance(result, dict)
            or result.get("resultType") != "complete"
            or type(result.get("ttlMs")) is not int
            or result.get("cacheScope") not in ("private", "public")
        ):
            raise McpSkillError("invalid_skills_result")
        return result


def _resource_uri(uri: str) -> bool:
    if len(uri) > 8192 or any(ord(char) < 33 for char in uri) or "\\" in uri:
        return False
    try:
        parsed = urlsplit(uri)
        if not parsed.scheme or parsed.query or parsed.fragment:
            return False
        for segment in parsed.path.split("/"):
            for _ in range(8):
                decoded = unquote(segment)
                if decoded == segment:
                    break
                segment = decoded
            else:
                return False
            if segment in {".", ".."} or "/" in segment or "\\" in segment or any(ord(c) < 33 for c in segment):
                return False
        return True
    except ValueError:
        return False


def _read_resource_bytes(result: dict[str, object], uri: str) -> bytes:
    contents = result.get("contents")
    if not isinstance(contents, list) or len(contents) != 1 or not isinstance(contents[0], dict):
        raise McpSkillError("invalid_skill_content")
    item = contents[0]
    if item.get("uri") != uri or ("text" in item) == ("blob" in item):
        raise McpSkillError("invalid_skill_content")
    try:
        text, blob = item.get("text"), item.get("blob")
        if isinstance(text, str) and len(text) <= _MAX_BYTES:
            content = text.encode("utf-8")
        elif isinstance(blob, str) and len(blob) <= 4 * ((_MAX_BYTES + 2) // 3):
            content = base64.b64decode(blob, validate=True)
        else:
            raise McpSkillError("skill_content_limit")
        if len(content) > _MAX_BYTES:
            raise McpSkillError("skill_content_limit")
        return content
    except (ValueError, UnicodeError) as error:
        raise McpSkillError("invalid_skill_content") from error


def _read_frontmatter(content: bytes) -> dict[str, object]:
    lines = content[:262_144].splitlines(keepends=True)
    if not lines or lines[0].strip() != b"---":
        raise McpSkillError("invalid_skill_frontmatter")
    end = next((index for index, line in enumerate(lines[1:], 1) if line.strip() == b"---"), None)
    if end is None:
        raise McpSkillError("skill_frontmatter_limit")
    try:
        parsed = parse_hermes_yaml_mapping(b"".join(lines[1:end]).decode("utf-8"))
    except UnicodeError as error:
        raise McpSkillError("invalid_skill_frontmatter") from error
    if parsed is None:
        raise McpSkillError("invalid_skill_frontmatter")
    return parsed
