"""HOL Registry trust scores for new or changed skills, MCP servers and plugins.

Guard asks the fixed Guard Cloud origin for an artifact's public registry trust
score and reviews the artifact through the ``low_trust_artifact`` risk action
when the score is below ``LOW_TRUST_THRESHOLD``. Only the artifact's kind and
public name go on the wire: no credential, cookie, path or device identifier.

A missing score never triggers a review. An unknown artifact, an unreachable
origin, a malformed answer, an ambiguous match or a kind the origin cannot score
yet all resolve to ``None``, so the lookup can only add a review, never remove
one. Lookups run only for artifacts the policy engine is about to decide fresh
(first seen or changed), and answers are cached on disk to keep repeat scans off
the network.

Rollback: ``HOL_GUARD_REGISTRY_TRUST=off`` (or ``low_trust_artifact = "allow"``)
skips the lookup entirely.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from ..no_redirect import RejectRedirects
from ..version import __version__
from .mdm.network_transport import managed_opener

REGISTRY_TRUST_ENV = "HOL_GUARD_REGISTRY_TRUST"
LOW_TRUST_THRESHOLD = 80
LOW_TRUST_RISK_KEY = "low_trust_artifact"

TRUST_ORIGIN = "https://hol.org"
PLUGIN_SEARCH_PATH = "/api/guard/plugins/search"
TRUST_USER_AGENT = f"hol-guard/{__version__}"
TRUST_DEADLINE_SECONDS = 2.0
MAX_TRUST_RESPONSE_BYTES = 65_536
_SEARCH_LIMIT = 20

CACHE_FILE_NAME = "registry-trust-cache.json"
_CACHE_SCHEMA = "guard-registry-trust-cache.v1"
_SCORED_TTL_SECONDS = 24 * 60 * 60
_UNSCORED_TTL_SECONDS = 6 * 60 * 60
# After a transport failure, skip the network for a few minutes so an offline
# device does not wait on every evaluation. No score means no review.
_UNREACHABLE_KEY = "origin:unreachable"
_UNREACHABLE_TTL_SECONDS = 5 * 60
_MAX_CACHE_ENTRIES = 512

# Guard artifact types the registry scores, keyed to the registry kind.
_REGISTRY_KINDS: dict[str, str] = {
    "skill": "skill",
    "skill_file": "skill",
    "mcp_server": "mcp",
    "plugin": "plugin",
    "extension": "plugin",
}
_DISABLED_VALUES = frozenset({"0", "off", "false", "disabled"})


class _ReadableResponse(Protocol):
    @property
    def status(self) -> int: ...

    def read(self, amount: int, /) -> bytes: ...

    def close(self) -> None: ...


class TrustOpener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> _ReadableResponse: ...


def registry_trust_enabled(environ: Mapping[str, str] | None = None) -> bool:
    source = environ if environ is not None else os.environ
    return source.get(REGISTRY_TRUST_ENV, "").strip().lower() not in _DISABLED_VALUES


def registry_kind(artifact_type: str | None) -> str | None:
    return _REGISTRY_KINDS.get(artifact_type or "")


def registry_trust_score(
    guard_home: Path | None,
    *,
    artifact_type: str | None,
    name: str | None,
    opener: TrustOpener | None = None,
    now: float | None = None,
) -> int | None:
    """Return the artifact's registry trust score (0-100), or ``None`` when unknown."""

    kind = registry_kind(artifact_type)
    lookup_name = (name or "").strip()
    if kind is None or not lookup_name or len(lookup_name) > 256 or not registry_trust_enabled():
        return None
    # Guard Cloud exposes plugin trust today; skill and MCP scores need a
    # registry route the origin does not serve yet.
    if kind != "plugin":
        return None
    clock = time.time() if now is None else now
    key = f"{kind}:{lookup_name.lower()}"
    cache = _load_cache(guard_home)
    cached = cache.get(key)
    if cached is not None and _fresh(cached, clock):
        score = cached.get("score")
        return score if isinstance(score, int) else None
    if _recently_unreachable(cache.get(_UNREACHABLE_KEY), clock):
        return None
    score = _fetch_plugin_score(lookup_name, opener=opener)
    if score is _UNREACHABLE:
        # A transport failure is not an answer: keep any stale entry and retry
        # once the marker expires.
        cache[_UNREACHABLE_KEY] = {"checked_at": clock}
        _store_cache(guard_home, cache)
        return None
    cache.pop(_UNREACHABLE_KEY, None)
    cache[key] = {"score": score, "checked_at": clock}
    _store_cache(guard_home, cache)
    return cast(int | None, score)


def is_low_trust(score: int | None) -> bool:
    return score is not None and score < LOW_TRUST_THRESHOLD


_UNREACHABLE = object()


def _fetch_plugin_score(name: str, *, opener: TrustOpener | None) -> int | None | object:
    query = urllib.parse.urlencode({"q": name, "limit": _SEARCH_LIMIT})
    request = urllib.request.Request(
        f"{TRUST_ORIGIN}{PLUGIN_SEARCH_PATH}?{query}",
        method="GET",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
            "User-Agent": TRUST_USER_AGENT,
        },
    )
    handler = opener if opener is not None else cast(TrustOpener, managed_opener(redirect_handler=RejectRedirects()))
    try:
        response = handler.open(request, timeout=TRUST_DEADLINE_SECONDS)
    except (urllib.error.URLError, OSError, ValueError):
        return _UNREACHABLE
    try:
        if response.status != 200:
            return _UNREACHABLE
        body = _read_bounded(response)
    except (OSError, ValueError):
        return _UNREACHABLE
    finally:
        response.close()
    if body is None:
        return _UNREACHABLE
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return _UNREACHABLE
    return _match_plugin_score(payload, name)


def _read_bounded(response: _ReadableResponse) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    while size < MAX_TRUST_RESPONSE_BYTES:
        chunk = response.read(min(8192, MAX_TRUST_RESPONSE_BYTES - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
    return None if response.read(1) else b"".join(chunks)


def _match_plugin_score(payload: object, name: str) -> int | None:
    """Score of the one catalog plugin whose slug or display name is ``name``.

    Search is fuzzy, so only an exact, unambiguous name match counts; anything
    else is an unknown plugin, which never triggers review.
    """

    plugins = payload.get("plugins") if isinstance(payload, dict) else None
    if not isinstance(plugins, list):
        return None
    wanted = name.strip().lower()
    scores: set[int] = set()
    matched = 0
    for plugin in plugins:
        if not isinstance(plugin, dict) or not _plugin_names(plugin) & {wanted}:
            continue
        matched += 1
        score = plugin.get("trustScore")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 100:
            scores.add(round(score))
    if matched != 1 or len(scores) != 1:
        return None
    return scores.pop()


def _plugin_names(plugin: Mapping[str, object]) -> set[str]:
    names: set[str] = set()
    slug = plugin.get("slug")
    if isinstance(slug, str) and slug.strip():
        names.add(slug.strip().lower())
        names.add(slug.strip().lower().rsplit("/", 1)[-1])
    display = plugin.get("displayName")
    if isinstance(display, str) and display.strip():
        names.add(display.strip().lower())
    return names


def _fresh(entry: Mapping[str, object], now: float) -> bool:
    checked_at = entry.get("checked_at")
    if not isinstance(checked_at, (int, float)) or checked_at > now:
        return False
    ttl = _SCORED_TTL_SECONDS if isinstance(entry.get("score"), int) else _UNSCORED_TTL_SECONDS
    return now - checked_at < ttl


def _recently_unreachable(entry: Mapping[str, object] | None, now: float) -> bool:
    checked_at = entry.get("checked_at") if entry is not None else None
    if not isinstance(checked_at, (int, float)) or checked_at > now:
        return False
    return now - checked_at < _UNREACHABLE_TTL_SECONDS


def _cache_path(guard_home: Path | None) -> Path | None:
    return None if guard_home is None else guard_home / CACHE_FILE_NAME


def _load_cache(guard_home: Path | None) -> dict[str, dict[str, object]]:
    path = _cache_path(guard_home)
    if path is None:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    if not isinstance(raw, dict) or raw.get("schema") != _CACHE_SCHEMA or not isinstance(raw.get("entries"), dict):
        return {}
    return {
        key: dict(value) for key, value in raw["entries"].items() if isinstance(key, str) and isinstance(value, dict)
    }


def _store_cache(guard_home: Path | None, cache: dict[str, dict[str, object]]) -> None:
    path = _cache_path(guard_home)
    if path is None:
        return
    newest = sorted(cache.items(), key=lambda item: _checked_at(item[1]), reverse=True)[:_MAX_CACHE_ENTRIES]
    document = {"schema": _CACHE_SCHEMA, "entries": dict(newest)}
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)


def _checked_at(entry: Mapping[str, object]) -> float:
    value = entry.get("checked_at")
    return float(value) if isinstance(value, (int, float)) else 0.0


__all__ = [
    "LOW_TRUST_RISK_KEY",
    "LOW_TRUST_THRESHOLD",
    "REGISTRY_TRUST_ENV",
    "is_low_trust",
    "registry_kind",
    "registry_trust_enabled",
    "registry_trust_score",
]
