"""Model usage per AI tool, read from each tool's own usage record on this computer.

Codex writes a `token_usage_record` for every model request into the session
rollout, and Claude Code writes `message.usage` on every assistant message in
the session transcript. The meter adds those numbers up per local day. It never
estimates: a tool whose usage record Guard does not read is listed as unread.

Both records are append-only and can reach hundreds of megabytes per session,
so the meter remembers how far it read each file (in `context-usage-meter.json`
under the Guard home) and later reads only the bytes added since. Only lines
carrying a usage, summary or model record are parsed; chat text is never kept.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path

SCHEMA = "guard-context-usage-meter.v1"
CACHE_NAME = "context-usage-meter.json"
CACHE_VERSION = 1
WINDOW_DAYS = 7
RECENT_SESSIONS = 10
FIELDS = (
    "uncached_input_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "output_tokens",
    "requests",
    "compactions",
)
# Tools Guard protects whose usage it does not read; the meter names them instead of guessing.
UNREAD = ("copilot", "cursor", "gemini", "opencode", "pi")
_CHUNK = 1 << 24
# Claude Code re-logs a message (same id and usage) up to a few hundred lines later after a resume.
_RECENT_IDS = 1024
# A file not written for an hour is finished; its dedupe ids are dropped from the cache.
_IDS_KEPT_FOR = 3600.0


@dataclass(frozen=True)
class _Source:
    harness: str
    root: Path
    pattern: str
    needles: tuple[bytes, ...]


def _sources(home: Path, env: Mapping[str, str]) -> tuple[_Source, ...]:
    codex = Path(env["CODEX_HOME"]).expanduser() if env.get("CODEX_HOME") else home / ".codex"
    claude = Path(env["CLAUDE_CONFIG_DIR"]).expanduser() if env.get("CLAUDE_CONFIG_DIR") else home / ".claude"
    return (
        _Source(
            "codex",
            codex / "sessions",
            "rollout-*.jsonl",
            (b'"type":"token_usage_record"', b'"type":"compacted"', b'"type":"turn_context"'),
        ),
        _Source(
            "claude-code", claude / "projects", "*.jsonl", (b'"type":"assistant"', b'"subtype":"compact_boundary"')
        ),
    )


def _matching_lines(path: Path, start: int, needles: tuple[bytes, ...]) -> Iterator[bytes | int]:
    """Yield each complete line at or after `start` that contains a needle, then the end offset.

    A final line without a newline is still being written, so reading stops before it.
    """
    with path.open("rb") as handle:
        handle.seek(start)
        offset = start
        tail = b""
        while block := handle.read(_CHUNK):
            data = tail + block
            cut = data.rfind(b"\n")
            if cut < 0:
                tail = data
                continue
            body, tail = data[:cut], data[cut + 1 :]
            starts: set[int] = set()
            for needle in needles:
                found = body.find(needle)
                while found >= 0:
                    line_start = body.rfind(b"\n", 0, found) + 1
                    end = body.find(b"\n", found)
                    end = len(body) if end < 0 else end
                    starts.add(line_start)
                    found = body.find(needle, end)
            for line_start in sorted(starts):
                end = body.find(b"\n", line_start)
                yield body[line_start : len(body) if end < 0 else end]
            # `data` starts at `offset`, so everything through `cut` is now read; the tail is not.
            offset += cut + 1
            yield offset


def _local_day(stamp: object) -> str | None:
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        moment = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return moment.date().isoformat()
    return moment.astimezone().date().isoformat()


def _number(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _count(entry: dict, day: str | None, **values: int) -> None:
    if day is None:
        return
    bucket = entry["days"].setdefault(day, dict.fromkeys(FIELDS, 0))
    for key, value in values.items():
        bucket[key] += value if isinstance(value, int) and value > 0 else 0


def _codex_line(entry: dict, record: dict) -> None:
    kind = record.get("type")
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    day = _local_day(record.get("timestamp"))
    if kind == "token_usage_record":
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        total, cached, written = (
            _number(usage.get(key)) for key in ("input_tokens", "cached_input_tokens", "cache_write_input_tokens")
        )
        # OpenAI counts cached input inside `input_tokens`.
        _count(
            entry,
            day,
            uncached_input_tokens=total - cached - written,
            cached_input_tokens=cached,
            cache_write_tokens=written,
            output_tokens=_number(usage.get("output_tokens")),
            requests=1,
        )
    elif kind == "compacted":
        _count(entry, day, compactions=1)
    elif kind == "turn_context":
        _describe(entry, payload.get("model"), payload.get("cwd"))


def _claude_line(entry: dict, record: dict) -> None:
    day = _local_day(record.get("timestamp"))
    if record.get("type") == "system" and record.get("subtype") == "compact_boundary":
        _count(entry, day, compactions=1)
        return
    message = record.get("message") if isinstance(record.get("message"), dict) else {}
    usage = message.get("usage")
    if record.get("type") != "assistant" or not isinstance(usage, dict):
        return
    # One response is written as one line per content block, each repeating the same usage.
    message_id = message.get("id")
    if isinstance(message_id, str):
        seen, order = entry["_seen"]
        key = message_id[-16:]
        if key in seen:
            return
        if len(order) == order.maxlen:
            seen.discard(order[0])
        order.append(key)
        seen.add(key)
    model = message.get("model")
    _describe(entry, None if model == "<synthetic>" else model, record.get("cwd"))
    # Anthropic reports `input_tokens` without the cached part; cache reads and writes are separate.
    _count(
        entry,
        day,
        uncached_input_tokens=_number(usage.get("input_tokens")),
        cached_input_tokens=_number(usage.get("cache_read_input_tokens")),
        cache_write_tokens=_number(usage.get("cache_creation_input_tokens")),
        output_tokens=_number(usage.get("output_tokens")),
        requests=1,
    )


def _describe(entry: dict, model: object, cwd: object) -> None:
    if isinstance(model, str) and model:
        entry["model"] = model[:80]
    if isinstance(cwd, str) and cwd:
        entry["folder"] = Path(cwd).name[:120]


def _session_key(source: _Source, path: Path) -> str:
    parts = path.relative_to(source.root).parts
    if source.harness == "claude-code" and len(parts) > 2:
        # Subagent transcripts live in a folder named after their parent session.
        return f"{parts[0]}/{parts[1]}"
    return "/".join(parts)[: -len(".jsonl")] if parts[-1].endswith(".jsonl") else "/".join(parts)


def _fresh(stat: os.stat_result, session: str) -> dict:
    return {
        "ino": stat.st_ino,
        "size": 0,
        "offset": 0,
        "mtime": 0.0,
        "session": session,
        "model": None,
        "folder": None,
        "ids": [],
        "days": {},
    }


def _read_file(source: _Source, path: Path, entry: dict | None) -> dict:
    stat = path.stat()
    if entry is None or entry.get("ino") != stat.st_ino or stat.st_size < entry.get("offset", 0):
        entry = _fresh(stat, _session_key(source, path))
    entry["size"], entry["mtime"] = stat.st_size, stat.st_mtime
    if stat.st_size == entry["offset"]:
        return entry
    handle_line = _codex_line if source.harness == "codex" else _claude_line
    order = collections.deque((str(key) for key in entry["ids"]), maxlen=_RECENT_IDS)
    entry["_seen"] = (set(order), order)
    try:
        for item in _matching_lines(path, entry["offset"], source.needles):
            if isinstance(item, int):
                entry["offset"] = item
                continue
            try:
                record = json.loads(item)
            except ValueError:
                continue
            if isinstance(record, dict):
                handle_line(entry, record)
    finally:
        entry["ids"] = list(entry.pop("_seen")[1])
    return entry


def _load_cache(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION or not isinstance(data.get("files"), dict):
        return {}
    files = {}
    for key, entry in data["files"].items():
        if isinstance(entry, dict) and isinstance(entry.get("days"), dict) and isinstance(entry.get("offset"), int):
            entry.setdefault("ids", [])
            files[key] = entry
    return files


def _save_cache(path: Path, files: dict[str, dict], now: float) -> None:
    for entry in files.values():
        if now - entry.get("mtime", 0) > _IDS_KEPT_FOR:
            entry["ids"] = []
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".context-usage-meter.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"version": CACHE_VERSION, "files": files}, handle, separators=(",", ":"))
        os.replace(temporary, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(temporary)


def scan(home: Path, guard_home: Path, env: Mapping[str, str], *, now: float | None = None) -> dict[str, dict]:
    """Bring the per-file counts up to date for sessions active in the last WINDOW_DAYS days."""
    now = time.time() if now is None else now
    cutoff = now - WINDOW_DAYS * 86400
    cache_path = guard_home / CACHE_NAME
    previous = _load_cache(cache_path)
    files: dict[str, dict] = {}
    for source in _sources(home, env):
        if not source.root.is_dir():
            continue
        for path in source.root.rglob(source.pattern):
            key = f"{source.harness}:{path}"
            try:
                if path.stat().st_mtime < cutoff:
                    continue
                files[key] = _read_file(source, path, previous.get(key))
            except (OSError, ValueError):
                if key in previous:
                    files[key] = previous[key]
    _save_cache(cache_path, files, now)
    return files


def _tools(files: Mapping[str, dict], days: int, today: date, recent: int) -> list[dict]:
    first = (today - timedelta(days=days - 1)).isoformat()
    sessions: dict[tuple[str, str], dict] = {}
    for key, entry in files.items():
        harness = key.split(":", 1)[0]
        counts = collections.Counter()
        for day, bucket in entry["days"].items():
            if day >= first:
                counts.update({field: int(bucket.get(field, 0)) for field in FIELDS})
        if not counts["requests"] and not counts["compactions"]:
            continue
        session = sessions.setdefault(
            (harness, entry["session"]),
            {"model": None, "folder": None, "last_active": 0.0, "totals": collections.Counter()},
        )
        session["totals"].update(counts)
        if entry["mtime"] >= session["last_active"]:
            session["last_active"] = entry["mtime"]
            session["model"] = entry.get("model") or session["model"]
            session["folder"] = entry.get("folder") or session["folder"]
    tools = []
    for source in ("codex", "claude-code"):
        mine = sorted(
            (value for (harness, _), value in sessions.items() if harness == source),
            key=lambda value: value["last_active"],
            reverse=True,
        )
        totals = collections.Counter()
        for value in mine:
            totals.update(value["totals"])
        tools.append(
            {
                "harness": source,
                "sessions": len(mine),
                "totals": {field: totals[field] for field in FIELDS},
                "recent": [
                    {
                        "last_active": datetime.fromtimestamp(value["last_active"])
                        .astimezone()
                        .isoformat(timespec="seconds"),
                        "model": value["model"],
                        "folder": value["folder"],
                        "totals": {field: value["totals"][field] for field in FIELDS},
                    }
                    for value in mine[:recent]
                ],
            }
        )
    return tools


def summarize(files: Mapping[str, dict], *, today: date | None = None) -> dict:
    """Totals per tool for today and the last WINDOW_DAYS local days, with the week's latest sessions."""
    today = today or date.today()
    return {
        "schema": SCHEMA,
        "state": "ready",
        "window_days": WINDOW_DAYS,
        "today": _tools(files, 1, today, 0),
        "week": _tools(files, WINDOW_DAYS, today, RECENT_SESSIONS),
        "unread": list(UNREAD),
    }


class UsageMeter:
    """Counts in a background thread so a first read of a large history never holds a request open."""

    def __init__(self, *, max_age: float = 30.0) -> None:
        self._lock = threading.Lock()
        self._files: dict[str, dict] | None = None
        self._read_at = 0.0
        self._worker: threading.Thread | None = None
        self._failed = False
        self._max_age = max_age

    def read(self, home: Path, guard_home: Path, env: Mapping[str, str]) -> dict:
        with self._lock:
            stale = self._files is None or time.monotonic() - self._read_at > self._max_age
            if stale and (self._worker is None or not self._worker.is_alive()):
                self._worker = threading.Thread(
                    target=self._count, args=(home, guard_home, dict(env)), name="guard-usage-meter", daemon=True
                )
                self._worker.start()
            files, failed = self._files, self._failed
        if files is None:
            return {
                "schema": SCHEMA,
                "state": "unavailable" if failed else "counting",
                "window_days": WINDOW_DAYS,
                "today": [],
                "week": [],
                "unread": list(UNREAD),
            }
        return summarize(files)

    def _count(self, home: Path, guard_home: Path, env: Mapping[str, str]) -> None:
        try:
            files = scan(home, guard_home, env)
        except (OSError, ValueError):
            with self._lock:
                self._failed = self._files is None
            return
        with self._lock:
            self._files, self._read_at, self._failed = files, time.monotonic(), False


METER = UsageMeter()
