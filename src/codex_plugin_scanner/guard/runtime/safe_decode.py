"""Safe multi-layer decoder for Guard encoded payload analysis.

Decodes content through layers of encoding (base64, hex, URL, etc.) without
executing any decoded payloads. Enforces hard limits on input size, decoded
size, recursion depth, and decode time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import time
import zlib
from dataclasses import dataclass, field
from typing import Literal

_MAX_INPUT_BYTES: int = 256 * 1024
_MAX_DECODED_BYTES: int = 512 * 1024
_MAX_RECURSION_DEPTH: int = 3
_MAX_DECODE_TIME_MS: float = 50.0
_DECODE_CACHE_LIMIT: int = 128
SAFE_DECODE_DETECTOR_VERSION: str = "safe-decode.v2"

EncodingType = Literal[
    "base64",
    "base64-urlsafe",
    "base32",
    "hex",
    "url-percent",
    "unicode-escape",
    "powershell-encoded",
    "shell-heredoc",
    "python-c",
    "node-e",
    "js-atob",
]


@dataclass(frozen=True)
class DecodedLayer:
    """Metadata for one decoded layer of encoded content."""

    encoding: EncodingType
    input_length: int
    output_length: int
    content_hash: str
    preview_redacted: str
    depth: int


@dataclass
class DecodeResult:
    """Result of a recursive decode pipeline run."""

    layers: list[DecodedLayer] = field(default_factory=list)
    final_text: str = ""
    truncated: bool = False
    timed_out: bool = False
    depth_exceeded: bool = False
    size_exceeded: bool = False
    eval_signals: list[str] = field(default_factory=list)
    exec_signals: list[str] = field(default_factory=list)
    marshal_signals: list[str] = field(default_factory=list)


_B64_CANDIDATE = re.compile(
    r"(?=[A-Za-z0-9+/]*(?:[+/]|(?=[A-Za-z0-9+/]*[A-Z])[A-Za-z0-9+/]*[a-z]))"
    r"(?:"
    r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)"
    r"|(?:[A-Za-z0-9+/]{4}){4,}"
    r")"
)
_B64_URLSAFE_CANDIDATE = re.compile(
    r"(?=[A-Za-z0-9\-_]*[\-_])"
    r"(?:[A-Za-z0-9\-_]{4}){5,}(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?"
)
_B32_CANDIDATE = re.compile(r"(?=[A-Za-z2-7]*(?:[A-Z]|[2-7]))[A-Za-z2-7]{16,}={0,6}")
_HEX_CANDIDATE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
_URL_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_POWERSHELL_ENCODED = re.compile(
    r"-(?:En(?:c(?:oded(?:Command)?)?)?)\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)
_PYTHON_C = re.compile(
    r"\bpython(?:3)?\b[^\r\n;&|]*\s-c\s*(?P<quote>['\"])(?P<code>(?:\\.|(?!(?P=quote)).)*)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_NODE_E = re.compile(
    r"\bnode\b[^\r\n;&|]*\s-e\s*(?P<quote>['\"])(?P<code>(?:\\.|(?!(?P=quote)).)*)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_HEREDOC = re.compile(r"<<-?\s*'?(\w+)'?\s*\n(.*?)\n\1\b", re.DOTALL)
_JS_ATOB = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/=]{4,})['\"]", re.IGNORECASE)

_JS_EVAL = re.compile(r"\beval\s*\(", re.IGNORECASE)
_PY_EXEC = re.compile(r"\bexec\s*\(", re.IGNORECASE)
_PY_MARSHAL = re.compile(r"\bmarshal\s*\.\s*loads\s*\(", re.IGNORECASE)

_REDACT_TOKENS = re.compile(
    r"\b(?:password|token|secret|key|aws_|npm_token|node_auth)\w*\s*=\s*\S+",
    re.IGNORECASE,
)
_DECODE_CACHE: dict[str, DecodeResult] = {}
_DECODE_CACHE_ORDER: list[str] = []


def decode_cache_key(
    content: str,
    *,
    max_input_bytes: int = _MAX_INPUT_BYTES,
    max_decoded_bytes: int = _MAX_DECODED_BYTES,
    max_depth: int = _MAX_RECURSION_DEPTH,
    detector_version: str = SAFE_DECODE_DETECTOR_VERSION,
) -> str:
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return f"{detector_version}:{max_input_bytes}:{max_decoded_bytes}:{max_depth}:{digest}"


def clear_decode_cache() -> None:
    _DECODE_CACHE.clear()
    _DECODE_CACHE_ORDER.clear()


def _clone_decode_result(result: DecodeResult) -> DecodeResult:
    return DecodeResult(
        layers=list(result.layers),
        final_text=result.final_text,
        truncated=result.truncated,
        timed_out=result.timed_out,
        depth_exceeded=result.depth_exceeded,
        size_exceeded=result.size_exceeded,
        eval_signals=list(result.eval_signals),
        exec_signals=list(result.exec_signals),
        marshal_signals=list(result.marshal_signals),
    )


def _cache_decode_result(key: str, result: DecodeResult) -> None:
    if key in _DECODE_CACHE:
        _DECODE_CACHE[key] = _clone_decode_result(result)
        return
    _DECODE_CACHE[key] = _clone_decode_result(result)
    _DECODE_CACHE_ORDER.append(key)
    while len(_DECODE_CACHE_ORDER) > _DECODE_CACHE_LIMIT:
        oldest = _DECODE_CACHE_ORDER.pop(0)
        _DECODE_CACHE.pop(oldest, None)


def _hash_preview(text: str) -> tuple[str, str]:
    encoded = text.encode("utf-8", errors="replace")
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    preview_raw = text[:120]
    preview = _REDACT_TOKENS.sub("[REDACTED]", preview_raw)
    return digest, preview


def _bytes_to_text(raw: bytes) -> str:
    """Convert decoded bytes to text, transparently decompressing gzip/zlib output first.

    Decompression is bounded by _MAX_DECODED_BYTES to prevent gzip-bomb expansion.
    """
    import contextlib
    import gzip

    if raw[:2] == b"\x1f\x8b":
        with contextlib.suppress(zlib.error, OSError), gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            raw = gz.read(_MAX_DECODED_BYTES + 1)
    elif raw[:1] == b"\x78":
        with contextlib.suppress(zlib.error):
            decompressor = zlib.decompressobj()
            raw = decompressor.decompress(raw, max_length=_MAX_DECODED_BYTES + 1)
    return raw.decode("utf-8", errors="replace")


def _try_base64(data: str) -> str | None:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False)
        return _bytes_to_text(decoded)
    except (binascii.Error, ValueError):
        return None


def _try_base64_urlsafe(data: str) -> str | None:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        return _bytes_to_text(decoded)
    except (binascii.Error, ValueError):
        return None


def _try_base32(data: str) -> str | None:
    padded = data + "=" * ((8 - len(data) % 8) % 8)
    try:
        decoded = base64.b32decode(padded.upper())
        return decoded.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _try_hex(data: str) -> str | None:
    cleaned = data.removeprefix("0x")
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    try:
        decoded = bytes.fromhex(cleaned)
        return decoded.decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def _try_url_percent(data: str) -> str | None:
    if not _URL_PERCENT.search(data):
        return None
    try:
        from urllib.parse import unquote

        return unquote(data, errors="replace")
    except Exception:
        return None


def _try_unicode_escape(data: str) -> str | None:
    if not _UNICODE_ESCAPE.search(data):
        return None
    try:
        return data.encode("utf-8").decode("unicode_escape", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return None


def _try_base64_utf16le(data: str) -> str | None:
    """Decode base64 bytes as UTF-16LE — the PowerShell -EncodedCommand convention."""
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        return raw.decode("utf-16-le", errors="replace")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _extract_powershell_encoded(text: str) -> str | None:
    m = _POWERSHELL_ENCODED.search(text)
    if not m:
        return None
    return _try_base64_utf16le(m.group(1)) or _try_base64(m.group(1))


def _unescape_command_argument(value: str) -> str:
    return value.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def _extract_heredoc(text: str) -> str | None:
    m = _HEREDOC.search(text)
    if not m:
        return None
    return m.group(2)


def _extract_js_atob(text: str) -> str | None:
    m = _JS_ATOB.search(text)
    if not m:
        return None
    return _try_base64(m.group(1))


def _detect_eval_signals(text: str) -> list[str]:
    return [m.group(0)[:40] for m in _JS_EVAL.finditer(text)]


def _detect_exec_signals(text: str) -> list[str]:
    return [m.group(0)[:40] for m in _PY_EXEC.finditer(text)]


def _detect_marshal_signals(text: str) -> list[str]:
    return [m.group(0)[:40] for m in _PY_MARSHAL.finditer(text)]


def _find_encoded_candidate(text: str) -> tuple[EncodingType, str] | None:
    m = _POWERSHELL_ENCODED.search(text)
    if m:
        return ("powershell-encoded", m.group(1))

    m = _PYTHON_C.search(text)
    if m:
        return ("python-c", m.group("code"))

    m = _NODE_E.search(text)
    if m:
        return ("node-e", m.group("code"))

    m = _JS_ATOB.search(text)
    if m:
        return ("js-atob", m.group(1))

    m = _HEREDOC.search(text)
    if m:
        return ("shell-heredoc", m.group(2))

    m = _URL_PERCENT.search(text)
    if m:
        return ("url-percent", text)

    m = _UNICODE_ESCAPE.search(text)
    if m:
        return ("unicode-escape", text)

    m = _B64_URLSAFE_CANDIDATE.search(text)
    if m:
        return ("base64-urlsafe", m.group(0))

    m = _B64_CANDIDATE.search(text)
    if m:
        return ("base64", m.group(0))

    m = _B32_CANDIDATE.search(text)
    if m:
        return ("base32", m.group(0))

    m = _HEX_CANDIDATE.search(text)
    if m:
        return ("hex", m.group(0))

    return None


def decode_layers(
    content: str,
    *,
    max_input_bytes: int = _MAX_INPUT_BYTES,
    max_decoded_bytes: int = _MAX_DECODED_BYTES,
    max_depth: int = _MAX_RECURSION_DEPTH,
    max_time_ms: float = _MAX_DECODE_TIME_MS,
) -> DecodeResult:
    """Decode multi-layer encoded content without executing any payload."""
    key = decode_cache_key(
        content,
        max_input_bytes=max_input_bytes,
        max_decoded_bytes=max_decoded_bytes,
        max_depth=max_depth,
    )
    cached = _DECODE_CACHE.get(key)
    if cached is not None:
        return _clone_decode_result(cached)
    result = _decode_layers_uncached(
        content,
        max_input_bytes=max_input_bytes,
        max_decoded_bytes=max_decoded_bytes,
        max_depth=max_depth,
        max_time_ms=max_time_ms,
    )
    if not result.timed_out:
        _cache_decode_result(key, result)
    return result


def _decode_layers_uncached(
    content: str,
    *,
    max_input_bytes: int,
    max_decoded_bytes: int,
    max_depth: int,
    max_time_ms: float,
) -> DecodeResult:
    result = DecodeResult()
    start = time.monotonic()

    if len(content.encode("utf-8", errors="replace")) > max_input_bytes:
        result.size_exceeded = True
        result.final_text = content
        return result

    current = content

    depth = -1
    _depth_limited = False
    for depth in range(max_depth):
        elapsed_ms = (time.monotonic() - start) * 1000.0
        if elapsed_ms > max_time_ms:
            result.timed_out = True
            break

        result.eval_signals.extend(_detect_eval_signals(current))
        result.exec_signals.extend(_detect_exec_signals(current))
        result.marshal_signals.extend(_detect_marshal_signals(current))

        candidate = _find_encoded_candidate(current)
        if candidate is None:
            break

        encoding_type, candidate_data = candidate
        decoded: str | None = None

        if encoding_type == "base64":
            decoded = _try_base64(candidate_data)
        elif encoding_type == "base64-urlsafe":
            decoded = _try_base64_urlsafe(candidate_data)
        elif encoding_type == "base32":
            decoded = _try_base32(candidate_data)
        elif encoding_type == "hex":
            decoded = _try_hex(candidate_data)
        elif encoding_type == "url-percent":
            decoded = _try_url_percent(candidate_data)
        elif encoding_type == "unicode-escape":
            decoded = _try_unicode_escape(candidate_data)
        elif encoding_type == "powershell-encoded":
            decoded = _try_base64_utf16le(candidate_data) or _try_base64(candidate_data)
        elif encoding_type in {"python-c", "node-e"}:
            decoded = _unescape_command_argument(candidate_data)
        elif encoding_type == "shell-heredoc":
            decoded = candidate_data
        elif encoding_type == "js-atob":
            decoded = _try_base64(candidate_data)

        if decoded is None or decoded == current:
            break

        decoded_bytes = len(decoded.encode("utf-8", errors="replace"))
        if decoded_bytes > max_decoded_bytes:
            result.size_exceeded = True
            result.truncated = True
            decoded = decoded[: max_decoded_bytes // 4]

        digest, preview = _hash_preview(decoded)
        result.layers.append(
            DecodedLayer(
                encoding=encoding_type,
                input_length=len(candidate_data),
                output_length=len(decoded),
                content_hash=digest,
                preview_redacted=preview,
                depth=depth,
            )
        )
        current = decoded

        if result.size_exceeded:
            break

        if depth == max_depth - 1:
            _depth_limited = True

    if _depth_limited and not result.timed_out:
        result.depth_exceeded = True
        result.eval_signals.extend(_detect_eval_signals(current))
        result.exec_signals.extend(_detect_exec_signals(current))
        result.marshal_signals.extend(_detect_marshal_signals(current))

    result.final_text = current
    return result
