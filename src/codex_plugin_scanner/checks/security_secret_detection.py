"""Secret candidate filtering and bounded detection."""

from __future__ import annotations


def _is_example_surface(relative_path: _security.Path) -> bool:
    path_parts = {part.lower() for part in relative_path.parts}
    return (
        relative_path.suffix.lower() in _security.DOCUMENTATION_EXTS
        or bool(path_parts & _security.EXAMPLE_PATH_HINTS)
        or bool(_security.TEST_FILE_RE.search(relative_path.name))
    )


def _extract_secret_candidate(detector: _security.SecretPattern, match: _security.re.Match[str]) -> str:
    return match.group(detector.value_group).strip()


def _normalize_secret_candidate(value: str) -> str:
    normalized = value.strip().strip("\"'`")
    if normalized.lower().startswith("bearer "):
        normalized = normalized[7:].strip()
    return normalized


def _looks_like_interpolated_secret(value: str) -> bool:
    """True only for complete env/template references with no literal payload."""
    normalized = _security._normalize_secret_candidate(value)
    return bool(
        _security._PURE_SHELL_EXPANSION_RE.fullmatch(normalized)
        or _security._PURE_TEMPLATE_EXPANSION_RE.fullmatch(normalized)
    )


def _looks_like_placeholder_secret(value: str) -> bool:
    normalized = _security._normalize_secret_candidate(value)
    lowered = normalized.lower()
    if not normalized:
        return True
    if _security._looks_like_interpolated_secret(normalized) or normalized.startswith(("<", "[")):
        return True
    if "..." in normalized or "…" in normalized:
        return True
    if lowered.startswith(("your-", "your_", "your", "example-", "sample-", "demo-")):
        return True
    if lowered.endswith(("-here", "_here", "example", "sample")):
        return True
    if lowered in _security.PLACEHOLDER_MARKERS:
        return True
    return bool(_security.re.search(r"(?i)(?:^|[-_])(x{4,}|\*{3,})(?:[-_]|$)", normalized))


def _normalized_alnum(value: str) -> str:
    return _security.re.sub(r"[^a-z0-9]", "", _security._normalize_secret_candidate(value).lower())


def _ascending_run_stats(value: str) -> tuple[int, int]:
    if not value:
        return 0, 0
    longest = 1
    current = 1
    coverage = 0
    for previous, token in _security.pairwise(value):
        if ord(token) == ord(previous) + 1:
            current += 1
            longest = max(longest, current)
        else:
            if current >= 4:
                coverage += current
            current = 1
    if current >= 4:
        coverage += current
    return longest, coverage


def _provider_payload(value: str) -> tuple[str, int] | None:
    normalized = _security._normalize_secret_candidate(value)
    for pattern, minimum_length in _security.PROVIDER_PREFIX_PATTERNS:
        match = pattern.fullmatch(normalized)
        if match:
            return match.group("payload"), minimum_length
    return None


def _looks_like_synthetic_provider_candidate(value: str) -> bool:
    provider_payload = _security._provider_payload(value)
    if provider_payload is None:
        return False
    payload, _minimum_length = provider_payload
    normalized = _security._normalized_alnum(payload)
    if len(normalized) < 8:
        return False
    longest_run, coverage = _security._ascending_run_stats(normalized)
    return longest_run >= 8 and coverage / len(normalized) >= 0.6


def _looks_like_incomplete_provider_candidate(value: str) -> bool:
    provider_payload = _security._provider_payload(value)
    if provider_payload is None:
        return False
    payload, minimum_length = provider_payload
    normalized = _security._normalized_alnum(payload)
    return len(normalized) < minimum_length


def _looks_like_example_generic_secret(value: str) -> bool:
    normalized = _security._normalize_secret_candidate(value).lower()
    return normalized in _security.EXAMPLE_GENERIC_VALUES


def _newline_offsets(content: str) -> tuple[int, ...]:
    return tuple(match.start() for match in _security.re.finditer("\n", content))


def _line_number_for_offset(content: str, offset: int, offsets: tuple[int, ...] | None = None) -> int:
    newline_offsets = offsets if offsets is not None else _security._newline_offsets(content)
    return _security.bisect.bisect_left(newline_offsets, offset) + 1


def _has_illustrative_context(
    relative_path: _security.Path,
    content: str,
    offset: int,
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
) -> bool:
    if {part.lower() for part in relative_path.parts} & _security.ILLUSTRATIVE_PATH_HINTS:
        return True
    context_lines = lines if lines is not None else content.splitlines()
    line_number = _security._line_number_for_offset(content, offset, offsets)
    start = max(0, line_number - 3)
    end = min(len(context_lines), line_number + 2)
    context = "\n".join(context_lines[start:end])
    return any(pattern.search(context) for pattern in _security.ILLUSTRATIVE_CONTEXT_PATTERNS)


def _private_key_looks_like_placeholder(body_lines: list[str]) -> bool:
    body_text = "\n".join(body_lines)
    if _security._looks_like_placeholder_secret(body_text):
        return True
    placeholder_lines = {"mii...", "[redacted]", "redacted", "secret-key-material"}
    lowered_lines = [line.lower() for line in body_lines]
    return any(line in placeholder_lines or "redacted" in line for line in lowered_lines)


def _extract_inline_private_key_body(line: str, header: str) -> list[str]:
    header_index = line.find(header)
    if header_index == -1:
        return []
    tail = line[header_index + len(header) :]
    if "\\n" not in tail:
        return []
    body_lines: list[str] = []
    for fragment in tail.split("\\n")[1:]:
        cleaned = fragment.strip().strip("\"'`),;}]")
        if cleaned:
            body_lines.append(cleaned)
    return body_lines


def _first_private_key_line(
    relative_path: _security.Path,
    content: str,
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
) -> int | None:
    content_lines = lines if lines is not None else content.splitlines()
    example_surface = _security._is_example_surface(relative_path)
    for match in _security.PRIVATE_KEY_HEADER_RE.finditer(content):
        line_number = _security._line_number_for_offset(content, match.start(), offsets)
        label = match.group("label")
        footer = _security.PRIVATE_KEY_FOOTER_TEMPLATE.format(label=label)
        header = match.group(0)
        body_lines = _security._extract_inline_private_key_body(content_lines[line_number - 1], header)
        has_footer = False
        for candidate_line in content_lines[line_number:]:
            stripped = candidate_line.strip()
            if not stripped:
                if body_lines:
                    break
                continue
            if stripped == footer:
                has_footer = True
                break
            if stripped.startswith("-----END ") or stripped.startswith("-----BEGIN ") or stripped == "```":
                break
            body_lines.append(stripped)
        if not body_lines:
            continue
        body_text = "".join(body_lines)
        if example_surface and _security._private_key_looks_like_placeholder(body_lines):
            continue
        if len(body_text) >= 32:
            return line_number
        if has_footer:
            return line_number
    return None


def _should_skip_secret_match(
    relative_path: _security.Path,
    content: str,
    detector: _security.SecretPattern,
    match: _security.re.Match[str],
    *,
    lines: list[str] | None = None,
    offsets: tuple[int, ...] | None = None,
    field_name_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    """Decide whether a match qualifies for a scoped non-secret or example exemption."""
    candidate = _security._extract_secret_candidate(detector, match)
    if _security._looks_like_interpolated_secret(candidate):
        return True
    if detector.kind == "generic" and _security._provider_payload(candidate) is None:
        if _security._is_generated_token_expression(relative_path, content, match):
            return True
        span_index = _security.bisect.bisect_right(field_name_spans, (match.start(), len(content))) - 1
        if span_index >= 0:
            start, end = field_name_spans[span_index]
            if start <= match.start() and match.end() <= end:
                return True
    if not _security._is_example_surface(relative_path):
        return False
    if _security._looks_like_placeholder_secret(candidate):
        return True
    effective_kind = detector.kind
    if effective_kind == "generic" and _security._provider_payload(candidate) is not None:
        effective_kind = "provider"
    if effective_kind == "generic":
        return _security._looks_like_example_generic_secret(candidate)
    if effective_kind == "provider":
        if not _security._has_illustrative_context(relative_path, content, match.start(), lines=lines, offsets=offsets):
            return False
        return _security._looks_like_synthetic_provider_candidate(
            candidate
        ) or _security._looks_like_incomplete_provider_candidate(candidate)
    return False


def _first_hardcoded_secret_line(relative_path: _security.Path, content: str) -> int | None:
    """Find the first retained secret line while enforcing the per-file match budget."""
    offsets = _security._newline_offsets(content)
    lines = content.splitlines()
    field_name_spans = _security._field_name_map_spans(relative_path, content)
    first_line = _security._first_private_key_line(relative_path, content, lines=lines, offsets=offsets)
    first_offset: int | None = None
    matches_seen = 0
    for detector in _security.SECRET_PATTERNS:
        if detector.kind == "private_key":
            continue
        for match in detector.pattern.finditer(content):
            matches_seen += 1
            if matches_seen > _security.MAX_SECRET_MATCHES_PER_FILE:
                raise _security.ScanBudgetExceededError(
                    f"secret matches exceeded {_security.MAX_SECRET_MATCHES_PER_FILE} in {relative_path}"
                )
            if first_offset is not None and match.start() >= first_offset:
                break
            if _security._should_skip_secret_match(
                relative_path,
                content,
                detector,
                match,
                lines=lines,
                offsets=offsets,
                field_name_spans=field_name_spans,
            ):
                continue
            first_offset = match.start()
            line_number = _security._line_number_for_offset(content, match.start(), offsets)
            if first_line is None or line_number < first_line:
                first_line = line_number
    return first_line


# Bind after definitions so either the facade or this helper can be imported first.
from . import security as _security  # noqa: E402
