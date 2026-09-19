"""Prompt intent.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _prompt_sentence_start(text: str, index: int) -> int:
    matches = list(runner._PROMPT_SENTENCE_BOUNDARY_PATTERN.finditer(text, 0, index))
    return matches[-1].end() if matches else 0


def _prompt_sentence_end(text: str, index: int) -> int:
    match = runner._PROMPT_SENTENCE_BOUNDARY_PATTERN.search(text, index)
    return match.end() if match is not None else len(text)


def _prompt_secret_intent_region(text: str, *, start: int, end: int) -> str:
    current_sentence_start = runner._prompt_sentence_start(text, start)
    region_start = runner._prompt_sentence_start(text, max(0, current_sentence_start - 1))
    first_sentence_end = runner._prompt_sentence_end(text, end)
    second_sentence_end = (
        runner._prompt_sentence_end(text, first_sentence_end) if first_sentence_end < len(text) else first_sentence_end
    )
    return text[region_start:second_sentence_end]


def _prompt_has_secret_read_intent(prompt_text: str, *, start: int, end: int) -> bool:
    if runner._prompt_match_is_documented_example(prompt_text, start=start, end=end):
        return False
    sentence = runner._secret_match_sentence(prompt_text, start=start, end=end)
    sentence_end = runner._prompt_sentence_end(prompt_text, end)
    sentence_intents = tuple(runner._SECRET_READ_INTENT_PATTERN.finditer(sentence))
    if sentence_intents:
        if any(
            not runner._secret_read_intent_is_negated(sentence, match.start(), match.end())
            for match in sentence_intents
        ):
            return True
        return runner._following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    if runner._NEGATED_SECRET_READ_PATTERN.search(sentence) is not None:
        return runner._following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    region = runner._prompt_secret_intent_region(prompt_text, start=start, end=end)
    for match in runner._SECRET_READ_INTENT_PATTERN.finditer(region):
        if not runner._secret_read_intent_is_negated(region, match.start(), match.end()):
            return True
    return False


def _secret_match_sentence(prompt_text: str, *, start: int, end: int) -> str:
    sentence_start = runner._prompt_sentence_start(prompt_text, start)
    sentence_end = runner._prompt_sentence_end(prompt_text, end)
    return prompt_text[sentence_start:sentence_end]


def _following_sentence_has_secret_read_intent(prompt_text: str, sentence_end: int) -> bool:
    if sentence_end >= len(prompt_text):
        return False
    next_end = runner._prompt_sentence_end(prompt_text, sentence_end)
    following = prompt_text[sentence_end:next_end]
    has_positive_intent = any(
        not runner._secret_read_intent_is_negated(following, match.start(), match.end())
        for match in runner._SECRET_READ_INTENT_PATTERN.finditer(following)
    )
    if not has_positive_intent:
        return False
    return runner._FOLLOWING_SECRET_REFERENCE_PATTERN.search(following) is not None


def _secret_read_intent_is_negated(region: str, intent_start: int, intent_end: int) -> bool:
    window_start = max(0, intent_start - 90)
    prefix = region[window_start:intent_start]
    clause_start = window_start
    for boundary in (".", "!", "?", ";", ",", " and ", " but ", " then "):
        boundary_index = prefix.rfind(boundary)
        if boundary_index >= 0:
            clause_start = max(clause_start, window_start + boundary_index + len(boundary))
    scoped_start = clause_start
    scoped_region = region[scoped_start:intent_end]
    return runner._NEGATED_SECRET_READ_PATTERN.search(scoped_region) is not None


def _prompt_match_is_documented_example(prompt_text: str, *, start: int, end: int) -> bool:
    region = runner._prompt_secret_intent_region(prompt_text, start=start, end=end)
    if runner._DOCUMENT_PROMPT_ACTION_PATTERN.search(region) is None:
        return False
    if runner._DOCUMENT_PROMPT_TARGET_PATTERN.search(region) is None:
        return False
    if runner._DOCUMENT_PROMPT_GUARDRAIL_PATTERN.search(region) is None:
        return False
    if runner._DOCUMENT_PROMPT_CONTEXT_PATTERN.search(region) is None and not runner._prompt_match_is_wrapped_literal(
        prompt_text,
        start=start,
        end=end,
    ):
        return False
    return runner._DOCUMENT_PROMPT_STRONG_GUARDRAIL_PATTERN.search(
        region
    ) is not None or runner._prompt_match_is_wrapped_literal(
        prompt_text,
        start=start,
        end=end,
    )


def _prompt_match_is_wrapped_literal(prompt_text: str, *, start: int, end: int) -> bool:
    if start < len(prompt_text) and prompt_text[start] in {"`", "'", '"'}:
        delimiter = prompt_text[start]
        return runner._next_non_whitespace_character(prompt_text, end) == delimiter
    delimiter = runner._previous_non_whitespace_character(prompt_text, start)
    if delimiter not in {"`", "'", '"'}:
        return False
    return runner._next_non_whitespace_character(prompt_text, end) == delimiter


def _previous_non_whitespace_character(text: str, index: int) -> str | None:
    for position in range(index - 1, -1, -1):
        if not text[position].isspace():
            return text[position]
    return None


def _next_non_whitespace_character(text: str, index: int) -> str | None:
    for position in range(index, len(text)):
        if not text[position].isspace():
            return text[position]
    return None


def _first_match(patterns: tuple[runner.re.Pattern[str], ...], text: str) -> runner.re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return match
    return None


def _iter_hint_occurrences(text: str, hint: str) -> list[tuple[int, int]]:
    occurrences: list[tuple[int, int]] = []
    current_pos = 0
    while True:
        start = text.find(hint, current_pos)
        if start == -1:
            return occurrences
        end = start + len(hint)
        occurrences.append((start, end))
        current_pos = start + 1
