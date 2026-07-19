"""Track shell bindings that can resolve to GitHub commands or command text."""

from __future__ import annotations

import re
from collections.abc import Callable

AssignmentUpdates = tuple[tuple[str, bool], ...]
_GH_LOOKUP_EXPRESSION = r"\$\(\s*(?:command\s+-v|which)\s+gh\s*\)"
_GH_LOOKUP_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    + rf'(?:{_GH_LOOKUP_EXPRESSION}|"{_GH_LOOKUP_EXPRESSION}")'
)


def normalize_github_lookup_assignments(command_text: str) -> str:
    """Normalize statically resolved GitHub executable assignments."""

    return _GH_LOOKUP_ASSIGNMENT.sub(lambda match: f"{match.group('name')}=gh", command_text)


def contains_github_command_text(text: str) -> bool:
    """Return whether text contains a literal GitHub CLI command token."""

    executable = r"(?:[A-Za-z]:)?(?:[/\\][A-Za-z0-9_.~-]+)*[/\\]?gh(?:\.exe)?"
    return (
        re.search(
            rf"(?:^|[=;&|()\s])[\"']?{executable}(?:[;&|)\s]|$)",
            text,
            re.IGNORECASE,
        )
        is not None
    )


def pipeline_executes_github_text(
    pipeline: list[list[str]],
    *,
    primary_command: Callable[[list[str]], tuple[str | None, int | None]],
    github_command_text_variables: frozenset[str],
) -> bool:
    """Return whether a pipeline feeds GitHub command text to a shell."""

    shell_stdin_executors = frozenset({"bash", "dash", "eval", "sh", "xargs", "zsh"})
    for index, segment in enumerate(pipeline[1:], start=1):
        command_name, _command_index = primary_command(segment)
        if command_name not in shell_stdin_executors:
            continue
        upstream_tokens = [token for prior in pipeline[:index] for token in prior]
        if contains_github_command_text(" ".join(upstream_tokens)) or tokens_reference_github_variable(
            upstream_tokens,
            github_command_variables=frozenset(),
            github_command_text_variables=github_command_text_variables,
        ):
            return True
    return False


def assignment_updates(
    segment: list[str],
    *,
    command_index: int | None,
    text_values: bool = False,
    text_value_classifier: Callable[[str], bool] | None = None,
) -> AssignmentUpdates:
    """Return GitHub binding changes from shell assignment tokens."""

    updates: list[tuple[str, bool]] = []
    assignment_limit = len(segment) if command_index is None else command_index
    for token in segment[:assignment_limit]:
        name, separator, value = token.partition("=")
        if not separator or not is_shell_variable_name(name):
            continue
        if text_values:
            names_github = (
                text_value_classifier(value)
                if text_value_classifier is not None
                else bool(value.split()) and contains_github_command_text(value)
            )
        else:
            names_github = value_names_github_executable(value)
        updates.append((name, names_github))
    return tuple(updates)


def persistent_assignment_updates(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int | None,
    text_values: bool,
    text_value_classifier: Callable[[str], bool] | None = None,
) -> AssignmentUpdates:
    """Return binding changes that survive the current shell command."""

    classifier: Callable[..., AssignmentUpdates] = assignment_updates
    if segment_is_standalone_assignment(segment):
        return classifier(
            segment,
            command_index=None,
            text_values=text_values,
            text_value_classifier=text_value_classifier,
        )
    if command_name in {"declare", "export", "local", "readonly", "typeset"} and command_index is not None:
        assignments = [token for token in segment[command_index + 1 :] if not token.startswith("-")]
        return classifier(
            assignments,
            command_index=None,
            text_values=text_values,
            text_value_classifier=text_value_classifier,
        )
    if command_name == "unset" and command_index is not None:
        return tuple(
            (token, False)
            for token in segment[command_index + 1 :]
            if not token.startswith("-") and is_shell_variable_name(token)
        )
    return ()


def apply_assignment_updates(bindings: set[str], updates: AssignmentUpdates) -> None:
    """Apply ordered binding changes in place."""

    for name, names_github in updates:
        if names_github:
            bindings.add(name)
        else:
            bindings.discard(name)


def update_exported_bindings(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int | None,
    current_bindings: set[str],
    exported_bindings: set[str],
    suppress_removals: bool = False,
) -> None:
    """Track which GitHub-resolving variables are inherited by child shells."""

    if command_name == "unset" and command_index is not None:
        if not suppress_removals:
            for token in segment[command_index + 1 :]:
                exported_bindings.discard(token)
        return
    exports = command_name == "export"
    exports = exports or (
        command_name in {"declare", "typeset"}
        and command_index is not None
        and any("x" in token[1:] for token in segment[command_index + 1 :] if token.startswith("-"))
    )
    if not exports or command_index is None:
        return
    removes_export = any(
        token == "--unexport" or (token.startswith("-") and "n" in token[1:]) for token in segment[command_index + 1 :]
    )
    for token in segment[command_index + 1 :]:
        if token.startswith("-"):
            continue
        name = token.partition("=")[0]
        if not is_shell_variable_name(name):
            continue
        if not removes_export and name in current_bindings:
            exported_bindings.add(name)
        elif not suppress_removals:
            exported_bindings.discard(name)


def segment_is_standalone_assignment(segment: list[str]) -> bool:
    return bool(segment) and all(token_is_shell_assignment(token) for token in segment)


def token_is_shell_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    return bool(separator) and is_shell_variable_name(name)


def is_shell_variable_name(name: str) -> bool:
    return bool(name) and not name[0].isdigit() and name.replace("_", "a").isalnum()


def value_names_github_executable(value: str) -> bool:
    normalized = value.strip("\"'")
    if any(character.isspace() for character in normalized):
        return False
    executable = normalized.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable.removesuffix(".exe") == "gh"


def conditional_pipeline_indexes(parts: list[str]) -> frozenset[int]:
    """Return pipelines reached through conditional shell separators."""

    indexes: set[int] = set()
    pipeline_index = 0
    for token in parts:
        if token not in {"&", "&&", ";", "||"}:
            continue
        pipeline_index += 1
        if token in {"&&", "||"}:
            indexes.add(pipeline_index)
    return frozenset(indexes)


def conditional_pipeline_connectors(parts: list[str]) -> dict[int, str]:
    """Map each conditional pipeline to the connector that guards it."""

    connectors: dict[int, str] = {}
    pipeline_index = 0
    for token in parts:
        if token not in {"&", "&&", ";", "||"}:
            continue
        pipeline_index += 1
        if token in {"&&", "||"}:
            connectors[pipeline_index] = token
    return connectors


def pipeline_control_flow(
    parts: list[str],
    pipelines: list[list[list[str]]],
    *,
    primary_command: Callable[[list[str]], tuple[str | None, int | None]],
) -> tuple[frozenset[int], frozenset[int]]:
    """Return conditional and statically skipped pipeline indexes."""

    connectors = conditional_pipeline_connectors(parts)
    skipped: set[int] = set()
    for pipeline_index, connector in connectors.items():
        previous_command, _previous_index = primary_command(pipelines[pipeline_index - 1][-1])
        if (connector == "&&" and previous_command == "false") or (connector == "||" and previous_command == "true"):
            skipped.add(pipeline_index)
    conditional = set(connectors)
    if_stack: list[tuple[bool | None, str | None]] = []
    for pipeline_index, pipeline in enumerate(pipelines):
        segment = pipeline[0] if pipeline else []
        first = segment[0].strip("\"'").lower() if segment else ""
        if first == "if":
            condition = segment[1].strip("\"'").lower() if len(segment) > 1 else ""
            truth = True if condition == "true" else False if condition == "false" else None
            if_stack.append((truth, None))
            continue
        if first == "fi":
            if if_stack:
                _ = if_stack.pop()
            continue
        if first in {"then", "else", "elif"} and if_stack:
            truth, _branch = if_stack[-1]
            if first == "elif":
                truth = None
            branch = "else" if first == "else" else "then"
            if_stack[-1] = (truth, branch)
        if not if_stack or if_stack[-1][1] is None:
            continue
        truth, branch = if_stack[-1]
        if truth is None:
            conditional.add(pipeline_index)
        elif (branch == "then" and not truth) or (branch == "else" and truth):
            skipped.add(pipeline_index)
    return frozenset(conditional), frozenset(skipped)


def parent_expanded_variable_names(command_text: str) -> frozenset[str]:
    """Return shell variables expanded outside single-quoted text."""

    visible = re.sub(r"'[^']*'", "", command_text)
    names = {
        match.group("braced") or match.group("plain")
        for match in re.finditer(
            r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))",
            visible,
        )
    }
    return frozenset(name for name in names if name is not None)


def complex_control_flow_may_invoke_github(
    command_text: str,
    *,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> bool:
    """Fail closed when compound shell state can affect a GitHub invocation."""

    has_compound_flow = re.search(
        r"(?:^|[;&|]\s*)(?:case|for|if|until|while)\b|(?:^|[;&|]\s*)[({]\s+",
        command_text,
    )
    if has_compound_flow is None:
        return False
    github_assignment = re.search(
        r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"']?"
        + r"(?:(?:[A-Za-z]:)?(?:[/\\][A-Za-z0-9_.~-]+)*[/\\])?gh(?:\.exe)?(?:[\"']|[;&|\s]|$)",
        command_text,
        re.IGNORECASE,
    )
    return (
        github_assignment is not None
        or _GH_LOOKUP_ASSIGNMENT.search(command_text) is not None
        or tokens_reference_github_variable(
            [command_text],
            github_command_variables=github_command_variables,
            github_command_text_variables=github_command_text_variables,
        )
    )


def segment_starts_function_definition(segment: list[str], *, command_index: int, normalized_tokens: list[str]) -> bool:
    """Return whether a shell segment begins a function definition."""

    raw_command = segment[command_index].strip("\"'").lower()
    if raw_command.endswith("(){"):
        return True
    suffix_index = command_index + 1
    has_function_suffix = raw_command.endswith("()")
    if suffix_index < len(normalized_tokens) and normalized_tokens[suffix_index] == "()":
        has_function_suffix = True
        suffix_index += 1
    return has_function_suffix and any(token in {"{", "("} for token in normalized_tokens[suffix_index:])


def definition_payload(segment: list[str], *, command_name: str, command_index: int) -> str:
    """Extract the executable body of an alias or function definition."""

    payload = " ".join(segment[command_index + 1 :]).strip()
    if command_name == "alias":
        _alias_name, separator, alias_body = payload.partition("=")
        return alias_body if separator else payload
    for opener, closer in (("{", "}"), ("(", ")")):
        opener_index = payload.find(opener)
        if opener_index >= 0:
            return payload[opener_index + 1 :].rsplit(closer, 1)[0].strip()
    return payload.rsplit("}", 1)[0].strip()


def executable_control_flow_segment(segment: list[str]) -> list[str]:
    """Strip shell reserved words that prefix an executable command."""

    normalized = segment
    while normalized:
        first = normalized[0].strip("\"'").lower()
        if first == "coproc":
            normalized = normalized[1:]
            if len(normalized) > 1 and normalized[1] in {"(", "{"}:
                normalized = normalized[1:]
            continue
        if first in {"!", "(", "{", "do", "elif", "else", "if", "then", "until", "while"}:
            normalized = normalized[1:]
            continue
        if first.endswith(")") and len(normalized) > 1:
            normalized = normalized[1:]
            continue
        break
    return normalized


def case_arm_segments(segment: list[str]) -> tuple[list[str], ...]:
    """Return every executable arm from a shell case segment."""

    if not segment or segment[0].strip("\"'").lower() != "case":
        return ()
    arms: list[list[str]] = []
    current: list[str] = []
    for token in segment[3:]:
        if token in {";;", ";&", ";;&"}:
            if current:
                arms.append(executable_control_flow_segment(current))
            current = []
            continue
        current.append(token)
    if current:
        arms.append(executable_control_flow_segment(current))
    return tuple(arm for arm in arms if arm)


def scoped_command_substitutions(
    command_text: str,
    *,
    payloads: Callable[[str], tuple[str, ...]],
) -> tuple[tuple[str, str], ...]:
    """Pair quote-aware command substitutions with their preceding shell text."""

    scoped: list[tuple[str, str]] = []
    cursor = 0
    for payload in payloads(command_text):
        patterns = (f"$({payload})", f"<({payload})", f">({payload})", f"`{payload}`")
        positions = [position for pattern in patterns if (position := command_text.find(pattern, cursor)) >= 0]
        if not positions:
            continue
        position = min(positions)
        scoped.append((payload, command_text[:position]))
        cursor = position + 1
    return tuple(scoped)


def function_definition_payloads(command_text: str) -> tuple[tuple[str, str, int, int], ...]:
    """Extract balanced shell function bodies from common definition forms."""

    pattern = re.compile(
        r"(?:\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\s*\)\s*)?|"
        + r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*)"
        + r"(?P<opener>[{(])"
    )
    payloads: list[tuple[str, str, int, int]] = []
    for match in pattern.finditer(command_text):
        opener = match.group("opener")
        closer = "}" if opener == "{" else ")"
        depth = 1
        quote: str | None = None
        escaped = False
        index = match.end()
        while index < len(command_text) and depth:
            character = command_text[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif quote is not None:
                if character == quote:
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == opener:
                depth += 1
            elif character == closer:
                depth -= 1
            index += 1
        if depth == 0:
            payloads.append(
                (
                    command_text[match.end() : index - 1],
                    command_text[: match.start()],
                    match.start(),
                    index,
                )
            )
    return tuple(payloads)


def dynamic_command_may_invoke_github(
    command_name: str,
    *,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> bool:
    """Return whether a dynamic command token resolves to tracked GitHub data."""

    normalized = command_name.strip("\"'")
    if normalized.startswith("${") and normalized.endswith("}"):
        expression = normalized[2:-1]
        variable_name = expression
        fallback = ""
        for operator in (":-", "-"):
            if operator in expression:
                variable_name, fallback = expression.split(operator, 1)
                break
        return (
            variable_name in {"GH", "gh"}
            or variable_name in github_command_variables
            or variable_name in github_command_text_variables
            or value_names_github_executable(fallback)
        )
    if normalized.startswith("$"):
        variable_name = normalized[1:]
        return (
            variable_name in {"GH", "gh"}
            or variable_name in github_command_variables
            or variable_name in github_command_text_variables
        )
    return False


def tokens_reference_github_variable(
    tokens: list[str],
    *,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> bool:
    """Return whether tokens reference a tracked GitHub binding."""

    github_variables = github_command_variables | github_command_text_variables | {"GH", "gh"}
    for token in tokens:
        references = re.finditer(
            r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))",
            token,
        )
        if any((match.group("braced") or match.group("plain")) in github_variables for match in references):
            return True
    return False
