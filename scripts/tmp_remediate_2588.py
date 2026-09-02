from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"{label} block not found")
    return text.replace(old, new, 1)


semantic = Path("src/codex_plugin_scanner/guard/runtime/semantic_explanations.py")
text = semantic.read_text()
text = replace_once(
    text,
    'required_tokens=(frozenset({"-d", "--data", "--data-binary", "--form", "--upload-file", "--body", "-infile"}),),',
    'required_tokens=(frozenset({"-d", "--data", "--data-binary", "--form", "-F", "--upload-file", "-T", "--body", "-infile"}),),',
    "network.upload tokens",
)
text = replace_once(
    text,
    '''def _normalized_tokens(arguments: Iterable[str]) -> Iterable[str]:
    for argument in arguments:
        value = argument.strip().casefold()
        if value:
            yield value
            if "=" in value:
                yield value.split("=", 1)[0]
''',
    '''def _normalized_tokens(arguments: Iterable[str]) -> Iterable[str]:
    for argument in arguments:
        raw = argument.strip()
        if not raw:
            continue
        folded = raw.casefold()
        yield folded
        # Short options can be case-sensitive (notably curl -F/-T versus -f).
        if raw.startswith("-") and not raw.startswith("--") and len(raw) == 2:
            yield raw
        if "=" in raw:
            prefix = raw.split("=", 1)[0]
            yield prefix.casefold()
            if prefix.startswith("-") and not prefix.startswith("--") and len(prefix) == 2:
                yield prefix
''',
    "normalized tokens",
)
text = replace_once(
    text,
    '''def _network_host(input: CommandSemanticInput, arguments: Sequence[str]) -> str | None:
    for value in input.network_hosts:
        host = value.strip().strip("[]")
        if host:
            return host
    for argument in arguments:
        match = _URL_RE.search(argument)
        if match:
            return match.group(1).strip("[]")
    return None
''',
    '''def _network_host(input: CommandSemanticInput, arguments: Sequence[str]) -> str | None:
    for value in input.network_hosts:
        host = _host_only(value)
        if host:
            return host
    for argument in arguments:
        if "://" not in argument:
            continue
        host = _host_only(argument)
        if host:
            return host
    return None


def _host_only(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    try:
        from urllib.parse import urlsplit

        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        if parsed.hostname:
            return parsed.hostname
    except ValueError:
        pass
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1 : candidate.index("]")]
    return candidate.strip("[]")
''',
    "network host",
)
semantic.write_text(text)

builder = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_builder.py")
text = builder.read_text()
text = replace_once(
    text,
    '''from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    GuardActionExplanationV1,
    parse_action_explanation,
)''',
    '''from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    ACTION_EXPLANATION_SCHEMA_VERSION,
    ACTION_EXPLANATION_VERSION,
    GuardActionExplanationV1,
    parse_action_explanation,
)''',
    "contract imports",
)
text = text.replace("                    operands=tuple(segment.arguments),", "                    operands=(),")
text = text.replace(
    '        "schema_version": "guard.action-explanation.v1",\n        "explanation_version": "1.0.0",',
    '        "schema_version": ACTION_EXPLANATION_SCHEMA_VERSION,\n        "explanation_version": ACTION_EXPLANATION_VERSION,',
)
if "operands=tuple(segment.arguments)" in text:
    raise SystemExit("compound operands fix failed")
if '"schema_version": "guard.action-explanation.v1"' in text or '"explanation_version": "1.0.0"' in text:
    raise SystemExit("contract version fix failed")
builder.write_text(text)

semantic_tests = Path("tests/test_guard_semantic_explanations.py")
text = semantic_tests.read_text()
if "def test_curl_short_upload_flags_remain_case_sensitive()" not in text:
    text += '''


def test_curl_short_upload_flags_remain_case_sensitive() -> None:
    def explain(args: tuple[str, ...]):
        return explain_command(
            CommandSemanticInput(
                action_identity="curl-short-flag",
                canonical_identity="curl-short-flag",
                actor_label="an AI app",
                executable="curl",
                arguments=args,
            )
        )

    assert explain(("-F", "field=data", "https://example.test/upload")).kind == "network_send"
    assert explain(("-T", "artifact.bin", "https://example.test/upload")).kind == "network_send"
    assert explain(("-f", "https://example.test/status")).kind == "network_read"


def test_ipv6_network_host_strips_brackets_and_port() -> None:
    explanation = explain_command(
        CommandSemanticInput(
            action_identity="ipv6-host",
            canonical_identity="ipv6-host",
            actor_label="an AI app",
            executable="curl",
            arguments=("https://[::1]:8080/path",),
        )
    )
    label = explanation.everyday.targets[0].label
    assert label == "the service at ::1"
    assert ":8080" not in label
'''
semantic_tests.write_text(text)

builder_tests = Path("tests/test_guard_action_explanation_builder.py")
text = builder_tests.read_text()
if "def test_compound_step_flags_do_not_become_filesystem_targets()" not in text:
    text += '''


def test_compound_step_flags_do_not_become_filesystem_targets() -> None:
    canonical = parse_shell_command("cd project && rm build -rf")
    explanation = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:compound-flags",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    labels = [target.label for target in explanation.everyday.targets]
    assert any("build" in label for label in labels)
    assert all("item named rf" not in label for label in labels)


def test_compound_contract_versions_use_authoritative_constants() -> None:
    from codex_plugin_scanner.guard.runtime.action_explanation_contract import (
        ACTION_EXPLANATION_SCHEMA_VERSION,
        ACTION_EXPLANATION_VERSION,
    )

    canonical = parse_shell_command("rm build -rf && npm install")
    explanation = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:compound-version",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert explanation.schema_version == ACTION_EXPLANATION_SCHEMA_VERSION
    assert explanation.explanation_version == ACTION_EXPLANATION_VERSION
'''
builder_tests.write_text(text)
