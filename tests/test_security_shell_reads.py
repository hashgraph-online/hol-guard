"""Credential-read syntax must not exempt literal or adjacent secret material."""

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.checks.security import SecretPattern, _first_hardcoded_secret_line, _should_skip_secret_match
from codex_plugin_scanner.checks.security_shell_reads import _shell_credential_read_spans


@pytest.mark.parametrize("path", ["scripts/start.sh", "scripts/start.bash", "skills/connect/SKILL.md"])
@pytest.mark.parametrize(
    "expression",
    [
        '$(printenv "$TOKEN_VAR")',
        '$(printenv "${TOKEN_VAR}" 2>/dev/null || true)',
        "$(printenv API_TOKEN)",
        "$(gcloud auth print-access-token)",
        "$(gcloud auth application-default print-access-token 2>/dev/null || true)",
        '$(gcloud auth print-access-token --project="$GCP_PROJECT")',
        '$(gcloud --configuration="$CONFIG" auth print-access-token)',
        '$(gcloud auth print-access-token --impersonate-service-account "$SERVICE_ACCOUNT")',
        "$(gcloud auth print-access-token --account=operator@example.invalid)",
    ],
)
def test_complete_runtime_credential_reads_are_not_literals(path, expression):
    content = f'export SERVICE_TOKEN="{expression}"; export SERVICE_TOKEN\n'
    if path.endswith(".md"):
        content = f"```bash\n{content}```\n"
    assert _first_hardcoded_secret_line(Path(path), content) is None


def test_inline_shell_branches_and_multiple_reads():
    content = (
        'if [ -n "$ADC" ]; then TOKEN="$(gcloud auth application-default print-access-token)"; '
        'else TOKEN="$(gcloud auth print-access-token)"; fi\n'
    )
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is None


def test_newline_after_a_logical_operator_starts_a_recognized_assignment():
    # A physical newline is supported even when the preceding command uses &&.
    content = 'true &&\nTOKEN="$(printenv TOKEN)"\n'
    assert len(_shell_credential_read_spans(Path("scripts/start.sh"), content)) == 1
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is None


@pytest.mark.parametrize("operator", ["&&", "||"])
def test_same_line_logical_chains_keep_conservative_findings(operator):
    # Same-line chains are outside this patch's line/semicolon assignment grammar.
    content = f'true {operator} TOKEN="$(printenv TOKEN)"\n'
    assert not _shell_credential_read_spans(Path("scripts/start.sh"), content)
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) == 1


@pytest.mark.parametrize(
    "content",
    [
        "TOKEN='\nTOKEN=\"$(printenv TOKEN)\"\nactual-pass-937\n'",
        "TOKEN='x; TOKEN=\"$(printenv TOKEN)\"; actual-pass-937'",
        'TOKEN="\nTOKEN="$(printenv TOKEN)"\nactual-pass-937\n"',
        'TOKEN=actual-pass-937\\\nTOKEN="$(printenv TOKEN)"',
        'TOKEN=actual-pass-937\\;TOKEN="$(printenv TOKEN)"',
        "cat <<'EOF'\nTOKEN=\"$(printenv TOKEN)\"\nactual-pass-937\nEOF\n",
        'cat <<EOF\nTOKEN="$(printenv TOKEN)"\nactual-pass-937\nEOF\n',
        'cat <<"EOF"\nTOKEN="$(printenv TOKEN)"\nactual-pass-937\nEOF\n',
        'cat <<-EOF\n\tTOKEN="$(printenv TOKEN)"\nactual-pass-937\n\tEOF\n',
        'cat <<unusual-delimiter\nTOKEN="$(printenv TOKEN)"\nactual-pass-937\nunusual-delimiter\n',
        "TOKEN=`printf 'TOKEN=\"$(printenv TOKEN)\"'`",
        "TOKEN=$'prefix\\'\nTOKEN=\"$(printenv TOKEN)\"\nsuffix'",
        "VALUE=\\\n#'\nTOKEN=\"$(printenv TOKEN)\"\nactual-pass-937'",
        "VALUE=x\u00a0#'\nTOKEN=\"$(printenv TOKEN)\"\nactual-pass-937'",
    ],
)
def test_literal_payloads_and_escaped_separators_do_not_create_assignments(content):
    assert not _shell_credential_read_spans(Path("scripts/start.sh"), content)
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is not None


@pytest.mark.parametrize(
    "prefix",
    [
        "# A comment may contain 'quotes, `backticks` and <<heredoc text.\n",
        "VALUE='a multiline\nvalue with a literal backslash \\';\n",
        'VALUE="a multiline\nvalue"\n',
        'VALUE="$(cd "$(dirname "$0")/.." && pwd)/suffix"\n',
        "VALUE=\"$(printf '%s' \"$(printf 'nested')\")\"\n",
        'VALUE="${DIRECTORY:-/tmp}/$(date +%s)"\n',
        'VALUE="${TOKEN_NAME:-$OTHER_NAME}"\n',
    ],
)
def test_completed_contexts_and_comments_preserve_later_real_assignments(prefix):
    content = prefix + 'TOKEN="$(printenv TOKEN)"\n'
    assert len(_shell_credential_read_spans(Path("scripts/start.sh"), content)) == 1
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is None


@pytest.mark.parametrize(
    "parameter",
    [
        '${PASSWORD:+-H "X-Header: ${PASSWORD}"}',
        '${OPTION:-"a } brace, a # hash and ${OTHER}"}',
        '${OPTION:+"header: ${OTHER}" extra}',
    ],
)
def test_closed_conditional_parameters_allow_later_unrelated_reads(parameter):
    content = f'RESPONSE="$(curl {parameter} /path)"\nTOKEN="$(printenv TOKEN)"\n'
    assert len(_shell_credential_read_spans(Path("scripts/start.sh"), content)) == 1
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is None


@pytest.mark.parametrize(
    "prefix",
    [
        '${OPTION:+"prefix\n',
        '${OPTION:+"prefix"\n',
        '${OPTION:+"prefix \\"}\n',
        "${OPTION:+'prefix\n",
        "${OPTION:+$(printf 'prefix')\n",
        '${OPTION:+"${OTHER:-"nested"}"\n',
        "VALUE=\"${OPTION:-$(printf 'unclosed')}\n",
        'VALUE="${OPTION:-$$UNRECOGNIZED}\n',
        "${OPTION:-$$UNRECOGNIZED}\n",
        "${OPTION:-$[1 + 2]}\n",
        '${OPTION:+"prefix" # not a shell comment }\'\n',
    ],
)
def test_ambiguous_or_unclosed_parameter_contexts_keep_findings(prefix):
    content = prefix + 'TOKEN="$(printenv TOKEN)"\nactual-pass-937\n'
    assert not _shell_credential_read_spans(Path("scripts/start.sh"), content)
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is not None


def test_read_shaped_text_inside_a_closed_parameter_is_not_an_assignment():
    content = '${OPTION:+"prefix\nTOKEN="$(printenv TOKEN)"\nactual-pass-937"}\n'
    assert not _shell_credential_read_spans(Path("scripts/start.sh"), content)
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is not None


@pytest.mark.parametrize(
    "content",
    [
        'TOKEN="literal-937$(printenv TOKEN)"',
        'TOKEN="$(printenv TOKEN)literal-937"',
        'TOKEN="$(printenv TOKEN)"literal-937',
        'TOKEN="$(printenv TOKEN)"#literal-937',
        'TOKEN="$(gcloud auth print-access-token)"#literal-937',
        "TOKEN=\"$(printenv TOKEN)\"'literal-937'",
        'TOKEN="$(printenv TOKEN)"\\\nliteral-937',
        'TOKEN="$(printenv TOKEN; printf actual-pass-937)"',
        'TOKEN="$(printenv TOKEN || echo actual-pass-937)"',
        'TOKEN="$(printenv ${TOKEN:-actual-pass-937})"',
        'TOKEN="$(printenv TOKEN OTHER_TOKEN)"',
        'TOKEN="$(printenv TOKEN 2>/tmp/capture)"',
        'TOKEN="$(gcloud auth print-access-token --token=actual-pass-937)"',
        'TOKEN="$(gcloud auth print-access-token --flags-file=/tmp/flags)"',
        'TOKEN="$(gcloud auth print-access-token --project="${PROJECT:-actual-pass-937}")"',
        'TOKEN="$(gcloud auth print-access-token --project="$(printf actual-pass-937)")"',
        'TOKEN="$(gcloud auth print-access-token | echo actual-pass-937)"',
        'TOKEN="$(printf actual-pass-937)"',
        'TOKEN="$(printenv TOKEN)',
        "TOKEN='$(printenv TOKEN)'",
        'TOKEN="\\$(printenv TOKEN)"',
        'TOKEN="$(printenv TOKEN)\\"literal-937"',
        'const token = "$(printenv TOKEN)"',
    ],
)
def test_literal_mixed_or_unrecognized_values_still_fire(content):
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) is not None


@pytest.mark.parametrize("path", ["src/config.py", "src/config.ts", "config.json", "README.md"])
def test_shell_syntax_outside_a_shell_context_is_not_exempt(path):
    assert _first_hardcoded_secret_line(Path(path), 'TOKEN="$(printenv TOKEN)"') == 1


@pytest.mark.parametrize("language", ["python", "typescript", "", "bashful"])
def test_documentation_language_cannot_hide_a_literal(language):
    content = f'```{language}\nTOKEN="$(printenv TOKEN)"\n + "actual-pass-937"\n```\n'
    assert _first_hardcoded_secret_line(Path("README.md"), content) == 2


def test_unclosed_shell_fence_is_not_exempt():
    assert _first_hardcoded_secret_line(Path("README.md"), '```bash\nTOKEN="$(printenv TOKEN)"\n') == 2


def test_shell_fence_does_not_exempt_later_non_shell_text():
    content = '```sh\nTOKEN="$(printenv TOKEN)"\n```\n```python\ntoken="$(printenv TOKEN)"\n```\n'
    assert _first_hardcoded_secret_line(Path("README.md"), content) == 5


def test_credential_read_does_not_hide_adjacent_literal_or_provider_secret():
    prefix = 'TOKEN="$(printenv TOKEN)"\n'
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), prefix + 'password="actual-pass-937"') == 2
    # Synthetic regression payload, not a credential.
    provider = "ghp_" + "Q7vN2mL9rT5xB8cD1fG6hJ3kP4sW0zY2uA9b"
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), prefix.rstrip() + f" # {provider}") == 1


def test_future_broader_detector_cannot_cross_a_credential_read():
    content = 'TOKEN="$(printenv TOKEN)"\npassword="actual-pass-937"'
    detector = SecretPattern(re.compile(r'TOKEN="(.+)"', re.DOTALL), kind="generic", value_group=1)
    match = detector.pattern.search(content)
    assert match is not None
    assert not _should_skip_secret_match(
        Path("scripts/start.sh"),
        content,
        detector,
        match,
        shell_read_spans=_shell_credential_read_spans(Path("scripts/start.sh"), content),
    )
