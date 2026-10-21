"""Regenerate the `artifact_hash_url` parity corpus.

`GuardArtifact.to_dict` redacts a url by round-tripping it through
`urlsplit`/`parse_qsl`/`urlencode`/`urlunsplit`, and the artifact hash is taken
over the result, so the native helpers have to reproduce CPython's answer byte
for byte. This records that answer for a small corpus covering each branch, and
the Rust tests assert their own answer matches.

`parse_qsl` is recorded with `keep_blank_values=True` because that is what
`guard/models.py` passes; the default drops a bare or empty-valued key, which
would quietly change which query a redacted url ends up carrying.

Run it from the repository root with the pinned Python 3.12 after changing
either side:

    python scripts/ci/generate_artifact_hash_url_parity.py [output-path]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

FIXTURE = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "rust/crates/guard-command/testdata/artifact_hash_url_parity.json"
)

# Each query names a shape the pair parser has to keep: an empty query, repeated
# keys, a bare key, an empty value, an empty name, both escape spellings, and an
# empty segment between separators.
QUERIES: list[str] = [
    "",
    "a=1",
    "a=1&b=2",
    "a=1&a=2",
    "a",
    "a=",
    "=1",
    "a=%20b",
    "a+b=c+d",
    "a=1&&b=2",
]

# Urls whose split-then-unsplit answer has to come back unchanged.
URLS: list[str] = [
    "https://example.test/a/b?x=1&y=2#frag",
    "http://example.test",
    "//example.test/p",
    "/just/a/path",
    "relative/path",
    "mailto:user@example.test",
    "http://example.test/p?a=1#f",
    "?only=query",
    "#only-fragment",
    "",
]

# Split tuples that pin which arm of `urlunsplit` adds a `//` separator.
UNSPLIT: list[tuple[str, str, str, str, str]] = [
    ("", "", "", "", ""),
    ("", "", "//path", "", ""),
    ("", "", "//path", "a=1", ""),
    ("", "", "///triple", "", ""),
    ("", "", "path", "", ""),
    ("", "", "/path", "", ""),
    ("http", "", "", "", ""),
    ("http", "", "path", "", ""),
    ("http", "", "/path", "", ""),
    ("http", "", "//path", "", ""),
    ("http", "example.test", "", "", ""),
    ("http", "example.test", "path", "", ""),
    ("http", "example.test", "/path", "", ""),
    ("http", "example.test", "//path", "", ""),
    ("https", "example.test:8443", "/a/b", "x=1&y=2", "frag"),
    ("mailto", "", "user@example.test", "", ""),
    ("mailto", "", "//user@example.test", "", ""),
    ("news", "", "comp.lang.rust", "", ""),
    ("", "example.test", "/p", "", ""),
    ("file", "", "/etc/hosts", "", ""),
    ("file", "", "//etc/hosts", "", ""),
    ("ftp", "", "//host/p", "", ""),
    ("unknownscheme", "", "//path", "", ""),
    ("unknownscheme", "", "/path", "", ""),
    ("http", "example.test", "/p", "", "f"),
    ("http", "example.test", "/p", "q=1", ""),
]


def main() -> int:
    query = []
    for text in QUERIES:
        pairs = parse_qsl(text, keep_blank_values=True)
        query.append(
            {"query": text, "pairs": [list(pair) for pair in pairs], "encoded": urlencode(pairs)}
        )

    roundtrip = []
    for url in URLS:
        split = urlsplit(url)
        roundtrip.append(
            {
                "url": url,
                "scheme": split.scheme,
                "netloc": split.netloc,
                "path": split.path,
                "query": split.query,
                "fragment": split.fragment,
                "expected": urlunsplit(
                    (split.scheme, split.netloc, split.path, split.query, split.fragment)
                ),
            }
        )

    unsplit = []
    for scheme, netloc, path, text, fragment in UNSPLIT:
        unsplit.append(
            {
                "scheme": scheme,
                "netloc": netloc,
                "path": path,
                "query": text,
                "fragment": fragment,
                "expected": urlunsplit((scheme, netloc, path, text, fragment)),
            }
        )

    document = {"query": query, "roundtrip": roundtrip, "urlunsplit": unsplit}
    FIXTURE.write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
