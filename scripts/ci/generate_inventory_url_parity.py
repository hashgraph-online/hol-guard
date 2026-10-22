r"""Record the inventory URL-redaction corpus the Rust port must match.

`inventory_contract_redaction.redact_url` and `classify_endpoint_host` push an
untrusted endpoint string through CPython's `urllib.parse`, so the port has to
reproduce that parser rather than an RFC-correct one. Four behaviours decide
the output and none of them is the Rust default:

1. `urlsplit` only *lstrips* the C0-control-or-space set and then deletes every
   tab, CR and LF anywhere in the URL, so `"ht\ntp://h/"` parses with scheme
   `http` while a trailing space survives into the path.
2. `urlsplit` raises for a half-bracketed netloc, a bracketed host that is
   neither IPvFuture nor IPv6, and a netloc whose NFKC normalization grows a
   URL delimiter. `.port` raises separately, and `redact_url` swallows only
   that second error.
3. `unquote` decodes each maximal ASCII run on its own with `errors="replace"`,
   so a `%C3` escape never combines with a following literal non-ASCII
   character, and `quote_plus` escapes everything outside `[A-Za-z0-9_.~-]`.
4. `IPv6Address.is_private` delegates to the mapped IPv4 address when there is
   one, so `::ffff:10.0.0.1` classifies `local_private` while `::ffff:8.8.8.8`
   does not.

Run this after changing the URL half of the redaction module and commit the
regenerated fixture; `python_url_tests.rs` and `inventory_redaction_tests.rs`
read it. Run it from the repository root on the interpreter the project
targets. `urllib.parse` is not frozen across releases, so a different
interpreter would record cases the port was never written against and the
fixture would still look green:

    uv run --python 3.12 --no-project python \
        scripts/ci/generate_inventory_url_parity.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from codex_plugin_scanner.guard.inventory_contract_redaction import (
    classify_endpoint_host,
    redact_headers,
    redact_url,
)

FIXTURE = Path("rust/crates/guard-command/testdata/inventory_url_parity.json")
SCRIPT = "scripts/ci/generate_inventory_url_parity.py"

#: The release the Rust port models, and the one the rest of the repository
#: pins its parity generators and CI environments to (`uv ... --python 3.12`).
TARGET_PYTHON = (3, 12)

SPLIT_URLS: list[str] = [
    "https://example.test/path?a=1#frag",
    "HTTPS://Example.TEST:8443/Path",
    "  \t https://example.test/leading",
    "https://example.test/trailing ",
    "ht\ntp://example.test/newline-in-scheme",
    "htt\tps://example.test/tab-in-scheme",
    "1http://example.test/digit-scheme",
    "+http://example.test/plus-scheme",
    "mailto:person@example.test",
    "//example.test/scheme-relative",
    "/just/a/path",
    "https://user:pw@example.test/userinfo",
    "https://user@host@example.test/double-at",
    "https://[::1]:8080/bracketed",
    "https://[::1]/bracketed-no-port",
    "https://[v7.future]/ipvfuture",
    "https://[::1/unclosed",
    "https://::1]/unopened",
    "https://[127.0.0.1]/bracketed-ipv4",
    "https://[not-an-address]/bracketed-name",
    "https://[::1]extra/trailing-after-bracket",
    "https://example.test:port/non-numeric",
    "https://example.test:99999/out-of-range",
    "https://example.test:/empty-port",
    "https://example.test:0/zero-port",
    "https://example.test:65535/max-port",
    "https://example.test:+80/signed-port",
    "https://exam℀ple.test/nfkc-grows-delimiter",
    "https://ümlaut.test/plain-non-ascii",
    "https://fe80::1%25eth0/zone",
    "https://example.test?query-without-path",
    "https://example.test#fragment-without-path",
    "https://example.test/both?a=1&a=2#f",
    "unknownscheme://example.test/path",
    "git+ssh://example.test/repo.git",
    "",
    "https://",
    "https:///empty-netloc",
    # `urlunsplit` rebuilds an empty netloc differently across CPython patch
    # releases; these pin the behaviour of the version CI runs.
    "https:////double-slash-path",
    "https:relative-path",
    "https:",
]

REDACT_URLS: list[str] = [
    "https://example.test/path?token=abc123&page=2",
    "https://example.test/path?TOKEN=abc123",
    "https://example.test/path?api-key=abc&api_key=def&apiXkey=ghi",
    "https://example.test/path?authorization=Bearer+abc",
    "https://user:hunter2@example.test/path",
    "https://example.test:8443/path?a=1;b=2",
    "https://example.test/path?blank=&novalue&=orphan",
    # CPython `re.IGNORECASE` folds U+0131 onto `i`, so this key is sensitive.
    "https://example.test/path?credent%C4%B1al=hunter2",
    "https://example.test/path?t%C4%B1ken=hunter2",
    "https://example.test/path?name=a%20b%2Bc",
    "https://example.test/path?name=%C3%A9caf%C3%A9",
    "https://example.test/path?name=%C3é",
    "https://example.test/path?name=%zz",
    "https://example.test/path?name=a+b",
    "https://example.test/path?secret=%F0%9F%94%91",
    "https://[::1]:9000/path?token=x",
    "https://example.test:99999/path?token=x",
    "https://[::1/unclosed?token=x",
    "https://exam℀ple.test/path",
    "ftp://example.test/pub",
    "unknownscheme://example.test/path?token=x",
    "mailto:person@example.test",
    "/relative/path?token=x",
    "//example.test/scheme-relative?token=x",
    "https://example.test/path#frag?not-a-query",
    "https://example.test/sp ace?token=x",
    # `redact_url` rebuilds through `urlunsplit`, whose empty-netloc rules
    # changed across CPython patch releases; pin the version CI runs.
    "https:////double-slash-path?token=x",
    "https:relative-path?token=x",
    "",
]

CLASSIFY_HOSTS: list[str | None] = [
    None,
    "",
    "https://localhost:3000/api",
    "http://127.0.0.1/api",
    "http://[::1]/api",
    "http://LOCALHOST/api",
    "http://10.0.0.5/api",
    "http://172.16.0.1/api",
    "http://192.168.1.1/api",
    "http://192.0.0.9/api",
    "http://192.0.0.10/api",
    "http://8.8.8.8/api",
    "http://[fd00::1]/api",
    "http://[fe80::1]/api",
    "http://[::ffff:10.0.0.1]/api",
    "http://[::ffff:8.8.8.8]/api",
    "http://[2001:4860:4860::8888]/api",
    "https://example.test/api",
    "https://[::1/unclosed",
    "http://127.0.0.01/leading-zero-octet",
    "not-a-url",
    "http://[fe80::1%25eth0]/zone",
]

HEADER_NAMES: list[list[str]] = [
    [],
    ["Content-Type", "Accept"],
    ["Authorization", "X-Api-Key", "Cookie"],
    ["Authorization", "authorization"],
    ["X-Auth-Token", "x-bearer", "x-password", "x-credential", "x-secret"],
    ["apiXkey", "api-key", "api_key"],
    ["X-Credent\u0131al", "X-T\u0131ken"],
]


def _split_case(url: str) -> dict[str, object]:
    """Record `urlsplit` plus the two accessors `redact_url` reads."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {"url": url, "error": True}
    try:
        port: int | None = parsed.port
    except ValueError:
        port_error = True
        port = None
    else:
        port_error = False
    return {
        "url": url,
        "error": False,
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "hostname": parsed.hostname,
        "port": port,
        "port_error": port_error,
    }


def _require_target_interpreter() -> str:
    """Return the running version, refusing anything but the modeled release."""
    running = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] != TARGET_PYTHON:
        target = ".".join(str(part) for part in TARGET_PYTHON)
        raise SystemExit(
            f"this corpus models CPython {target} and is running on {running}; "
            f"rerun it as: uv run --python {target} --no-project python {SCRIPT}"
        )
    return running


def build_document() -> dict[str, object]:
    """Collect every recorded URL behaviour into the fixture payload."""
    return {
        "python_version": _require_target_interpreter(),
        "classify_endpoint_host": [
            {"value": value, "expected": classify_endpoint_host(value)} for value in CLASSIFY_HOSTS
        ],
        "redact_headers": [
            {"names": names, "expected": list(redact_headers(dict.fromkeys(names, "value")).items())}
            for names in HEADER_NAMES
        ],
        "redact_url": [{"url": url, "expected": redact_url(url)} for url in REDACT_URLS],
        "urlsplit": [_split_case(url) for url in SPLIT_URLS],
    }


def main() -> None:
    """Write the parity fixture the Rust URL tests read."""
    document = build_document()
    FIXTURE.write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
