r"""The CPython oracle the inventory URL-redaction corpus is recorded from.

These three functions were `inventory_contract_redaction`'s URL half until the
resident took the grammar over. The corpus in
`rust/crates/guard-command/testdata/inventory_url_parity.json` exists to prove
the Rust port reproduces CPython's `urllib.parse`, so it has to be recorded
from CPython. Asking the runtime that the corpus pins would pin that runtime
against itself and prove nothing.

This is generator tooling, not runtime code: nothing under `src/` imports it,
and a Guard install never runs it. Keep it byte-for-byte what the module did
on the interpreter named in the fixture's `python_version`, and change it only
to track a deliberate change in the redaction contract, alongside the Rust
owner and a regenerated fixture.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

#: `_SENSITIVE_KEY_RE` as the module spelled it while it owned these bodies.
_SENSITIVE_KEY_RE = re.compile(
    r"(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)",
    re.IGNORECASE,
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Preserve header names while redacting credential-bearing header values."""
    return {key.lower(): "present_redacted" if _SENSITIVE_KEY_RE.search(key) else "present" for key in headers}


def redact_url(value: str) -> str:
    """Remove sensitive URL credentials and query values before exporting an endpoint."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "malformed_url_redacted"
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    redacted_pairs = [
        (key, "redacted" if _SENSITIVE_KEY_RE.search(key) else item)
        for key, item in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(redacted_pairs), parsed.fragment))


def classify_endpoint_host(value: str | None) -> Literal["none", "local_loopback", "local_private", "remote_public"]:
    """Classify an endpoint host without making a network request."""
    if not value:
        return "none"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "remote_public"
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "local_loopback"
    try:
        if ipaddress.ip_address(host).is_private:
            return "local_private"
    except ValueError:
        pass
    return "remote_public"
