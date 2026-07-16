"""Structured curl operation parsing for command safety matchers."""

from __future__ import annotations

CURL_SHORT_OPTIONS_WITH_VALUES = frozenset(
    {
        "A",
        "b",
        "c",
        "C",
        "d",
        "D",
        "e",
        "E",
        "F",
        "H",
        "K",
        "m",
        "o",
        "P",
        "Q",
        "r",
        "t",
        "T",
        "u",
        "U",
        "w",
        "x",
        "X",
        "y",
        "Y",
        "z",
    }
)
CURL_LONG_OPTIONS_WITH_VALUES = frozenset(
    {
        "--abstract-unix-socket",
        "--alt-svc",
        "--aws-sigv4",
        "--cacert",
        "--capath",
        "--cert",
        "--cert-type",
        "--ciphers",
        "--config",
        "--connect-timeout",
        "--connect-to",
        "--cookie",
        "--cookie-jar",
        "--create-file-mode",
        "--crlfile",
        "--curves",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--delegation",
        "--dns-interface",
        "--dns-ipv4-addr",
        "--dns-ipv6-addr",
        "--dns-servers",
        "--doh-url",
        "--dump-header",
        "--ech",
        "--egd-file",
        "--engine",
        "--etag-compare",
        "--etag-save",
        "--expect100-timeout",
        "--form",
        "--form-string",
        "--ftp-account",
        "--ftp-alternative-to-user",
        "--ftp-method",
        "--ftp-port",
        "--ftp-ssl-ccc-mode",
        "--happy-eyeballs-timeout-ms",
        "--haproxy-clientip",
        "--header",
        "--hostpubmd5",
        "--hostpubsha256",
        "--hsts",
        "--interface",
        "--ip-tos",
        "--ipfs-gateway",
        "--json",
        "--keepalive-time",
        "--keepalive-cnt",
        "--key",
        "--key-type",
        "--krb",
        "--libcurl",
        "--limit-rate",
        "--local-port",
        "--login-options",
        "--mail-auth",
        "--mail-from",
        "--mail-rcpt",
        "--max-filesize",
        "--max-redirs",
        "--max-time",
        "--netrc-file",
        "--noproxy",
        "--oauth2-bearer",
        "--output",
        "--output-dir",
        "--parallel-max",
        "--parallel-max-host",
        "--pass",
        "--pinnedpubkey",
        "--preproxy",
        "--proto",
        "--proto-default",
        "--proto-redir",
        "--proxy",
        "--proxy-cacert",
        "--proxy-capath",
        "--proxy-cert",
        "--proxy-cert-type",
        "--proxy-ciphers",
        "--proxy-crlfile",
        "--proxy-header",
        "--proxy-key",
        "--proxy-key-type",
        "--proxy-pass",
        "--proxy-pinnedpubkey",
        "--proxy-service-name",
        "--proxy-tls13-ciphers",
        "--proxy-tlsauthtype",
        "--proxy-tlspassword",
        "--proxy-tlsuser",
        "--proxy-user",
        "--proxy1.0",
        "--pubkey",
        "--quote",
        "--random-file",
        "--range",
        "--rate",
        "--referer",
        "--request-target",
        "--resolve",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--sasl-authzid",
        "--service-name",
        "--speed-limit",
        "--speed-time",
        "--socks4",
        "--socks4a",
        "--socks5",
        "--socks5-hostname",
        "--socks5-gssapi-service",
        "--stderr",
        "--telnet-option",
        "--tftp-blksize",
        "--tls-max",
        "--tls-earlydata",
        "--tls13-ciphers",
        "--tlsauthtype",
        "--tlspassword",
        "--tlsuser",
        "--time-cond",
        "--trace",
        "--trace-ascii",
        "--trace-config",
        "--unix-socket",
        "--upload-file",
        "--upload-flags",
        "--user",
        "--user-agent",
        "--url-query",
        "--variable",
        "--vlan-priority",
        "--write-out",
    }
)


def curl_operations(arguments: tuple[str, ...]) -> tuple[tuple[str | None, tuple[str, ...]], ...]:
    """Return request methods and URL targets grouped by curl operation."""

    operations: list[tuple[str | None, tuple[str, ...]]] = []
    method: str | None = None
    targets: list[str] = []
    index = 0
    parse_options = True
    while index < len(arguments):
        argument = arguments[index]
        lowered = argument.lower()
        if parse_options and argument == "--":
            parse_options = False
            index += 1
            continue
        if not parse_options:
            targets.append(argument.strip("'\""))
            index += 1
            continue
        if lowered == "--next":
            operations.append((method, tuple(targets)))
            method = None
            targets = []
            index += 1
            continue
        if lowered == "--request" and index + 1 < len(arguments):
            method = arguments[index + 1].lower()
            index += 2
            continue
        if lowered.startswith("--request="):
            method = argument.split("=", 1)[1].lower()
            index += 1
            continue
        if lowered == "--url" and index + 1 < len(arguments):
            targets.append(arguments[index + 1].strip("'\""))
            index += 2
            continue
        if lowered.startswith("--url="):
            targets.append(argument.split("=", 1)[1].strip("'\""))
            index += 1
            continue
        long_option = lowered.split("=", 1)[0]
        if long_option in CURL_LONG_OPTIONS_WITH_VALUES:
            index += 1 if "=" in argument else 2
            continue
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 1:
            consumed_next = False
            for offset, short_option in enumerate(argument[1:], start=1):
                if short_option not in CURL_SHORT_OPTIONS_WITH_VALUES:
                    continue
                attached_value = argument[offset + 1 :]
                if not attached_value and index + 1 < len(arguments):
                    attached_value = arguments[index + 1]
                    consumed_next = True
                if short_option == "X":
                    method = attached_value.lower()
                break
            index += 2 if consumed_next else 1
            continue
        if not argument.startswith("-"):
            targets.append(argument.strip("'\""))
        index += 1
    operations.append((method, tuple(targets)))
    return tuple(operations)
