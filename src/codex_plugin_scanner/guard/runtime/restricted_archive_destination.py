"""Canonical URL, public-address, and DNS policy for archive egress."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import urllib.parse

from .restricted_archive_contract import _CanonicalDestination, _RestrictedDownloadError
from .restricted_archive_deadline import _remaining_seconds

_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "100.100.100.200"})
_DNS_RESOLVER_SLOTS = threading.BoundedSemaphore(value=2)


def _canonical_destination(url: str) -> _CanonicalDestination:
    if not url or _CONTROL_OR_SPACE_RE.search(url) or "\\" in url:
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        )
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or 443
    except ValueError:
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        ) from None
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not 1 <= port <= 65535
        or _INVALID_PERCENT_ESCAPE_RE.search(parsed.path)
        or _INVALID_PERCENT_ESCAPE_RE.search(parsed.query)
    ):
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        )
    raw_hostname = parsed.hostname.rstrip(".")
    if not raw_hostname or "%" in raw_hostname:
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        )
    try:
        hostname = raw_hostname.encode("ascii").decode("ascii").lower()
    except UnicodeError:
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination uses an ambiguous non-ASCII hostname.",
        ) from None
    try:
        parsed_address = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_address = None
    if parsed_address is None and (
        len(hostname) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in hostname.split(".")
        )
    ):
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        )
    path = urllib.parse.quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
    query = urllib.parse.quote(parsed.query, safe="/%?:@-._~!$&'()*+,;=")
    is_ipv6 = False
    if parsed_address is not None:
        is_ipv6 = parsed_address.version == 6
    rendered_hostname = f"[{hostname}]" if is_ipv6 else hostname
    netloc = rendered_hostname if port == 443 else f"{rendered_hostname}:{port}"
    canonical_url = urllib.parse.urlunsplit(("https", netloc, path, query, ""))
    request_target = urllib.parse.urlunsplit(("", "", path, query, ""))
    return _CanonicalDestination(
        url=canonical_url,
        hostname=hostname,
        port=port,
        request_target=request_target,
        host_header=netloc,
    )


def is_external_https_archive_source(source_url: str) -> bool:
    """Return whether a package source belongs to the approved-archive pipeline."""

    normalized = source_url.strip()
    # npm treats slashless, single-slash, and backslash spellings after an
    # HTTPS scheme as remote fetches.  Classify them here so they can never
    # fall through to the ordinary registry-install path; the strict
    # destination validator below rejects the non-canonical spelling before
    # approval or network access.
    if not normalized.lower().startswith("https:"):
        return False
    try:
        parsed = urllib.parse.urlsplit(normalized)
        hostname = parsed.hostname
    except ValueError:
        # A parse failure must still enter the restricted route so the strict
        # canonical validator rejects it. Returning False here would let an
        # ambiguous HTTPS-like npm source fall through to an ordinary install.
        return True
    # Every npm HTTPS-like spelling belongs to the restricted archive path
    # unless it is the exact canonical npm registry host.  In particular,
    # Node normalizes extra slash/backslash spellings that urllib parses with
    # no hostname; those must be classified here and rejected by the strict
    # canonical validator rather than falling through to ordinary installs.
    return not (
        parsed.scheme.lower() == "https"
        and hostname is not None
        and hostname.lower().rstrip(".") == "registry.npmjs.org"
    )


def canonical_external_https_archive_source(source_url: str) -> str | None:
    """Return the restricted canonical destination, or ``None`` if rejected."""

    try:
        return _canonical_destination(source_url).url
    except _RestrictedDownloadError:
        return None


def _address_is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return _address_is_public(address.ipv4_mapped)
        if address.sixtofour is not None and not _address_is_public(address.sixtofour):
            return False
        if address.teredo is not None and not _address_is_public(address.teredo[1]):
            return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and str(address) not in _METADATA_ADDRESSES
    )


def _resolve_public_addresses(destination: _CanonicalDestination, *, deadline: float) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(destination.hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not _address_is_public(literal):
            raise _RestrictedDownloadError(
                "external_archive_destination_rejected",
                "External archive destination resolved to a non-public address.",
            )
        return (str(literal),)

    results: list[object] = []
    errors: list[BaseException] = []
    if not _DNS_RESOLVER_SLOTS.acquire(blocking=False):
        raise _RestrictedDownloadError(
            "external_archive_dns_timeout",
            "External archive DNS resolver capacity is unavailable.",
        )

    def resolve() -> None:
        try:
            results.append(
                socket.getaddrinfo(
                    destination.hostname,
                    destination.port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            )
        except BaseException as error:  # pragma: no cover - transferred to caller
            errors.append(error)
        finally:
            _DNS_RESOLVER_SLOTS.release()

    resolver = threading.Thread(target=resolve, name="guard-archive-dns", daemon=True)
    try:
        resolver.start()
    except RuntimeError:
        _DNS_RESOLVER_SLOTS.release()
        raise _RestrictedDownloadError(
            "external_archive_dns_unresolved",
            "External archive DNS resolver could not be started.",
        ) from None
    resolver.join(_remaining_seconds(deadline))
    if resolver.is_alive():
        raise _RestrictedDownloadError(
            "external_archive_dns_timeout",
            "External archive destination DNS resolution timed out.",
        )
    if errors or not results:
        raise _RestrictedDownloadError(
            "external_archive_dns_unresolved",
            "External archive destination could not be resolved.",
        )
    resolved_items = results[0]
    if not isinstance(resolved_items, list):
        raise _RestrictedDownloadError(
            "external_archive_dns_unresolved",
            "External archive destination returned an invalid DNS response.",
        )
    addresses: dict[bytes, str] = {}
    rejected_non_public = False
    for item in resolved_items:
        if not isinstance(item, tuple):
            continue
        if len(item) < 5 or not isinstance(item[4], tuple) or not item[4]:
            continue
        raw_address = item[4][0]
        if not isinstance(raw_address, str):
            continue
        try:
            address = ipaddress.ip_address(raw_address.split("%", 1)[0])
        except ValueError:
            raise _RestrictedDownloadError(
                "external_archive_dns_unresolved",
                "External archive destination returned an invalid DNS address.",
            ) from None
        if not _address_is_public(address):
            rejected_non_public = True
            continue
        _ = addresses.setdefault(bytes([address.version]) + address.packed, str(address))
    if rejected_non_public and addresses:
        raise _RestrictedDownloadError(
            "external_archive_dns_ambiguous",
            "External archive destination returned mixed public and non-public DNS addresses.",
        )
    if rejected_non_public:
        raise _RestrictedDownloadError(
            "external_archive_destination_rejected",
            "External archive destination resolved to a non-public address.",
        )
    if not addresses:
        raise _RestrictedDownloadError(
            "external_archive_dns_unresolved",
            "External archive destination did not resolve to a usable public address.",
        )
    return tuple(addresses[key] for key in sorted(addresses))


def _same_ip(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left.split("%", 1)[0]) == ipaddress.ip_address(right.split("%", 1)[0])
    except ValueError:
        return False
