"""Environment-independent TLS trust construction for managed Guard networking."""

from __future__ import annotations

import os
import re
import ssl
import sys
from contextlib import suppress
from pathlib import Path

import requests.certs as requests_certs

from .managed_file_trust import machine_controlled_file_is_trusted


class ManagedTrustError(RuntimeError):
    """A managed TLS trust source is unavailable or invalid."""


def build_default_ssl_context() -> ssl.SSLContext:
    """Keep platform trust and explicit CA overrides usable in bundled runtimes."""
    context = ssl.create_default_context()
    if not os.environ.get("SSL_CERT_FILE") and not os.environ.get("SSL_CERT_DIR"):
        # Preserve platform trust; an empty context still fails TLS verification.
        with suppress(ManagedTrustError, OSError):
            context.load_verify_locations(cafile=str(_requests_ca_bundle()))
    return context


def _requests_ca_bundle() -> Path:
    where = getattr(requests_certs, "where", None)
    if not callable(where):
        raise ManagedTrustError("managed_system_trust_invalid")
    value = where()
    if not isinstance(value, str) or not value:
        raise ManagedTrustError("managed_system_trust_invalid")
    try:
        return Path(value).resolve(strict=True)
    except OSError as exc:
        raise ManagedTrustError("managed_system_trust_invalid") from exc


def _load_public_and_system_trust(context: ssl.SSLContext) -> None:
    """Load public and platform roots without honoring shell CA overrides."""

    public_bundle = _requests_ca_bundle()
    try:
        context.load_verify_locations(cafile=str(public_bundle))
    except (OSError, ssl.SSLError) as exc:
        raise ManagedTrustError("managed_system_trust_invalid") from exc

    if sys.platform == "win32":
        try:
            for store_name in ("ROOT", "CA"):
                for certificate, encoding, _trust in ssl.enum_certificates(store_name):
                    if encoding != "x509_asn":
                        continue
                    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate))
        except (OSError, ssl.SSLError) as exc:
            raise ManagedTrustError("managed_system_trust_invalid") from exc
        return

    defaults = ssl.get_default_verify_paths()
    system_cafile = Path(defaults.openssl_cafile) if defaults.openssl_cafile else None
    system_capath = Path(defaults.openssl_capath) if defaults.openssl_capath else None
    try:
        if system_cafile is not None and system_cafile.is_file() and system_cafile.resolve() != public_bundle:
            context.load_verify_locations(cafile=str(system_cafile))
        if system_capath is not None and system_capath.is_dir():
            context.load_verify_locations(capath=str(system_capath))
    except (OSError, ssl.SSLError) as exc:
        raise ManagedTrustError("managed_system_trust_invalid") from exc


def _validate_managed_ca_bundle(path_value: str) -> Path:
    bundle = Path(path_value)
    if not machine_controlled_file_is_trusted(bundle):
        raise ManagedTrustError("managed_ca_bundle_invalid")
    return bundle


def build_managed_ssl_context(ca_bundle_path: str | None) -> ssl.SSLContext:
    """Build mandatory TLS verification with additive administrator-managed trust."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    _load_public_and_system_trust(context)
    if ca_bundle_path is not None:
        bundle = _validate_managed_ca_bundle(ca_bundle_path)
        try:
            context.load_verify_locations(cafile=str(bundle))
        except (OSError, ssl.SSLError) as exc:
            raise ManagedTrustError("managed_ca_bundle_invalid") from exc
    return context


def export_managed_trust_roots(context: ssl.SSLContext) -> list[bytes]:
    """Materialize platform capath roots before exporting trust to native TLS.

    OpenSSL loads hashed-directory roots lazily. Use the same compiled default
    directory as managed trust, ignoring shell CA overrides and unrelated files.
    """
    if sys.platform != "win32":
        directory = ssl.get_default_verify_paths().openssl_capath
        if directory and Path(directory).is_dir():
            try:
                with os.scandir(directory) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 4096:
                            raise ManagedTrustError("managed_system_trust_invalid")
                        if re.fullmatch(r"[0-9a-fA-F]{8}\.[0-9]+", entry.name) is None:
                            continue
                        with open(entry.path, "rb") as certificate:
                            data = certificate.read(128 * 1024 + 1)
                        if len(data) > 128 * 1024:
                            raise ManagedTrustError("managed_system_trust_invalid")
                        context.load_verify_locations(
                            cadata=data.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in data else data
                        )
            except (OSError, ssl.SSLError, UnicodeError) as exc:
                raise ManagedTrustError("managed_system_trust_invalid") from exc
    roots = context.get_ca_certs(binary_form=True)
    if len(roots) > 1024 or any(len(root) > 16 * 1024 for root in roots):
        raise ManagedTrustError("managed_system_trust_invalid")
    return roots


__all__ = ["ManagedTrustError", "build_managed_ssl_context", "export_managed_trust_roots"]
