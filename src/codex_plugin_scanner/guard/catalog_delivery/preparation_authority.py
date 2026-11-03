"""Explicit authenticated preparation profiles, never authority from cache hashes."""

from __future__ import annotations

from importlib import import_module

from .authority import VerifiedDistribution
from .pack_store import PackReader, decode


def installed_bundle_type():
    try:
        module = import_module(".installed_bundle", __package__)
    except ModuleNotFoundError as exc:
        if exc.name != f"{__package__}.installed_bundle":
            raise
        return ()
    return module.VerifiedInstalledBundle


def load_installed_bundle():
    module = import_module(".installed_bundle", __package__)
    return module.load_installed_bundle() if module.advertised() else None


def publication(authority):
    from .activation_record import CommittedCommandPacks

    if type(authority) is VerifiedDistribution:
        return authority.manifest(), authority.data, authority.digest, "remote"
    if type(authority) is installed_bundle_type():
        return authority.manifest(), authority.data, authority.digest, "installed"
    if type(authority) is CommittedCommandPacks:
        record = authority.record()
        data = PackReader(authority.directory / "objects").blob(record["distribution"])
        return decode(data), data, record["root_digest"], "committed-subset"
    raise ValueError("pack preparation requires an authenticated publication")
