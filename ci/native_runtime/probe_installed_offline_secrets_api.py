"""Resolve the installed Secrets entry point without freezing its dependencies."""

from __future__ import annotations


def probe_api():
    from . import probe_installed_offline_secrets

    return probe_installed_offline_secrets
