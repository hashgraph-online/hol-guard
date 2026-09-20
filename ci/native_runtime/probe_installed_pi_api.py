"""Resolve the installed probe entry point without freezing injected dependencies."""

from __future__ import annotations


def probe_api():
    from . import probe_installed_pi_output

    return probe_installed_pi_output
