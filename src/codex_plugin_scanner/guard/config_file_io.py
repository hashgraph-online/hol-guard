"""Errors for Guard configuration files read by the native runtime."""

from __future__ import annotations


class ConfigFileTrustError(ValueError):
    """An existing configuration file could not be read with stable containment."""
