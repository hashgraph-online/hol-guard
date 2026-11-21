"""Bound resident transport for Linux containment preparation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .native_restricted_pytest import restricted_native
from .runtime.restricted_linux_landlock import LinuxContainmentUnavailableError
from .runtime.restricted_pytest_model import RestrictedPytestError


def linux_native(operation: str, fields: Mapping[str, Any], expected: type | tuple[type, ...]) -> Any:
    try:
        return restricted_native(operation, fields, expected)
    except RestrictedPytestError as error:
        raise LinuxContainmentUnavailableError(str(error)) from error
