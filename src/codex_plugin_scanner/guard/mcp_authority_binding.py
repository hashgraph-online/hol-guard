"""Private exact MCP authority checks; no policy results or risk cache."""

from __future__ import annotations

import math
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, fields
from hashlib import sha256
from pathlib import PosixPath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import cast

from .adapters.base import HarnessContext
from .config import GuardConfig
from .mdm.contracts import ManagedIntegrityTrust, ManagedNetworkPolicy, ManagedPolicy, ManagedUpdatePolicy
from .models import GuardArtifact
from .runtime.mcp_protection import McpServerIdentity

AuthorityCheck = Callable[[], None]
_CHECK: ContextVar[AuthorityCheck | None] = ContextVar("guard_mcp_authority_check", default=None)
_PROXY_SCOPE: ContextVar[bool] = ContextVar("guard_mcp_authority_proxy_scope", default=False)
_RECORD_TYPES = (
    GuardArtifact,
    GuardConfig,
    HarnessContext,
    ManagedPolicy,
    ManagedNetworkPolicy,
    ManagedUpdatePolicy,
    ManagedIntegrityTrust,
    McpServerIdentity,
)
_PATH_TYPES = (PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


class UnsupportedAuthorityValueError(ValueError):
    """A value cannot be inspected without invoking caller-defined behavior."""


def exact_authority_digest(value: object) -> bytes:
    """Bind complete ordered values, including private fields and scalar types."""
    digest = sha256()

    def part(tag: bytes, data: bytes = b"") -> None:
        digest.update(tag)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)

    def visit(item: object) -> None:
        kind = type(item)
        if item is None:
            part(b"n")
        elif kind is bool:
            part(b"b", b"1" if item else b"0")
        elif kind is str:
            part(b"s", cast(str, item).encode("utf-8"))
        elif kind is int:
            part(b"i", str(item).encode("ascii"))
        elif kind is float and math.isfinite(cast(float, item)):
            part(b"f", cast(float, item).hex().encode("ascii"))
        elif kind is bytes:
            part(b"y", cast(bytes, item))
        elif kind is list or kind is tuple:
            sequence = cast(list[object] | tuple[object, ...], item)
            part(b"l" if kind is list else b"t", len(sequence).to_bytes(8, "big"))
            for child in sequence:
                visit(child)
        elif kind is dict:
            mapping = cast(dict[object, object], item)
            part(b"d", len(mapping).to_bytes(8, "big"))
            for key, child in mapping.items():
                if type(key) is not str:
                    raise UnsupportedAuthorityValueError
                visit(key)
                visit(child)
        elif kind is frozenset:
            values = cast(frozenset[object], item)
            if any(type(child) is not str for child in values):
                raise UnsupportedAuthorityValueError
            part(b"z", len(values).to_bytes(8, "big"))
            for child in sorted(cast(frozenset[str], values)):
                visit(child)
        elif any(kind is known for known in _PATH_TYPES):
            part(b"p", kind.__name__.encode("ascii"))
            visit(str(item))
        elif (record_type := next((known for known in _RECORD_TYPES if kind is known), None)) is not None:
            part(b"r", kind.__name__.encode("ascii"))
            for record_field in fields(record_type):
                visit(record_field.name)
                visit(object.__getattribute__(item, record_field.name))
        else:
            raise UnsupportedAuthorityValueError

    visit(value)
    return digest.digest()


@dataclass(frozen=True, slots=True, repr=False)
class ExactAuthorityBinding:
    values: Callable[[], object]
    owners: Callable[[], tuple[object, ...]]
    expected_values: bytes
    expected_owners: tuple[object, ...]
    changed: Callable[[], Exception]
    input_check: AuthorityCheck | None = None

    def check(self) -> None:
        if self.input_check is not None:
            self.input_check()
        try:
            actual_owners = self.owners()
            if len(actual_owners) != len(self.expected_owners) or any(
                current is not original for current, original in zip(actual_owners, self.expected_owners, strict=True)
            ):
                raise self.changed()
            if exact_authority_digest(self.values()) != self.expected_values:
                raise self.changed()
        except (TypeError, ValueError, RecursionError, RuntimeError, OSError) as error:
            raise self.changed() from error


def capture_authority_binding(
    *,
    values: Callable[[], object],
    owners: Callable[[], tuple[object, ...]],
    changed: Callable[[], Exception],
    input_check: AuthorityCheck | None = None,
) -> ExactAuthorityBinding:
    if input_check is not None:
        input_check()
    expected_owners = owners()
    binding = ExactAuthorityBinding(
        values, owners, exact_authority_digest(values()), expected_owners, changed, input_check
    )
    binding.check()
    return binding


def check_current_mcp_authority() -> None:
    check = _CHECK.get()
    if check is not None:
        check()


def current_mcp_authority_check() -> AuthorityCheck | None:
    return _CHECK.get()


@contextmanager
def use_mcp_authority_check(check: AuthorityCheck | None, *, retain_current: bool = False) -> Iterator[None]:
    """Scope one invocation's check; nested calls restore the enclosing check."""
    enclosing = _CHECK.get()
    if retain_current and enclosing is not None and enclosing is not check:
        selected = check

        def combined() -> None:
            enclosing()
            if selected is not None:
                selected()

        check = combined
    token = _CHECK.set(check)
    try:
        yield
    finally:
        _CHECK.reset(token)


def inside_proxy_authority_scope() -> bool:
    return _PROXY_SCOPE.get()


@contextmanager
def proxy_authority_scope() -> Iterator[None]:
    token = _PROXY_SCOPE.set(True)
    check_token = _CHECK.set(None)
    try:
        yield
    finally:
        _CHECK.reset(check_token)
        _PROXY_SCOPE.reset(token)
