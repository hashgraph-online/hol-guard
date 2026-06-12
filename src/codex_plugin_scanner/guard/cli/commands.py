"""Guard CLI command facade."""

# fmt: off

from __future__ import annotations

import argparse
import sys
from types import ModuleType
from typing import Any, TextIO

from . import commands_impl as _impl
from . import commands_parser as _parser

_SYNCED_CALLS = {
    "_run_hermes_mcp_proxy",
}

_FACADE_NAMES = {
    "_SYNCED_CALLS",
    "_EXPORTED_EXCLUSIONS",
    "_build_guard_device_connect_payload",
    "_facade_module",
    "_finalize_guard_connect_payload",
    "_headless_approval_resolver",
    "_iter_facade_overrides",
    "_parser",
    "_refresh_cloud_policy_bundle",
    "_sync_impl_overrides",
    "_impl",
    "add_guard_parser",
    "add_guard_root_parser",
    "run_guard_command",
}


def _facade_module() -> ModuleType:
    return sys.modules[__name__]


def _iter_facade_overrides() -> dict[str, object]:
    module = _facade_module()
    overrides: dict[str, object] = {}
    for name, value in vars(module).items():
        if name.startswith("__") or name in _FACADE_NAMES:
            continue
        if hasattr(_impl, name):
            overrides[name] = value
    return overrides


def _sync_impl_overrides() -> None:
    _impl._apply_overrides(_iter_facade_overrides())


def add_guard_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    _parser.add_guard_parser(subparsers)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    _parser.add_guard_root_parser(parser)


def run_guard_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    _sync_impl_overrides()
    return _impl.run_guard_command(args, input_text=input_text, output_stream=output_stream)


def _build_guard_device_connect_payload(*args: Any, **kwargs: Any):
    _sync_impl_overrides()
    return _impl._build_guard_device_connect_payload(*args, **kwargs)


def _finalize_guard_connect_payload(*args: Any, **kwargs: Any):
    _sync_impl_overrides()
    return _impl._finalize_guard_connect_payload(*args, **kwargs)


def _headless_approval_resolver(*args: Any, **kwargs: Any):
    _sync_impl_overrides()
    return _impl._headless_approval_resolver(*args, **kwargs)


def _refresh_cloud_policy_bundle(*args: Any, **kwargs: Any):
    _sync_impl_overrides()
    return _impl._refresh_cloud_policy_bundle(*args, **kwargs)


def __getattr__(name: str) -> Any:
    if name in _SYNCED_CALLS:
        def _wrapped(*args: Any, **kwargs: Any):
            _sync_impl_overrides()
            return getattr(_impl, name)(*args, **kwargs)

        _wrapped.__name__ = name
        _wrapped.__qualname__ = name
        _wrapped.__doc__ = getattr(getattr(_impl, name), "__doc__", None)
        _wrapped.__module__ = __name__
        return _wrapped
    if hasattr(_impl, name):
        return getattr(_impl, name)
    return getattr(_parser, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_impl)) | set(dir(_parser)))
