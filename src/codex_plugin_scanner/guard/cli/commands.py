"""Guard CLI command facade."""

# fmt: off

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from types import ModuleType
from typing import Any, TextIO

from ...argparse_utils import FriendlyArgumentParser
from . import commands_parser as _parser
from . import commands_support as _support

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
    "_support_overrides",
    "_support",
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
        if hasattr(_support, name) and value is not getattr(_support, name):
            overrides[name] = value
    return overrides


@contextmanager
def _support_overrides() -> Iterator[None]:
    overrides = _iter_facade_overrides()
    missing = object()
    export_map, module_export_names = _support._build_export_map(overrides)
    override_names = set(overrides)
    targets: list[tuple[ModuleType, set[str]]] = [(_support, set(export_map))]
    for module in _support._SOURCE_MODULES:
        affected_names = {
            name
            for name in export_map
            if name not in module_export_names[module] or name in override_names
        }
        targets.append((module, affected_names))
    # The compatibility hook modules are intentionally lazy and therefore are
    # not members of ``commands_support._SOURCE_MODULES``.  When an explicit
    # oracle test has imported one, propagate facade monkeypatches into that
    # already-loaded module for the duration of the scoped call.  Do not
    # import the compatibility surface here: production hook startup must
    # remain independent of the Python evaluator.
    compatibility_prefix = f"{__package__}.commands_hook_"
    known_targets = {id(module) for module, _ in targets}
    for module in tuple(sys.modules.values()):
        if module is None or id(module) in known_targets:
            continue
        module_name = getattr(module, "__name__", "")
        if not module_name.startswith(compatibility_prefix):
            continue
        affected_names = {name for name in override_names if hasattr(module, name)}
        if affected_names:
            targets.append((module, affected_names))
    snapshots = [
        (module, {name: getattr(module, name, missing) for name in affected_names})
        for module, affected_names in targets
    ]
    try:
        _support._apply_overrides(overrides)
        # ``_apply_overrides`` knows only about the eager support registry;
        # apply the same scoped values to any lazy compatibility modules we
        # discovered above.
        for module, affected_names in targets:
            for name in affected_names:
                if name in export_map:
                    setattr(module, name, export_map[name])
        yield
    finally:
        for module, bindings in snapshots:
            for name, value in bindings.items():
                if value is missing:
                    if hasattr(module, name):
                        delattr(module, name)
                else:
                    setattr(module, name, value)


def _support_attr(name: str) -> Any:
    return getattr(_support, name)


def add_guard_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
    | argparse._SubParsersAction[FriendlyArgumentParser],
) -> None:
    _parser.add_guard_parser(subparsers)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    _parser.add_guard_root_parser(parser)


def run_guard_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    with _support_overrides():
        return _support_attr("run_guard_command")(
            args,
            input_text=input_text,
            output_stream=output_stream,
        )


def _build_guard_device_connect_payload(*args: Any, **kwargs: Any):
    with _support_overrides():
        return _support_attr("_build_guard_device_connect_payload")(*args, **kwargs)


def _finalize_guard_connect_payload(*args: Any, **kwargs: Any):
    with _support_overrides():
        return _support_attr("_finalize_guard_connect_payload")(*args, **kwargs)


def _headless_approval_resolver(*args: Any, **kwargs: Any):
    with _support_overrides():
        resolver = _support_attr("_headless_approval_resolver")(*args, **kwargs)

    def _scoped_resolver(*resolver_args: Any, **resolver_kwargs: Any):
        with _support_overrides():
            return resolver(*resolver_args, **resolver_kwargs)

    return _scoped_resolver


def _refresh_cloud_policy_bundle(*args: Any, **kwargs: Any):
    with _support_overrides():
        return _support_attr("_refresh_cloud_policy_bundle")(*args, **kwargs)


def __getattr__(name: str) -> Any:
    if name in _SYNCED_CALLS:
        def _wrapped(*args: Any, **kwargs: Any):
            with _support_overrides():
                return getattr(_support, name)(*args, **kwargs)

        _wrapped.__name__ = name
        _wrapped.__qualname__ = name
        _wrapped.__doc__ = getattr(getattr(_support, name), "__doc__", None)
        _wrapped.__module__ = __name__
        return _wrapped
    if hasattr(_support, name):
        return getattr(_support, name)
    return getattr(_parser, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_support)) | set(dir(_parser)))
