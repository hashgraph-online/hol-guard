"""Guard CLI command facade."""

# fmt: off

from __future__ import annotations

import argparse
import sys
from types import ModuleType
from typing import Any, TextIO

from . import commands_impl as _impl
from . import commands_parser as _parser

_SYNC_NAMES = (
    "_open_approval_center",
    "_prompt_init_step",
    "_run_guard_browser_connect_flow",
    "_run_guard_device_connect_flow",
    "_emit_native_hook_notification_stderr",
    "_runtime_action_data_flow_signals",
    "GuardBridge",
    "GuardStore",
    "RemoteGuardProxy",
    "StdioGuardProxy",
    "apply_managed_install",
    "cisco_risk_signal_v3_to_v2",
    "desktop_notification_setup_supported",
    "ensure_desktop_notification_setup",
    "ensure_guard_daemon",
    "evaluate_package_request_artifact",
    "guard_run",
    "load_guard_daemon_auth_token",
    "load_guard_surface_daemon_client",
    "policy_action_for_cisco_signals",
    "resolve_risk_action",
    "run_consumer_scan",
    "run_guard_disconnect_command",
    "run_guard_update",
    "scan_action_for_cisco_evidence",
    "sync_local_guard_cloud_proof",
    "sync_receipts",
    "sync_runtime_session",
    "sync_supply_chain_bundle",
    "wait_for_approval_requests",
)

_SYNCED_CALLS = {
    "_build_guard_device_connect_payload",
    "_finalize_guard_connect_payload",
    "_headless_approval_resolver",
    "_refresh_cloud_policy_bundle",
    "_run_hermes_mcp_proxy",
}


def _facade_module() -> ModuleType:
    return sys.modules[__name__]


def _sync_impl_overrides() -> None:
    module = _facade_module()
    for name in _SYNC_NAMES:
        if hasattr(module, name):
            setattr(_impl, name, getattr(module, name))


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
    return getattr(_impl, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_impl)) | set(dir(_parser)))
