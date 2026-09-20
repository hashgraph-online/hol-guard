"""Original shared import bindings for the runtime regression tests."""

from __future__ import annotations

import argparse
import builtins
import hashlib
import io
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from base64 import urlsafe_b64decode
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import synced_policy as synced_policy_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.approvals import apply_approval_resolution, wait_for_approval_requests
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review_module
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction_module
from codex_plugin_scanner.guard.cli import render as guard_render_module
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _codex_post_tool_output_artifact,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _runtime_hook_approval_context_token,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import _runtime_policy_path
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.codex_config import read_toml_payload
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config, overlay_synced_guard_policy
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import (
    GuardAction,
    GuardApprovalRequest,
    GuardArtifact,
    GuardReceipt,
    HarnessDetection,
    PolicyDecision,
)
from codex_plugin_scanner.guard.policy import decide_action, decide_action_with_v2
from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.policy_bundle_parser import (
    payload_hash_for_policy_bundle,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.proxy import RemoteGuardProxy, StdioGuardProxy
from codex_plugin_scanner.guard.proxy import framing as proxy_framing
from codex_plugin_scanner.guard.proxy import stdio as stdio_proxy_module
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime import secret_file_requests as secret_file_requests_module
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    approval_context_tokens_validation_reason,
    build_approval_context_token,
)
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    extract_package_intent_request,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_file_write_request,
    extract_sensitive_tool_action_request,
)
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2
from codex_plugin_scanner.guard.store import (
    GuardStore,
    _runtime_scoped_exact_match_key,
    runtime_tool_action_exact_match_context,
)
from codex_plugin_scanner.guard.synced_policy import synced_policy_payload
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)
from tests.support.network import stub_authenticated_urlopen

__all__ = [
    "APPROVAL_CONTEXT_TOKEN_PREFIX",
    "BaseHTTPRequestHandler",
    "ClassVar",
    "CodexHarnessAdapter",
    "GuardAction",
    "GuardActionEnvelope",
    "GuardApprovalRequest",
    "GuardArtifact",
    "GuardConfig",
    "GuardDaemonServer",
    "GuardReceipt",
    "GuardStore",
    "HTTPServer",
    "HarnessContext",
    "HarnessDetection",
    "Path",
    "PolicyDecision",
    "RemoteGuardProxy",
    "RiskSignalV2",
    "StdioGuardProxy",
    "_codex_post_tool_output_artifact",
    "_runtime_hook_approval_context_token",
    "_runtime_policy_path",
    "_runtime_scoped_exact_match_key",
    "apply_approval_resolution",
    "approval_context_tokens_validation_reason",
    "argparse",
    "artifact_hash",
    "build_approval_context_token",
    "build_package_request_artifact",
    "build_receipt",
    "builtins",
    "contextmanager",
    "datetime",
    "decide_action",
    "decide_action_with_v2",
    "emit_guard_payload",
    "evaluate_detection",
    "extract_package_intent_request",
    "extract_sensitive_file_write_request",
    "extract_sensitive_tool_action_request",
    "generate_dpop_key_pair",
    "guard_commands_module",
    "guard_render_module",
    "guard_runner_module",
    "hashlib",
    "interaction_module",
    "io",
    "json",
    "load_guard_config",
    "main",
    "os",
    "overlay_synced_guard_policy",
    "payload_hash_for_policy_bundle",
    "policy_bundle_acknowledgement_payload",
    "policy_bundle_test_keyring",
    "policy_bundle_test_verification_key",
    "proxy_framing",
    "pytest",
    "read_toml_payload",
    "replace",
    "runtime_review_module",
    "runtime_tool_action_exact_match_context",
    "secret_file_requests_module",
    "shlex",
    "shutil",
    "sign_policy_bundle",
    "sqlite3",
    "stdio_proxy_module",
    "stub_authenticated_urlopen",
    "subprocess",
    "synced_policy_module",
    "synced_policy_payload",
    "sys",
    "threading",
    "timezone",
    "urllib",
    "urlsafe_b64decode",
    "validated_policy_bundle_payload",
    "wait_for_approval_requests",
]
