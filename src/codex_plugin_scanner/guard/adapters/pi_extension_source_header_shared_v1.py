"""Version-one shared header renderer for generated Pi-family sources."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE
from .pi_extension_runtime_ownership import PiExtensionRuntimeOwnership

HeaderBuilder = Callable[..., str]


@dataclass(frozen=True)
class SourceHeaderRenderConfigV1:
    cli_wrapper_command_json: str
    cli_wrapper_args_json: str
    compatibility_version_json: str
    config_path_json: str
    guard_args_json: str
    guard_home_json: str
    home_dir_is_default_json: str
    home_dir_json: str
    recovery_args_json: str
    recovery_command_json: str
    runtime: PiExtensionRuntimeOwnership
    taskkill_path_json: str
    guard_cli_hook_timeout_ms: int
    guard_daemon_hook_timeout_ms: int
    guard_daemon_recovery_timeout_ms: int
    guard_daemon_retry_timeout_ms: int
    guard_hook_content_item_limit: int
    guard_hook_deadline_reserve_ms: int
    guard_hook_max_depth: int
    guard_hook_max_serialized_payload_chars: int
    guard_hook_object_key_limit: int
    guard_hook_text_limit_chars: int
    guard_hook_timeout_ms: int
    structured_constants_source: str
    structured_response_fields_source: str
    content_review_helpers_source: str


def build_source_header_v1(config: SourceHeaderRenderConfigV1) -> str:
    return (
        'import { spawn } from "node:child_process";\n'
        + 'import { createCipheriv, createHash, randomBytes } from "node:crypto";\n'  # pyright: ignore[reportImplicitStringConcatenation]
        'import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";\n'
        'import { tmpdir } from "node:os";\n'
        'import { join } from "node:path";\n'
        'import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";\n'
        "\n"
        f"const GUARD_CLI_WRAPPER_COMMAND = {config.cli_wrapper_command_json};\n"
        f"const GUARD_CLI_WRAPPER_ARGS = {config.cli_wrapper_args_json};\n"
        f"const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = {str(config.runtime.cli_accepts_json_args).lower()};\n"
        f"const GUARD_DAEMON_RECOVERY_COMMAND = {config.recovery_command_json};\n"
        f"const GUARD_DAEMON_RECOVERY_ARGS = {config.recovery_args_json};\n"
        "const GUARD_DAEMON_RECOVERY_ACCEPTS_FAILURE_KIND = "
        f"{str(config.runtime.recovery_accepts_failure_kind).lower()};\n"
        f"const GUARD_TASKKILL_PATH = {config.taskkill_path_json};\n"
        f"const GUARD_ARGS = {config.guard_args_json};\n"
        f"const GUARD_HOME = {config.guard_home_json};\n"
        f"const GUARD_HOME_DIR = {config.home_dir_json};\n"
        f"const GUARD_HOME_DIR_IS_DEFAULT = {config.home_dir_is_default_json};\n"
        f"const GUARD_CONFIG_PATH = {config.config_path_json};\n"
        f"const GUARD_COMPATIBILITY_VERSION = {config.compatibility_version_json};\n"
        f"const GUARD_TIMEOUT_MS = {config.guard_hook_timeout_ms};\n"
        f"const GUARD_DEADLINE_RESERVE_MS = {config.guard_hook_deadline_reserve_ms};\n"
        f"const GUARD_DAEMON_TIMEOUT_MS = {config.guard_daemon_hook_timeout_ms};\n"
        f"const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = {config.guard_daemon_recovery_timeout_ms};\n"
        f"const GUARD_DAEMON_RETRY_TIMEOUT_MS = {config.guard_daemon_retry_timeout_ms};\n"
        f"const GUARD_CLI_TIMEOUT_MS = {config.guard_cli_hook_timeout_ms};\n"
        f"const GUARD_TEXT_LIMIT_CHARS = {config.guard_hook_text_limit_chars};\n"
        f"const GUARD_CONTENT_ITEM_LIMIT = {config.guard_hook_content_item_limit};\n"
        f"const GUARD_OBJECT_KEY_LIMIT = {config.guard_hook_object_key_limit};\n"
        f"const GUARD_MAX_DEPTH = {config.guard_hook_max_depth};\n"
        f"const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = {config.guard_hook_max_serialized_payload_chars};\n"
        + config.structured_constants_source
        + "const GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS = 2_000;\n"
        "const GUARD_APPROVAL_RESUME_FETCH_TIMEOUT_MS = 1_500;\n"
        "const GUARD_APPROVAL_RESUME_MAX_WAIT_MS = 10 * 60 * 1_000;\n"
        "const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;\n"
        "const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set([\n"
        '  "read", "read_file", "open_file", "view", "view_file", "cat_file", "Read", "View"\n'
        "]);\n"
        "\n"
        "type GuardResponse = {\n"
        '  decision: "allow" | "deny";\n'
        "  reason?: string;\n"
        "  approval_request_id?: string;\n"
        "  approval_url?: string;\n"
        "  approval_center_url?: string;\n"
        "  resume_poll_path?: string;\n"
        '  model_output_action?: "allow_original" | "replace_with_reviewed_excerpt" | "block" | "not_applicable";\n'
        "  reviewed_output_sha256?: string;\n"
        "  reviewed_excerpt?: string;\n"
        "  observed_policy_action?: string;\n"
        "  observed_review_failure?: boolean;\n"
        "  observe_mode?: boolean;\n"
        "  policy_action?: string;\n"
        '  notice?: "none" | "excerpt" | "warning";\n'
        "  reason_code?: string;\n"
        + config.structured_response_fields_source
        + "};\n"
        + CLI_RUNTIME_HELPERS_SOURCE
        + config.content_review_helpers_source
    )


def make_source_header_builder_v1(
    *,
    structured_constants_source: str,
    structured_response_fields_source: str,
    content_review_helpers_source: str,
) -> HeaderBuilder:
    def build_source_header(
        *,
        cli_wrapper_command_json: str,
        cli_wrapper_args_json: str,
        compatibility_version_json: str,
        config_path_json: str,
        guard_args_json: str,
        guard_home_json: str,
        home_dir_is_default_json: str,
        home_dir_json: str,
        recovery_args_json: str,
        recovery_command_json: str,
        runtime: PiExtensionRuntimeOwnership,
        taskkill_path_json: str,
        guard_cli_hook_timeout_ms: int,
        guard_daemon_hook_timeout_ms: int,
        guard_daemon_recovery_timeout_ms: int,
        guard_daemon_retry_timeout_ms: int,
        guard_hook_content_item_limit: int,
        guard_hook_deadline_reserve_ms: int,
        guard_hook_max_depth: int,
        guard_hook_max_serialized_payload_chars: int,
        guard_hook_object_key_limit: int,
        guard_hook_text_limit_chars: int,
        guard_hook_timeout_ms: int,
    ) -> str:
        return build_source_header_v1(
            SourceHeaderRenderConfigV1(
                cli_wrapper_command_json=cli_wrapper_command_json,
                cli_wrapper_args_json=cli_wrapper_args_json,
                compatibility_version_json=compatibility_version_json,
                config_path_json=config_path_json,
                guard_args_json=guard_args_json,
                guard_home_json=guard_home_json,
                home_dir_is_default_json=home_dir_is_default_json,
                home_dir_json=home_dir_json,
                recovery_args_json=recovery_args_json,
                recovery_command_json=recovery_command_json,
                runtime=runtime,
                taskkill_path_json=taskkill_path_json,
                guard_cli_hook_timeout_ms=guard_cli_hook_timeout_ms,
                guard_daemon_hook_timeout_ms=guard_daemon_hook_timeout_ms,
                guard_daemon_recovery_timeout_ms=guard_daemon_recovery_timeout_ms,
                guard_daemon_retry_timeout_ms=guard_daemon_retry_timeout_ms,
                guard_hook_content_item_limit=guard_hook_content_item_limit,
                guard_hook_deadline_reserve_ms=guard_hook_deadline_reserve_ms,
                guard_hook_max_depth=guard_hook_max_depth,
                guard_hook_max_serialized_payload_chars=guard_hook_max_serialized_payload_chars,
                guard_hook_object_key_limit=guard_hook_object_key_limit,
                guard_hook_text_limit_chars=guard_hook_text_limit_chars,
                guard_hook_timeout_ms=guard_hook_timeout_ms,
                structured_constants_source=structured_constants_source,
                structured_response_fields_source=structured_response_fields_source,
                content_review_helpers_source=content_review_helpers_source,
            )
        )

    return build_source_header
