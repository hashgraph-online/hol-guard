"""Data-flow exfiltration rules for Guard runtime shell actions."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse

from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.data_flow import (
    ShellPipe,
    extract_command_segments,
    extract_command_substitutions,
    extract_pipes,
    extract_urls,
)
from codex_plugin_scanner.guard.runtime.data_flow_variables import (
    curl_data_uses_encoded_secret_variable,
    curl_data_uses_secret_variable,
)
from codex_plugin_scanner.guard.runtime.secret_sensitivity import SecretPathMatch, classify_secret_path
from codex_plugin_scanner.guard.runtime.secret_sources import secret_path_matches_in_command, strip_shell_token
from codex_plugin_scanner.guard.runtime.shell_commands import (
    command_execution_segments,
    command_tokens_after_env_assignments,
    git_remote_add_url_tokens,
    is_scp_remote_target,
    npm_publish_index,
    npm_publish_is_dry_run,
    scp_operands,
    segment_executes_command,
)
from codex_plugin_scanner.guard.runtime.signals import RiskSignalCategory, RiskSignalV2
from codex_plugin_scanner.guard.runtime.temp_files import chmod_temp_targets, temp_write_targets

_CURL_DATA_FILE_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b.*?"
    r"(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@|--upload-file(?:=|\s+)|-T\s*)"
    r"(?P<path>\"[^\"]+\"|'[^']+'|[^\s;&|]+)"
)
_CURL_DATA_STDIN_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?"
    r"(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@-|(?:--form|-F)(?:=|\s*)[^\s;&|]*@[.-](?=$|[\s;&|])|"
    r"--upload-file(?:=|\s+)[.-](?=$|[\s;&|])|-T\s*[.-](?=$|[\s;&|]))"
)
_CURL_DATA_VALUE_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?"
    r"(?:--data(?:-binary|-raw|-urlencode)?|-d)(?:=|\s*)"
    r"(?P<value>\"[^\"]+\"|'[^']+'|[^\s;&|]+)"
)
_PYTHON_SECRET_POST_PATTERN = re.compile(
    r"(?is)\bpython(?:3)?\b.*?-c\s+.*?"
    r"(?:requests\.post|urllib\.request|http\.client).*?open\(['\"](?P<path>[^'\"]+)['\"]"
)
_NODE_SECRET_FETCH_PATTERN = re.compile(
    r"(?is)\bnode\b.*?-e\s+.*?(?:fetch|axios\.post|https\.request|http\.request).*?"
    r"readFileSync\(['\"](?P<path>[^'\"]+)['\"]"
)
_DNS_LONG_LABEL_PATTERN = re.compile(
    r"(?i)(?:^|[\s;&|])(?:dig|nslookup|host)\s+"
    r"(?P<host>(?:[A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]{48,}(?:\.[A-Za-z0-9_-]+)*)"
)
_SCP_PATTERN = re.compile(r"(?is)(?:^|[\s;&|])scp\b(?P<body>[^\r\n;&|]+)")
_TOKEN_SOURCE_PATTERN = re.compile(r"(?i)\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|npm[_-]?token)\b")
_CLIPBOARD_COMMANDS = frozenset({"pbcopy", "xclip", "xsel", "wl-copy", "clip", "clip.exe"})
_WEBHOOK_HOST_PATTERN = re.compile(
    r"webhook\.site|hooks\.slack\.com|discord\.com|pastebin\.com|gist\.github\.com|transfer\.sh|requestbin"
)
_CURL_SHORT_FLAGS_WITH_VALUES = frozenset(
    {
        "A",
        "b",
        "C",
        "c",
        "d",
        "D",
        "e",
        "E",
        "F",
        "H",
        "h",
        "K",
        "m",
        "o",
        "P",
        "Q",
        "r",
        "t",
        "T",
        "u",
        "U",
        "w",
        "x",
        "X",
        "y",
        "Y",
        "z",
    }
)


def detect_data_flow_exfiltration(
    action: GuardActionEnvelope,
    *,
    workspace: Path | None,
) -> tuple[RiskSignalV2, ...]:
    if action.action_type != "shell_command" or action.command is None:
        return ()
    command = action.command
    findings: list[RiskSignalV2] = []
    secret_matches = _secret_path_matches_in_command(command, workspace=workspace)
    pipes = extract_pipes(command)
    if _has_secret_pipe_to_http_upload(pipes, command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "secret-pipe-http",
                "Shell pipeline sends a local secret to a network host",
                "This command pipes a local secret into an HTTP upload.",
                "secret path and HTTP upload appear in the same pipe chain",
                category="network",
            )
        )
    if _curl_uploads_secret_file(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "curl-data-file",
                "Curl uploads a local secret file",
                "This command sends a local secret file as curl request data.",
                "curl data flag references a sensitive local path",
                category="network",
            )
        )
    if curl_data_uses_secret_variable(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "shell-variable-secret-http",
                "Shell variable sends a local secret to a network host",
                "This command sends local secret to network host through a shell variable.",
                "shell variable is assigned from a sensitive path and later used as curl request data",
                category="network",
            )
        )
    if _python_posts_secret(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "python-secret-post",
                "Python posts a local secret",
                "This Python snippet reads a local secret and posts it to a network host.",
                "python -c combines a sensitive file read with an HTTP post",
                category="network",
            )
        )
    if _node_fetches_secret(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "node-secret-fetch",
                "Node sends a local secret",
                "This Node snippet reads a local secret and sends it to a network host.",
                "node -e combines fs.readFileSync on a sensitive path with fetch/request",
                category="network",
            )
        )
    if _encoded_secret_send(command, secret_matches, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "encoded-secret-send",
                "Encoded local secret is sent to a network host",
                "This command encodes a local secret before sending it to a network host.",
                "base64 appears between a sensitive path and HTTP upload",
                category="network",
            )
        )
    if _has_dns_exfil_hostname(command):
        findings.append(
            _data_flow_signal(
                "dns-exfil",
                "DNS query looks like encoded exfiltration",
                "This command sends an unusually long encoded-looking DNS label.",
                "DNS tool is called with a long encoded-looking label",
                category="network",
            )
        )
    if _has_webhook_exfil(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "webhook-sink",
                "Local secret is sent to a public collection endpoint",
                "This command targets a paste, gist, transfer, or webhook endpoint with local secret data.",
                "known collection host appears with local secret source",
                category="network",
            )
        )
    if _scp_sends_secret(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "scp-secret",
                "SCP sends a local secret file",
                "This command copies a local secret file to a remote host.",
                "scp command references a sensitive local source",
                category="network",
            )
        )
    if _git_remote_adds_token_url(command):
        findings.append(
            _data_flow_signal(
                "git-remote-token",
                "Git remote URL contains an access token",
                "This command stores a token-bearing URL in git remote configuration.",
                "git remote add URL includes credentials before host",
                category="secret",
            )
        )
    if _npm_publish_with_token_source(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "npm-publish-token-source",
                "NPM publish uses local token material",
                "This command publishes a package while local npm token material is in scope.",
                "npm publish appears with npm token source evidence",
                category="network",
            )
        )
    if _clipboard_receives_secret(pipes, command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "clipboard-secret",
                "Clipboard receives a local secret",
                "This command copies local secret contents into the clipboard.",
                "clipboard command receives sensitive source through a pipe",
                category="secret",
            )
        )
    if _world_readable_temp_secret(command, workspace=workspace):
        findings.append(
            _data_flow_signal(
                "world-readable-temp-secret",
                "Local secret is written to a world-readable temp file",
                "This command writes local secret contents to a world-readable temp file.",
                "sensitive source is redirected to /tmp and chmod makes it world-readable",
                category="secret",
            )
        )
    return tuple(_dedupe_signals(findings))


def _secret_path_matches_in_command(command: str, *, workspace: Path | None) -> tuple[SecretPathMatch, ...]:
    return secret_path_matches_in_command(command, workspace=workspace, extra_paths=_curl_data_file_paths(command))


def _curl_data_file_paths(command: str) -> tuple[str, ...]:
    paths: list[str] = []
    for segment in command_execution_segments(command):
        tokens = command_tokens_after_env_assignments(segment)
        if not tokens or tokens[0].lower() not in {"curl", "curl.exe"}:
            continue
        paths.extend(_curl_segment_data_file_paths(tokens[1:]))
    return tuple(paths)


def _curl_segment_data_file_paths(args: Sequence[str]) -> tuple[str, ...]:
    paths: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            break
        long_flag_path = _curl_long_flag_data_path(token, args, index)
        if long_flag_path is not None:
            path, consumed = long_flag_path
            if path is not None:
                paths.append(path)
            index += consumed
            continue
        short_flag_path = _curl_short_flag_data_path(token, args, index)
        if short_flag_path is not None:
            path, consumed = short_flag_path
            if path is not None:
                paths.append(path)
            index += consumed
            continue
        index += 1
    return tuple(paths)


def _curl_long_flag_data_path(token: str, args: Sequence[str], index: int) -> tuple[str | None, int] | None:
    long_flags = {
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--upload-file",
        "--form",
    }
    if token in long_flags:
        value = args[index + 1] if index + 1 < len(args) else ""
        return _curl_option_data_path(token, value), 2
    for flag in long_flags:
        prefix = f"{flag}="
        if token.startswith(prefix):
            return _curl_option_data_path(flag, token[len(prefix) :]), 1
    return None


def _curl_short_flag_data_path(token: str, args: Sequence[str], index: int) -> tuple[str | None, int] | None:
    if token in {"-d", "-T", "-F"}:
        value = args[index + 1] if index + 1 < len(args) else ""
        return _curl_option_data_path(token, value), 2
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    cluster = token[1:]
    for flag_index, flag in enumerate(cluster):
        attached_value = cluster[flag_index + 1 :]
        if flag not in {"d", "T", "F"}:
            if flag in _CURL_SHORT_FLAGS_WITH_VALUES:
                return None
            continue
        option = f"-{flag}"
        if attached_value:
            return _curl_option_data_path(option, attached_value), 1
        value = args[index + 1] if index + 1 < len(args) else ""
        return _curl_option_data_path(option, value), 2
    return None


def _curl_option_data_path(flag: str, value: str) -> str | None:
    normalized_value = strip_shell_token(value)
    if not normalized_value or normalized_value.startswith("-"):
        return None
    if flag in {"--upload-file", "-T"}:
        return normalized_value
    if flag in {"--form", "-F"}:
        field_value = normalized_value.split("=", 1)[1] if "=" in normalized_value else normalized_value
        if field_value and field_value[0] in {"@", "<"}:
            return field_value[1:].split(";", 1)[0].split(",", 1)[0]
        return None
    if flag == "--data-urlencode":
        if normalized_value.startswith("@"):
            return normalized_value[1:]
        if "@" not in normalized_value:
            return None
        name, file_candidate = normalized_value.split("@", 1)
        if "=" in name:
            return None
        return file_candidate
    if normalized_value.startswith("@"):
        return normalized_value[1:]
    return None


def _has_secret_pipe_to_http_upload(pipes: Sequence[ShellPipe], command: str, *, workspace: Path | None) -> bool:
    if not pipes or not _has_http_upload(command):
        return False
    return any(
        extract_pipes(segment)
        and _secret_path_matches_in_command(segment, workspace=workspace)
        and _contains_http_upload_sink(segment)
        for segment in extract_command_segments(command)
    )


def _has_http_upload(command: str) -> bool:
    return any(
        segment_executes_command(segment, {"curl", "curl.exe"}) and _CURL_DATA_STDIN_PATTERN.search(segment)
        for segment in command_execution_segments(command)
    )


def _contains_http_upload_sink(command: str) -> bool:
    return bool(extract_urls(command)) and _has_http_upload(command)


def _curl_uploads_secret_file(command: str, *, workspace: Path | None) -> bool:
    return any(
        extract_urls(segment)
        and any(classify_secret_path(path, cwd=workspace) is not None for path in _curl_data_file_paths(segment))
        for segment in extract_command_segments(command)
    ) or _curl_data_substitution_reads_secret(command, workspace=workspace)


def _curl_data_substitution_reads_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in command_execution_segments(command):
        if not segment_executes_command(segment, {"curl", "curl.exe"}):
            continue
        if not extract_urls(segment):
            continue
        for match in _CURL_DATA_VALUE_PATTERN.finditer(segment):
            value = match.group("value")
            if not any(
                _secret_path_matches_in_command(substitution, workspace=workspace)
                for substitution in extract_command_substitutions(value)
            ):
                continue
            return True
    return False


def _python_posts_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if (
            segment_executes_command(segment, {"python", "python3"})
            and extract_urls(segment)
            and any(
                classify_secret_path(match.group("path"), cwd=workspace) is not None
                for match in _PYTHON_SECRET_POST_PATTERN.finditer(segment)
            )
        ):
            return True
    return False


def _node_fetches_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if (
            segment_executes_command(segment, {"node"})
            and extract_urls(segment)
            and any(
                classify_secret_path(match.group("path"), cwd=workspace) is not None
                for match in _NODE_SECRET_FETCH_PATTERN.finditer(segment)
            )
        ):
            return True
    return False


def _encoded_secret_send(command: str, secret_matches: Sequence[SecretPathMatch], *, workspace: Path | None) -> bool:
    if not secret_matches:
        return False
    if curl_data_uses_encoded_secret_variable(command, workspace=workspace):
        return True
    return any(
        _secret_path_matches_in_command(segment, workspace=workspace)
        and "base64" in segment.lower()
        and _has_http_upload(segment)
        and bool(extract_urls(segment))
        for segment in extract_command_segments(command)
    )


def _has_dns_exfil_hostname(command: str) -> bool:
    return any(
        segment_executes_command(segment, {"dig", "nslookup", "host"})
        and any(_has_long_encoded_label(token) for token in _dns_query_tokens(segment))
        for segment in extract_command_segments(command)
    )


def _dns_query_tokens(segment: str) -> tuple[str, ...]:
    tokens = command_tokens_after_env_assignments(segment)
    return tuple(token.strip("'\"") for token in tokens[1:] if "." in token and not token.startswith(("-", "+", "@")))


def _has_long_encoded_label(host: str) -> bool:
    return any(len(label) >= 48 for label in host.split("."))


def _has_webhook_sink(urls: Sequence[str]) -> bool:
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if _WEBHOOK_HOST_PATTERN.search(host):
            return True
    return False


def _has_webhook_exfil(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if not _has_webhook_sink(extract_urls(segment)):
            continue
        if _secret_path_matches_in_command(segment, workspace=workspace):
            return True
        if _curl_uploads_secret_file(segment, workspace=workspace):
            return True
        if _has_secret_pipe_to_http_upload(extract_pipes(segment), segment, workspace=workspace):
            return True
    return False


def _scp_sends_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if not segment_executes_command(segment, {"scp"}):
            continue
        match = _SCP_PATTERN.search(segment)
        if match is None:
            continue
        operands = scp_operands(match.group("body"))
        if len(operands) < 2:
            continue
        target = operands[-1]
        sources = operands[:-1]
        if not is_scp_remote_target(target):
            continue
        if any(not is_scp_remote_target(source) and classify_secret_path(source, cwd=workspace) for source in sources):
            return True
    return False


def _git_remote_adds_token_url(command: str) -> bool:
    for segment in extract_command_segments(command):
        tokens = command_tokens_after_env_assignments(segment)
        url_tokens = git_remote_add_url_tokens(tokens)
        if not url_tokens:
            continue
        for url in extract_urls(" ".join(url_tokens)):
            parsed = urlparse(url)
            if parsed.username and _looks_like_token(parsed.username):
                return True
            if parsed.password and _looks_like_token(parsed.password):
                return True
    return False


def _looks_like_token(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("ghp_", "github_pat_", "glpat-", "x-access-token")) or len(value) >= 24


def _npm_publish_with_token_source(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        tokens = command_tokens_after_env_assignments(segment)
        publish_index = npm_publish_index(tokens)
        if publish_index is None:
            continue
        if npm_publish_is_dry_run(tokens, publish_index):
            continue
        if _TOKEN_SOURCE_PATTERN.search(segment):
            return True
        if _has_npm_secret_match(_secret_path_matches_in_command(segment, workspace=workspace)):
            return True
    return False


def _has_npm_secret_match(secret_matches: Sequence[SecretPathMatch]) -> bool:
    return any("npm" in match.family.lower() or ".npmrc" in match.requested_path.lower() for match in secret_matches)


def _clipboard_receives_secret(pipes: Sequence[ShellPipe], command: str, *, workspace: Path | None) -> bool:
    if not pipes:
        return False
    return any(
        (segment_pipes := extract_pipes(segment))
        and _secret_path_matches_in_command(segment, workspace=workspace)
        and any(segment_executes_command(pipe.right, _CLIPBOARD_COMMANDS) for pipe in segment_pipes)
        for segment in extract_command_segments(command)
    )


def _world_readable_temp_secret(command: str, *, workspace: Path | None) -> bool:
    write_targets = {
        target
        for segment in extract_command_segments(command)
        if _secret_path_matches_in_command(segment, workspace=workspace)
        for target in temp_write_targets(segment)
    }
    if not write_targets:
        return False
    return any(
        target in write_targets and _mode_makes_world_readable(mode) for target, mode in chmod_temp_targets(command)
    )


def _mode_makes_world_readable(mode: str) -> bool:
    normalized = mode.lower()
    if normalized.isdigit():
        return normalized[-1] in {"4", "5", "6", "7"}
    for clause in normalized.split(","):
        if "+r" in clause:
            who = clause.split("+", 1)[0]
            if not who or "a" in who or "o" in who:
                return True
        if "=" in clause:
            who, permissions = clause.split("=", 1)
            if "r" in permissions and (not who or "a" in who or "o" in who):
                return True
    return False


def _data_flow_signal(
    signal_key: str,
    title: str,
    plain_reason: str,
    technical_detail: str,
    *,
    category: RiskSignalCategory,
) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=f"data-flow:{signal_key}",
        category=category,
        severity="critical",
        confidence="strong",
        detector="data_flow.exfiltration",
        title=title,
        plain_reason=plain_reason,
        technical_detail=technical_detail,
        evidence_ref="command",
        redaction_level="summary",
        false_positive_hint="Allow only if this exact command intentionally moves non-sensitive local data.",
        advisory_id=None,
    )


def _dedupe_signals(signals: Sequence[RiskSignalV2]) -> tuple[RiskSignalV2, ...]:
    seen: set[str] = set()
    result: list[RiskSignalV2] = []
    for signal in signals:
        if signal.signal_id in seen:
            continue
        seen.add(signal.signal_id)
        result.append(signal)
    return tuple(result)
