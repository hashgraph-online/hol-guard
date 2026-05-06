"""Data-flow exfiltration rules for Guard runtime shell actions."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse

from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.data_flow import (
    ShellPipe,
    extract_command_segments,
    extract_input_redirects,
    extract_pipes,
    extract_urls,
)
from codex_plugin_scanner.guard.runtime.secret_sensitivity import SecretPathMatch, classify_secret_path
from codex_plugin_scanner.guard.runtime.signals import RiskSignalCategory, RiskSignalV2

_SECRET_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<path>"
    r"\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
    r"(?:~?/)?\.aws/credentials|(?:~?/)?\.ssh/id_(?:rsa|ed25519|ecdsa)|"
    r"wallet\.key|private-key\.pem|terraform\.tfvars"
    r")"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_CURL_DATA_FILE_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b.*?"
    r"(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@|--upload-file(?:=|\s+)|-T\s*)"
    r"(?P<path>\"[^\"]+\"|'[^']+'|[^\s;&|]+)"
)
_CURL_DATA_STDIN_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?"
    r"(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@-|--upload-file(?:=|\s+)[.-]|-T\s*[.-])"
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
_GIT_REMOTE_ADD_PATTERN = re.compile(r"(?is)(?:^|[\s;&|])git\s+remote\s+add\b(?P<body>[^\r\n;&|]+)")
_NPM_PUBLISH_PATTERN = re.compile(r"(?is)(?:^|[\s;&|])npm\s+publish\b")
_TOKEN_SOURCE_PATTERN = re.compile(r"(?i)\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|npm[_-]?token)\b")
_CLIPBOARD_SINK_PATTERN = re.compile(r"(?i)(?:^|[\s;&|])(?:pbcopy|xclip|xsel|wl-copy|clip(?:\.exe)?)\b")
_TEMP_SECRET_WRITE_PATTERN = re.compile(
    r"(?is)(?:>\s*(?P<redirect>/tmp/[^\s;&|]+)|tee\b(?:\s+(?:-[A-Za-z]+|--[A-Za-z-]+))*\s+(?P<tee>/tmp/[^\s;&|]+))"
)
_CHMOD_TEMP_PATTERN = re.compile(r"(?is)chmod\s+(?P<mode>[0-7]{3,4}|[A-Za-z,+=-]+)\s+(?P<path>/tmp/[^\s;&|]+)")
_SCP_OPTIONS_WITH_VALUES = frozenset({"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"})
_WEBHOOK_HOST_MARKERS = (
    "webhook.site",
    "hooks.slack.com",
    "discord.com",
    "pastebin.com",
    "gist.github.com",
    "transfer.sh",
    "requestbin",
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
    candidates = list(extract_input_redirects(command))
    candidates.extend(_strip_shell_token(match.group("path")) for match in _SECRET_PATH_TOKEN_PATTERN.finditer(command))
    candidates.extend(_curl_data_file_paths(command))
    return _secret_path_matches(tuple(candidates), workspace=workspace)


def _secret_path_matches(paths: Sequence[str], *, workspace: Path | None) -> tuple[SecretPathMatch, ...]:
    matches: list[SecretPathMatch] = []
    for path in paths:
        match = classify_secret_path(path, cwd=workspace)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def _curl_data_file_paths(command: str) -> tuple[str, ...]:
    paths: list[str] = []
    for segment in extract_command_segments(command):
        for match in _CURL_DATA_FILE_PATTERN.finditer(segment):
            paths.append(_strip_shell_token(match.group("path")))
    return tuple(paths)


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
    return any(_CURL_DATA_STDIN_PATTERN.search(segment) for segment in extract_command_segments(command))


def _contains_http_tool_or_url(command: str) -> bool:
    lowered = command.lower()
    return "curl" in lowered or "fetch" in lowered or "http" in lowered or bool(extract_urls(command))


def _contains_http_upload_sink(command: str) -> bool:
    return _contains_http_tool_or_url(command) and _has_http_upload(command)


def _curl_uploads_secret_file(command: str, *, workspace: Path | None) -> bool:
    return any(classify_secret_path(path, cwd=workspace) is not None for path in _curl_data_file_paths(command))


def _python_posts_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if not extract_urls(segment):
            continue
        if any(
            classify_secret_path(match.group("path"), cwd=workspace) is not None
            for match in _PYTHON_SECRET_POST_PATTERN.finditer(segment)
        ):
            return True
    return False


def _node_fetches_secret(command: str, *, workspace: Path | None) -> bool:
    for segment in extract_command_segments(command):
        if not extract_urls(segment):
            continue
        if any(
            classify_secret_path(match.group("path"), cwd=workspace) is not None
            for match in _NODE_SECRET_FETCH_PATTERN.finditer(segment)
        ):
            return True
    return False


def _encoded_secret_send(command: str, secret_matches: Sequence[SecretPathMatch], *, workspace: Path | None) -> bool:
    if not secret_matches:
        return False
    return any(
        _secret_path_matches_in_command(segment, workspace=workspace)
        and "base64" in segment.lower()
        and _has_http_upload(segment)
        and bool(extract_urls(segment))
        for segment in extract_command_segments(command)
    )


def _has_dns_exfil_hostname(command: str) -> bool:
    return any(_has_long_encoded_label(match.group("host")) for match in _DNS_LONG_LABEL_PATTERN.finditer(command))


def _has_long_encoded_label(host: str) -> bool:
    return any(len(label) >= 48 for label in host.split("."))


def _has_webhook_sink(urls: Sequence[str]) -> bool:
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if any(marker in host for marker in _WEBHOOK_HOST_MARKERS):
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
    for match in _SCP_PATTERN.finditer(command):
        body = match.group("body")
        operands = _scp_operands(body)
        if len(operands) < 2:
            continue
        target = operands[-1]
        sources = operands[:-1]
        if not _is_scp_remote_target(target):
            continue
        if any(not _is_scp_remote_target(source) and classify_secret_path(source, cwd=workspace) for source in sources):
            return True
    return False


def _scp_operands(body: str) -> tuple[str, ...]:
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    operands: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if token in _SCP_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        operands.append(token)
        index += 1
    return tuple(operands)


def _is_scp_remote_target(value: str) -> bool:
    return bool(re.fullmatch(r"(?:\S+@)?[^:\s]+:.+", value))


def _git_remote_adds_token_url(command: str) -> bool:
    for match in _GIT_REMOTE_ADD_PATTERN.finditer(command):
        for url in extract_urls(match.group("body")):
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
        if not _NPM_PUBLISH_PATTERN.search(segment):
            continue
        if "--dry-run" in segment:
            continue
        if _TOKEN_SOURCE_PATTERN.search(segment):
            return True
        if _has_npm_secret_match(_secret_path_matches_in_command(segment, workspace=workspace)):
            return True
    return False


def _has_npm_secret_match(secret_matches: Sequence[SecretPathMatch]) -> bool:
    return any("npm" in match.family.lower() or ".npmrc" in match.requested_path.lower() for match in secret_matches)


def _clipboard_receives_secret(pipes: Sequence[ShellPipe], command: str, *, workspace: Path | None) -> bool:
    if not pipes or not _CLIPBOARD_SINK_PATTERN.search(command):
        return False
    return any(
        extract_pipes(segment)
        and _secret_path_matches_in_command(segment, workspace=workspace)
        and _CLIPBOARD_SINK_PATTERN.search(segment)
        for segment in extract_command_segments(command)
    )


def _world_readable_temp_secret(command: str, *, workspace: Path | None) -> bool:
    write_targets = {
        _strip_shell_token(target)
        for segment in extract_command_segments(command)
        if _secret_path_matches_in_command(segment, workspace=workspace)
        for match in _TEMP_SECRET_WRITE_PATTERN.finditer(segment)
        for target in (match.group("redirect"), match.group("tee"))
        if target
    }
    if not write_targets:
        return False
    return any(
        _strip_shell_token(match.group("path")) in write_targets and _mode_makes_world_readable(match.group("mode"))
        for match in _CHMOD_TEMP_PATTERN.finditer(command)
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


def _strip_shell_token(value: str) -> str:
    stripped = value.strip().strip(",")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


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
