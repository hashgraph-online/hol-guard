from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _skip_rust_lexeme(source: str, index: int) -> int:
    if source.startswith("//", index):
        newline = source.find("\n", index + 2)
        return len(source) if newline == -1 else newline + 1
    if source.startswith("/*", index):
        depth = 1
        index += 2
        while index < len(source) and depth:
            if source.startswith("/*", index):
                depth += 1
                index += 2
            elif source.startswith("*/", index):
                depth -= 1
                index += 2
            else:
                index += 1
        return index
    if source[index] == '"':
        index += 1
        while index < len(source):
            if source[index] == "\\":
                index += 2
            elif source[index] == '"':
                return index + 1
            else:
                index += 1
        return index
    if source[index] == "'":
        # Skip character literals, but leave Rust lifetimes in the code stream.
        cursor = index + 1
        cursor += 2 if cursor < len(source) and source[cursor] == "\\" else 1
        if cursor < len(source) and source[cursor] == "'":
            return cursor + 1
    if source[index] == "r":
        cursor = index + 1
        while cursor < len(source) and source[cursor] == "#":
            cursor += 1
        if cursor < len(source) and source[cursor] == '"':
            hashes = cursor - index - 1
            terminator = '"' + ("#" * hashes)
            end = source.find(terminator, cursor + 1)
            return len(source) if end == -1 else end + len(terminator)
    return index


def _rust_matching_delimiter(source: str, opening: int, opener: str, closer: str) -> int:
    assert source[opening] == opener
    depth = 0
    index = opening
    while index < len(source):
        skipped = _skip_rust_lexeme(source, index)
        if skipped != index:
            index = skipped
            continue
        if source[index] == opener:
            depth += 1
        elif source[index] == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise AssertionError(f"unterminated Rust delimiter {opener!r}")


def _rust_function_body(source: str, name: str) -> str:
    pattern = re.compile(rf"\bfn\s+{re.escape(name)}\s*\(")
    index = 0
    match = None
    while index < len(source):
        skipped = _skip_rust_lexeme(source, index)
        if skipped != index:
            index = skipped
            continue
        match = pattern.match(source, index)
        if match:
            break
        index += 1
    assert match is not None, f"Rust function {name!r} not found"

    index = match.end()
    while index < len(source):
        skipped = _skip_rust_lexeme(source, index)
        if skipped != index:
            index = skipped
            continue
        if source[index] == "{":
            closing = _rust_matching_delimiter(source, index, "{", "}")
            return source[index + 1 : closing]
        index += 1
    raise AssertionError(f"Rust function {name!r} has no body")


def _rust_call(source: str, name: str) -> str:
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    index = 0
    while index < len(source):
        skipped = _skip_rust_lexeme(source, index)
        if skipped != index:
            index = skipped
            continue
        match = pattern.match(source, index)
        if match:
            opening = match.end() - 1
            closing = _rust_matching_delimiter(source, opening, "(", ")")
            return source[index : closing + 1]
        index += 1
    raise AssertionError(f"Rust call {name!r} not found")


def _rust_call_arguments(call: str) -> list[str]:
    opening = call.find("(")
    closing = _rust_matching_delimiter(call, opening, "(", ")")
    inner = call[opening + 1 : closing]
    arguments: list[str] = []
    start = 0
    depth = 0
    index = 0
    while index < len(inner):
        skipped = _skip_rust_lexeme(inner, index)
        if skipped != index:
            index = skipped
            continue
        if inner[index] in "([{":
            depth += 1
        elif inner[index] in ")]}":
            depth -= 1
        elif inner[index] == "," and depth == 0:
            arguments.append(inner[start:index].strip())
            start = index + 1
        index += 1
    if inner[start:].strip():
        arguments.append(inner[start:].strip())
    return arguments


def test_native_resident_client_has_bounded_admission() -> None:
    source = (ROOT / "src/codex_plugin_scanner/guard/native_runtime_resident.py").read_text(encoding="utf-8")
    assert "@native_resident_admission" in source
    assert "from .native_runtime_admission import native_resident_admission" in source


def test_daemon_http_server_is_bounded() -> None:
    source = (ROOT / "src/codex_plugin_scanner/guard/daemon/server.py").read_text(encoding="utf-8")
    assert "BoundedThreadingHTTPServer" in source
    assert "class _GuardDaemonHTTPServer(BoundedThreadingHTTPServer)" in source or (
        "BoundedThreadingHTTPServer(" in source and "ThreadingHTTPServer(" not in source
    )


def test_native_runtime_tracks_total_request_age() -> None:
    runtime_source = (ROOT / "rust/crates/guard-runtime/src/main.rs").read_text(encoding="utf-8")
    transport_source = (ROOT / "rust/crates/guard-runtime/src/resident_transport.rs").read_text(encoding="utf-8")
    assert "mod hardening;" in runtime_source
    assert "accepted_at: Instant" in transport_source
    assert "hardening::request_expired" in transport_source
    assert "native_request_deadline_exceeded" in transport_source


def test_native_io_failures_have_stable_non_integrity_classes() -> None:
    source = (ROOT / "rust/crates/guard-runtime/src/hardening.rs").read_text(encoding="utf-8")
    for reason in (
        "native_client_disconnected",
        "native_request_read_timeout",
        "native_response_write_timeout",
        "native_resource_pressure",
        "native_local_transport_changed",
    ):
        assert reason in source


def test_windows_resident_acl_application_does_not_assign_owner() -> None:
    source = (ROOT / "rust/crates/guard-runtime/src/resident_state_windows.rs").read_text(encoding="utf-8")
    function_body = _rust_function_body(source, "protect_windows_path")
    application = _rust_call(function_body, "SetNamedSecurityInfo")
    arguments = _rust_call_arguments(application)
    assert len(arguments) == 7
    assert "".join(arguments[2].split()) == "SecurityInformation::Dacl|SecurityInformation::ProtectedDacl"
    assert arguments[3] == "None"
    assert "WRITE_OWNER" not in source
    assert "verify_windows_path(path, &owner)" in function_body


def test_rust_acl_contract_extractor_ignores_imports_and_earlier_functions() -> None:
    source = """
use windows_permissions::wrappers::SetNamedSecurityInfo;
fn unrelated() {
    SetNamedSecurityInfo(path, object, SecurityInformation::Owner, Some(owner), None, None, None);
}
pub fn protect_windows_path(path: &Path) -> Result<(), String> {
    SetNamedSecurityInfo (
        path,
        object,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    );
}
"""
    body = _rust_function_body(source, "protect_windows_path")
    arguments = _rust_call_arguments(_rust_call(body, "SetNamedSecurityInfo"))
    assert arguments[3] == "None"


def test_doctor_reports_aggregate_admission_without_payloads() -> None:
    source = (ROOT / "src/codex_plugin_scanner/guard/cli/commands_dispatch_admin.py").read_text(encoding="utf-8")
    assert "native_resident_admission_snapshot" in source
    assert "daemon_admission_snapshot" in source
    combined = (ROOT / "src/codex_plugin_scanner/guard/native_runtime_admission.py").read_text(encoding="utf-8") + (
        ROOT / "src/codex_plugin_scanner/guard/daemon/bounded_http.py"
    ).read_text(encoding="utf-8")
    for prohibited in ("raw_command", "prompt_text", "request_payload", "environment_values", "credential"):
        assert prohibited not in combined
