#!/usr/bin/env python3
"""Integrate the daemon edge-hardening modules into the current release tree."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, value: str) -> None:
    (ROOT / path).write_text(value, encoding="utf-8")


def insert_after_future(source: str, import_line: str) -> str:
    if import_line in source:
        return source
    marker = "from __future__ import annotations\n"
    if marker not in source:
        raise RuntimeError(f"missing future-import anchor for {import_line}")
    return source.replace(marker, marker + "\n" + import_line + "\n", 1)


def integrate_resident_client() -> None:
    path = "src/codex_plugin_scanner/guard/native_runtime_resident.py"
    source = read(path)
    source = insert_after_future(
        source,
        "from .native_runtime_admission import native_resident_admission",
    )
    if "@native_resident_admission\ndef resident_native_request(" not in source:
        updated, count = re.subn(
            r"(?m)^def resident_native_request\(",
            "@native_resident_admission\ndef resident_native_request(",
            source,
            count=1,
        )
        if count != 1:
            raise RuntimeError("resident_native_request integration anchor changed")
        source = updated
    write(path, source)


def integrate_http_server() -> None:
    path = "src/codex_plugin_scanner/guard/daemon/server.py"
    source = read(path)
    source = insert_after_future(
        source,
        "from .bounded_http import BoundedThreadingHTTPServer",
    )
    source, class_count = re.subn(
        r"(?m)^class (\w+)\(ThreadingHTTPServer\):",
        r"class \1(BoundedThreadingHTTPServer):",
        source,
    )
    constructor_count = 0
    if class_count == 0:
        source, constructor_count = re.subn(
            r"(?<![A-Za-z])ThreadingHTTPServer\(",
            "BoundedThreadingHTTPServer(",
            source,
        )
    if class_count + constructor_count == 0 and "BoundedThreadingHTTPServer" not in source.replace(
        "from .bounded_http import BoundedThreadingHTTPServer", ""
    ):
        raise RuntimeError("daemon HTTP server integration anchor changed")
    write(path, source)


def integrate_doctor() -> None:
    path = "src/codex_plugin_scanner/guard/cli/commands_dispatch_admin.py"
    source = read(path)
    source = insert_after_future(
        source,
        "from ..daemon.bounded_http import daemon_admission_snapshot\nfrom ..native_runtime_admission import native_resident_admission_snapshot",
    )
    statements = (
        '    native_runtime_payload["admission"] = native_resident_admission_snapshot()\n'
        '    native_runtime_payload["daemon_http"] = daemon_admission_snapshot()\n'
    )
    if 'native_runtime_payload["admission"]' not in source:
        operation_anchor = '    native_runtime_payload["operations"] = native_core_metrics_snapshot()\n'
        payload_anchor = '    payload["native_runtime"] = native_runtime_payload\n'
        if operation_anchor in source:
            source = source.replace(operation_anchor, operation_anchor + statements, 1)
        elif payload_anchor in source:
            source = source.replace(payload_anchor, statements + payload_anchor, 1)
        else:
            raise RuntimeError("native doctor payload anchor changed")
    write(path, source)


def matching_brace(source: str, opening: int) -> int:
    depth = 0
    in_string = False
    escaped = False
    quote = ""
    index = opening
    while index < len(source):
        char = source[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in {'"', "'"}:
            in_string = True
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise RuntimeError("unbalanced Rust braces")


def add_pending_timestamps(source: str) -> str:
    struct_match = re.search(r"struct PendingRequest\s*\{", source)
    if struct_match is None:
        raise RuntimeError("PendingRequest struct not found")
    struct_end = matching_brace(source, source.index("{", struct_match.start()))
    struct_body = source[struct_match.start() : struct_end]
    if "accepted_at: Instant" not in struct_body:
        field_anchor = re.search(r"(?m)^(\s*)length:\s*usize,\s*$", struct_body)
        if field_anchor is None:
            raise RuntimeError("PendingRequest length field anchor changed")
        insertion = field_anchor.group(0) + f"\n{field_anchor.group(1)}accepted_at: Instant,"
        struct_body = struct_body[: field_anchor.start()] + insertion + struct_body[field_anchor.end() :]
        source = source[: struct_match.start()] + struct_body + source[struct_end:]

    search_at = 0
    constructor_count = 0
    while True:
        match = re.search(r"\bPendingRequest\s*\{", source[search_at:])
        if match is None:
            break
        start = search_at + match.start()
        if start == struct_match.start():
            search_at = start + len("PendingRequest")
            continue
        opening = source.index("{", start)
        closing = matching_brace(source, opening)
        body = source[opening + 1 : closing]
        if "accepted_at:" not in body:
            line_start = source.rfind("\n", opening, closing) + 1
            indent_match = re.match(r"\s*", source[line_start:closing])
            indent = indent_match.group(0) if indent_match else "        "
            source = source[:closing] + f"{indent}accepted_at: Instant,\n" + source[closing:]
            closing += len(indent) + len("accepted_at: Instant,\n")
            constructor_count += 1
        search_at = closing + 1
    if constructor_count == 0 and source.count("accepted_at: Instant") < 2:
        raise RuntimeError("PendingRequest constructors were not timestamped")
    return source


def add_stale_request_gate(source: str) -> str:
    if "native_request_deadline_exceeded" in source:
        return source
    function_pattern = re.compile(
        r"fn\s+(?P<name>[A-Za-z0-9_]+)\s*\((?P<params>.*?)\)\s*->\s*Result(?P<return>.*?)\{",
        re.DOTALL,
    )
    for match in function_pattern.finditer(source):
        params = match.group("params")
        if "PendingRequest" not in params or len(params) > 1500 or len(match.group("return")) > 500:
            continue
        variable_match = re.search(
            r"(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:&\s*(?:mut\s*)?)?PendingRequest",
            params,
        )
        if variable_match is None:
            continue
        variable = variable_match.group("variable")
        insertion = (
            f"\n    if hardening::request_expired({variable}.accepted_at) {{\n"
            '        return Err("native_request_deadline_exceeded".to_owned());\n'
            "    }\n"
        )
        return source[: match.end()] + insertion + source[match.end() :]
    raise RuntimeError("could not locate PendingRequest evaluation function")


def integrate_rust_runtime() -> None:
    path = "rust/crates/guard-runtime/src/main.rs"
    source = read(path)
    if "mod hardening;" not in source:
        forbid = "#![forbid(unsafe_code)]\n"
        if forbid not in source:
            raise RuntimeError("Rust unsafe-forbid anchor missing")
        source = source.replace(forbid, forbid + "\nmod hardening;\n", 1)
    source = re.sub(
        r"use std::time::Duration;",
        "use std::time::{Duration, Instant};",
        source,
        count=1,
    )
    if "Instant" not in source:
        raise RuntimeError("Rust Instant import integration failed")
    source = add_pending_timestamps(source)
    source = add_stale_request_gate(source)

    def map_io(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        code = match.group("code")
        mapper = "write_error" if "write" in code else "read_error"
        return f'{prefix}.map_err(|error| hardening::{mapper}(&error, "{code}"))?'

    source = re.sub(
        r'(?P<prefix>[^;\n]+)\.map_err\(\|_\|\s*"(?P<code>native_[a-z0-9_]*(?:read|write)[a-z0-9_]*)"\.to_owned\(\)\)\?',
        map_io,
        source,
    )

    def backoff(match: re.Match[str]) -> str:
        variable = match.group("variable")
        return (
            f"Err({variable}) => {{\n"
            f"                thread::sleep(hardening::accept_retry_delay(3, &{variable}));"
        )

    source = re.sub(
        r"Err\((?P<variable>[A-Za-z_][A-Za-z0-9_]*)\)\s*=>\s*\{\s*thread::sleep\(ACCEPT_RETRY_DELAY\);",
        backoff,
        source,
    )
    write(path, source)


def main() -> None:
    integrate_resident_client()
    integrate_http_server()
    integrate_doctor()
    integrate_rust_runtime()


if __name__ == "__main__":
    main()
