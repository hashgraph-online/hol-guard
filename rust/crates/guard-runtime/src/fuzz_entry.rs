//! Entry points for the fuzz targets in `rust/fuzz`.
//!
//! Each function takes the bytes a fuzzer produces and feeds them to a real
//! parser on an untrusted boundary: the resident's request frame, a command
//! model request, a shell command, scanned text, a harness's Python-flavoured
//! JSON, prompt text, the containment argument screens, and a package
//! registry's response body. A target asserts
//! nothing beyond "this input does not crash the parser"; libFuzzer reports a
//! panic, an abort, a sanitizer finding, or a timeout.
//!
//! Only parsing and classification is reachable from here. No entry point
//! dispatches an operation, touches the store, writes a file, or starts a
//! process, so a fuzzing run cannot have an effect outside its own process.
//! Nor does one read the filesystem: a screen that resolves a path against the
//! runner's own directory tree answers differently on every host, which makes
//! a finding unreproducible and a corpus worthless. Keep both true when adding
//! an entry point: a parser is fair game, an operation is not.
//!
//! The same functions replay the committed seed corpus as an ordinary test
//! (`fuzz_entry_tests.rs`), so a crash found by a campaign becomes a seed that
//! every pull request runs on the stable toolchain.

use std::time::{Duration, Instant};

/// The resident's request frame, as it arrives from a client: strict JSON
/// first, then the untagged request enum behind it.
pub fn resident_frame(data: &[u8]) {
    let Ok(value) = crate::resident_protocol::strict_json_value(data) else {
        return;
    };
    let _ = crate::strict_json::from_value::<crate::resident_protocol::ResidentRequestV1>(value);
}

/// A command model request: the envelope a harness sends, then the parse that
/// every command decision is built on.
pub fn command_request(data: &[u8]) {
    let Ok(request) = serde_json::from_slice::<guard_command::CommandModelRequestV1>(data) else {
        return;
    };
    if request.command.trim().is_empty() {
        return;
    }
    let _ = guard_command::parse_command(&request);
}

/// A shell command, in the one shape the command model actually parses. The
/// parser answers anything that is not POSIX in a shell string with an
/// `unsupported_` verdict before it tokenizes, so a target that offered a
/// choice of dialects would spend its budget on that early return and never
/// reach a pipeline, a redirect or a heredoc. The leading byte picks wrapper
/// normalization instead, which is a branch that does reach different code.
pub fn shell_command(data: &[u8]) {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    let _ = guard_command::command_model::parse_shell_command(
        text,
        None,
        None,
        "posix",
        "shell_string",
        "fuzz",
        selector % 2 == 0,
    );
}

/// Text through the secret scanner, bounded so a pathological input fails the
/// target's own deadline rather than the campaign's.
pub fn scanner_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_scanner::scan_text(
        text,
        true,
        false,
        1 << 20,
        Some(Instant::now() + Duration::from_secs(5)),
    );
}

/// Tool output as a harness writes it: JSON with CPython's own escapes and
/// duplicate-key rule.
pub fn python_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_runtime_pyjson::parse_unique(text);
    let _ = guard_runtime_pyjson::parse_marking_lone_surrogates(text);
}

/// Prompt text through the injection detectors and the `guard run` request
/// extractor.
pub fn prompt_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_command::prompt_analysis::detect_prompt_injection_requests(text);
    let _ = guard_command::prompt_analysis::extract_prompt_requests(text);
}

/// The containment screens a contained run is admitted by, every one of which
/// reads a `command` array out of the request it is given.
///
/// `contained_target` is deliberately absent. It resolves a virtual-environment
/// activation against the filesystem, so a campaign would be probing the
/// runner's own directory tree and would reach host-dependent answers, which
/// is both outside this module's promise and useless as a finding.
pub const CONTAINED_ARGV_OPERATIONS: &[&str] = &[
    "node_runtime_args",
    "python_runtime_args",
    "inline_eval",
    "test_script",
    "bun_vitest_invocation",
    "tsx_test_invocation",
    "vitest_arguments",
    "contained_kind",
    "launcher_program",
    "transparent_prefix",
];

/// The containment argument screens, which decide whether a contained run's
/// argv points out of the workspace it may touch. The leading byte picks one of
/// the screens and the rest is the JSON request it reads.
pub fn contained_path(data: &[u8]) {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(rest) else {
        return;
    };
    let operation =
        CONTAINED_ARGV_OPERATIONS[usize::from(*selector) % CONTAINED_ARGV_OPERATIONS.len()];
    let _ = guard_command::contained_argv::evaluate(operation, &value);
}

/// A package registry's response body. It arrives over the network from a host
/// Guard does not control, and what it says decides which release a
/// supply-chain review reasons about. The parse behind it is not only
/// `serde_json`: a hand-written deserializer reads the key order of the
/// `versions` object, because `serde_json::Map` sorts keys and the tie-break
/// between equally ranked versions depends on the document's own order.
pub fn registry_response(data: &[u8]) {
    let _ = guard_command::registry_metadata_transport::parse_registry_document(data);
}

/// One fuzz entry point: it takes the fuzzer's bytes and must not panic on any
/// of them.
pub type FuzzEntryPoint = fn(&[u8]);

/// Every entry point with the corpus directory it replays, so a new target
/// cannot be added without a seed corpus beside it.
pub const FUZZ_ENTRY_POINTS: &[(&str, FuzzEntryPoint)] = &[
    ("resident_frame", resident_frame),
    ("command_request", command_request),
    ("shell_command", shell_command),
    ("scanner_text", scanner_text),
    ("python_json", python_json),
    ("prompt_text", prompt_text),
    ("contained_path", contained_path),
    ("registry_response", registry_response),
];

#[cfg(test)]
#[path = "fuzz_entry_tests.rs"]
mod tests;
