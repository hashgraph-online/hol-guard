//! Replays the committed fuzz corpus on the stable toolchain.
//!
//! A libFuzzer campaign needs a nightly compiler and a sanitizer build, which
//! no pull request pays for. These tests run the same entry points over the
//! same seeds with `cargo test`, so a crash a campaign found stays fixed: the
//! input that found it is committed as a seed and every pull request replays
//! it.

use std::path::{Path, PathBuf};

fn fuzz_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let directory = fuzz_root().join("corpus").join(target);
    let entries = std::fs::read_dir(&directory).unwrap_or_else(|error| {
        panic!(
            "corpus directory {} is unreadable: {error}",
            directory.display()
        )
    });
    let mut seeds = Vec::new();
    for entry in entries {
        let path = entry.expect("corpus entry is readable").path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("seed is readable");
            seeds.push((path, bytes));
        }
    }
    seeds.sort();
    seeds
}

#[test]
fn every_entry_point_has_a_fuzz_target_and_a_corpus() {
    for (name, _) in super::FUZZ_ENTRY_POINTS {
        let target = fuzz_root().join("fuzz_targets").join(format!("{name}.rs"));
        assert!(
            target.is_file(),
            "{name} has no fuzz target at {}",
            target.display()
        );
        assert!(!seeds(name).is_empty(), "{name} has no committed seeds");
    }
}

#[test]
fn committed_seeds_do_not_crash_their_entry_point() {
    for (name, entry) in super::FUZZ_ENTRY_POINTS {
        let entry = *entry;
        for (path, bytes) in seeds(name) {
            let outcome = std::panic::catch_unwind(|| entry(&bytes));
            assert!(
                outcome.is_ok(),
                "{name} panicked on seed {}",
                path.display()
            );
        }
    }
}

#[test]
fn entry_points_accept_empty_and_truncated_input() {
    for (_, entry) in super::FUZZ_ENTRY_POINTS {
        entry(b"");
        entry(b"\x00");
        entry(b"{");
        entry(&[0xff, 0xfe, 0xfd]);
    }
}

#[test]
fn a_shell_command_seed_reaches_the_parser_rather_than_the_dialect_gate() {
    for selector in 0u8..2 {
        let mut input = vec![selector];
        input.extend_from_slice(b"cd /tmp && rm -rf ./build");
        super::shell_command(&input);
    }
    // The arguments the entry point passes, parsed here so the test can see
    // the answer. Anything other than POSIX in a shell string is answered
    // before the parser tokenizes, so a target that offered a choice of
    // dialects would be fuzzing that early return and nothing else.
    let parsed = guard_command::command_model::parse_shell_command(
        "cd /tmp && rm -rf ./build",
        None,
        None,
        "posix",
        "shell_string",
        "fuzz",
        true,
    );
    assert!(
        !parsed
            .uncertainty_reason
            .as_deref()
            .unwrap_or_default()
            .starts_with("unsupported_"),
        "the dialect the entry point sends is refused before parsing: {:?}",
        parsed.uncertainty_reason
    );
    assert!(
        parsed.segments.len() >= 2,
        "the parser never read the chain: {:?}",
        parsed.segments
    );
}

#[test]
fn every_contained_path_operation_is_one_the_screen_answers() {
    let request = serde_json::json!({ "command": ["node", "-e", "require('fs')"] });
    for operation in super::CONTAINED_ARGV_OPERATIONS {
        assert!(
            guard_command::contained_argv::evaluate(operation, &request).is_some(),
            "{operation} is not an operation the containment screen answers, so the \
             target replays its seeds into a no-op"
        );
    }
    assert!(
        !super::CONTAINED_ARGV_OPERATIONS.contains(&"contained_target"),
        "contained_target resolves an activation against the filesystem, which makes \
         a finding depend on the runner's own directory tree"
    );
}

#[test]
fn a_contained_path_seed_reaches_every_screen_in_turn() {
    let request = br#"{"command":["npx","jest","-ic../outside/jest.config.js"]}"#;
    for selector in 0..=u8::try_from(super::CONTAINED_ARGV_OPERATIONS.len()).unwrap() {
        let mut input = vec![selector];
        input.extend_from_slice(request);
        super::contained_path(&input);
    }
}

#[test]
fn a_resident_frame_entry_point_accepts_a_real_hook_request() {
    let frame = br#"{"schema":"guard.native.hook.request.v1","harness":"claude-code"}"#;
    super::resident_frame(frame);
}
