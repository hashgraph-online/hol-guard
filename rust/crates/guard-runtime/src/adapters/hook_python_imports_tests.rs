//! Hook commands that fall back to Python name a module and a function in
//! their `-c` code. Python files move as code ports to the native runtime,
//! and a command naming a module that is gone fails on every run with an
//! import error (Claude Code's SessionStart hook showed one at each session
//! start). These checks read the Rust source that writes those commands and
//! the Python package beside it, so a move breaks the build instead.

use std::path::{Path, PathBuf};

/// Every `from codex_plugin_scanner.<module> import <name>` in `source`,
/// including ones split over a Rust string continuation or over two
/// `"...".to_owned()` pieces.
fn imports(source: &str) -> Vec<(String, String)> {
    const PREFIX: &str = "from codex_plugin_scanner.";
    let not_ident = |c: char| !(c.is_ascii_alphanumeric() || c == '_');
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find(PREFIX) {
        rest = &rest[start + PREFIX.len()..];
        let Some(split) = rest.find(" import") else {
            break;
        };
        let module = rest[..split].to_owned();
        let mut after = rest[split + " import".len()..].trim_start_matches(not_ident);
        if let Some(next) = after.strip_prefix("to_owned") {
            after = next.trim_start_matches(not_ident);
        }
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        found.push((module, name));
    }
    found
}

fn package_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/codex_plugin_scanner")
}

/// Whether the Python package defines `name` in `module`.
fn defined(module: &str, name: &str) -> bool {
    let base = package_root().join(module.replace('.', "/"));
    let file = [base.with_extension("py"), base.join("__init__.py")]
        .into_iter()
        .find(|path| path.is_file());
    let Some(file) = file else {
        return false;
    };
    let text = std::fs::read_to_string(file).unwrap_or_default();
    text.lines().any(|line| {
        line.starts_with(&format!("def {name}("))
            || line.starts_with(&format!("class {name}("))
            || line.starts_with(&format!("class {name}:"))
    })
}

fn assert_resolves(writer: &str, source: &str) {
    let found = imports(source);
    assert!(!found.is_empty(), "{writer} writes no Python import");
    for (module, name) in found {
        assert!(
            defined(&module, &name),
            "{writer} writes `from codex_plugin_scanner.{module} import {name}`, \
             which the Python package does not define"
        );
    }
}

#[test]
fn claude_session_start_fallback_imports_a_defined_function() {
    assert_resolves(
        "claude_argv.rs",
        include_str!("harness_adapter/claude_argv.rs"),
    );
}

#[test]
fn cursor_daemon_recovery_imports_a_defined_function() {
    assert_resolves(
        "cursor_hook_script.rs",
        include_str!("cursor_hook_script.rs"),
    );
}

#[test]
fn opencode_plugin_fallback_imports_a_defined_function() {
    assert_resolves(
        "opencode_plugin_render.rs",
        include_str!("opencode_plugin_render.rs"),
    );
}

#[test]
fn pi_windows_fallback_imports_a_defined_function() {
    assert_resolves(
        "pi_extension.rs",
        include_str!("harness_adapter/pi_extension.rs"),
    );
}

#[test]
fn import_reader_follows_a_string_continuation() {
    let source = "\"x;from codex_plugin_scanner.guard.mod_a import \\\n             run_it;\"";
    assert_eq!(
        imports(source),
        vec![("guard.mod_a".to_owned(), "run_it".to_owned())]
    );
}

#[test]
fn import_reader_joins_two_string_pieces() {
    let source = "\"from codex_plugin_scanner.guard.mod_b import \".to_owned(),\n        \"run_that;\".to_owned(),";
    assert_eq!(
        imports(source),
        vec![("guard.mod_b".to_owned(), "run_that".to_owned())]
    );
}
