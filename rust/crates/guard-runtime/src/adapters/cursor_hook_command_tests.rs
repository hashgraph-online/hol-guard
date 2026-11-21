//! `split_hook`: the hook command split the Python `split_hook_command_line`
//! made, now owned here.

use std::collections::BTreeMap;

use super::Syntax;

const SPACED: &str = r"C:\Program Files\HOL Guard's\.venv\Scripts\python.exe";
const SHORT: &str = r"C:\PROGRA~1\HOLGUA~1\.venv\Scripts\python.exe";

fn argv(first: &str) -> Vec<String> {
    [first, "-m", "codex_plugin_scanner.cli", "hook", "e30"]
        .iter()
        .map(|part| (*part).to_owned())
        .collect()
}

#[test]
fn posix_commands_split_with_shell_quoting() {
    let mut syntax = Syntax::new(false, BTreeMap::new());
    let command = "'/guard home/python' -m codex_plugin_scanner.cli hook e30";
    assert_eq!(syntax.split_hook(command), Some(argv("/guard home/python")));
    assert_eq!(syntax.split_hook("/guard/python -m 'unclosed"), None);
}

#[test]
fn windows_commands_split_with_the_c_runtime_rules() {
    let mut syntax = Syntax::new(true, BTreeMap::new());
    let command = format!("\"{SPACED}\" -m codex_plugin_scanner.cli hook e30");
    assert_eq!(syntax.split_hook(&command), Some(argv(SPACED)));
    assert!(syntax.short_tokens().is_empty());
}

#[test]
fn windows_powershell_calls_split_back_to_their_argv() {
    let mut syntax = Syntax::new(true, BTreeMap::new());
    let quoted = SPACED.replace('\'', "''");
    let command = format!("& '{quoted}' -m codex_plugin_scanner.cli hook e30");
    assert_eq!(syntax.split_hook(&command), Some(argv(SPACED)));
}

#[test]
fn windows_short_names_expand_only_with_the_host_long_form() {
    let command = format!("{SHORT} -m codex_plugin_scanner.cli hook e30");
    let mut unknown = Syntax::new(true, BTreeMap::new());
    assert_eq!(unknown.split_hook(&command), Some(argv(SHORT)));
    assert!(unknown.short_tokens().contains(SHORT));
    let mut known = Syntax::new(
        true,
        BTreeMap::from([(SHORT.to_owned(), SPACED.to_owned())]),
    );
    assert_eq!(known.split_hook(&command), Some(argv(SPACED)));
}

#[test]
fn windows_reads_legacy_posix_entries_with_shell_quoting() {
    let mut syntax = Syntax::new(true, BTreeMap::new());
    let command = "'/legacy/python' -m codex_plugin_scanner.cli hook e30";
    assert_eq!(syntax.split_hook(command), Some(argv("/legacy/python")));
}
