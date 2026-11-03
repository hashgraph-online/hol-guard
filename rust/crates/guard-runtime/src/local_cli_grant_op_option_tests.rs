//! How the options and later commands a call passes refine its grant.

use std::collections::BTreeSet;

use super::*;

/// The answer for a script call that passes `options`, against a catalog that
/// lists `deploy` (allowed), `status` (unset), `--dry-run` (allowed), `--force`
/// (`force`) and `--repo` (unset).
fn catalog_state(
    force: Option<&str>,
    root: Option<&str>,
    command: &str,
    options: &[&str],
) -> String {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "root", root);
    fixture.command(&identity, "deploy", Some("allow"));
    fixture.command(&identity, "status", None);
    fixture.command(&identity, "--dry-run", Some("allow"));
    fixture.command(&identity, "--force", force);
    fixture.command(&identity, "--repo", None);
    let mut request = fixture.request(&identity.source, "review", Some(command));
    request.options = options.iter().map(|option| (*option).to_owned()).collect();
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"]["state"].as_str().unwrap().to_owned()
}

/// `catalog_state` with `--force` blocked.
fn option_state(root: Option<&str>, command: &str, options: &[&str]) -> String {
    catalog_state(Some("block"), root, command, options)
}

#[test]
fn an_allowed_option_allows_a_root_call_that_passes_only_it() {
    assert_eq!(option_state(None, "root", &["--dry-run"]), "allowed");
    // The root row is the call with no options, so its block does not reach
    // a call the operator allowed by its option.
    assert_eq!(
        option_state(Some("block"), "root", &["--dry-run"]),
        "allowed"
    );
}

#[test]
fn a_blocked_option_blocks_the_call() {
    assert_eq!(option_state(Some("allow"), "root", &["--force"]), "blocked");
    assert_eq!(
        option_state(Some("allow"), "root", &["--dry-run", "--force"]),
        "blocked"
    );
    assert_eq!(option_state(None, "deploy", &["--force"]), "blocked");
}

#[test]
fn an_unset_or_unlisted_option_leaves_a_root_call_to_review() {
    assert_eq!(option_state(None, "root", &["--repo"]), "none");
    assert_eq!(option_state(Some("allow"), "root", &["--repo"]), "none");
    assert_eq!(
        option_state(Some("allow"), "root", &["--dry-run", "--repo"]),
        "none"
    );
    // An abbreviation, alias or bundle the catalog does not list never rides
    // on an allowed option or command while another option is blocked.
    assert_eq!(option_state(Some("allow"), "root", &["--dry"]), "none");
    assert_eq!(option_state(Some("allow"), "root", &["-?"]), "none");
}

#[test]
fn a_blocked_root_still_blocks_a_call_whose_options_are_not_all_allowed() {
    assert_eq!(option_state(Some("block"), "root", &["--repo"]), "blocked");
    assert_eq!(option_state(Some("block"), "root", &["-?"]), "blocked");
    assert_eq!(
        catalog_state(None, Some("block"), "root", &["--dry-run", "--repo"]),
        "blocked"
    );
}

#[test]
fn a_root_call_without_options_reads_the_root_row() {
    assert_eq!(option_state(Some("allow"), "root", &[]), "allowed");
    assert_eq!(option_state(Some("block"), "root", &[]), "blocked");
    assert_eq!(option_state(None, "root", &[]), "none");
}

#[test]
fn an_allowed_command_covers_unset_options_only_while_none_is_blocked() {
    assert_eq!(catalog_state(None, None, "deploy", &["--repo"]), "allowed");
    assert_eq!(catalog_state(None, None, "deploy", &["-f"]), "allowed");
    assert_eq!(
        catalog_state(None, Some("allow"), "root", &["--repo"]),
        "allowed"
    );
    // `-f`, `--forc` or `-fv` could be the blocked `--force` under another
    // spelling, so the allowed command no longer covers them.
    for unlisted in ["--repo", "-f", "--forc", "-?"] {
        assert_eq!(
            option_state(None, "deploy", &[unlisted]),
            "none",
            "{unlisted}"
        );
    }
    assert_eq!(option_state(None, "deploy", &["--dry-run"]), "allowed");
}

#[test]
fn a_command_named_after_an_option_is_read_too() {
    // `tool --dry-run deploy` resolves to the root; `deploy` comes along.
    assert_eq!(
        option_state(None, "root", &["deploy", "--dry-run"]),
        "allowed"
    );
    assert_eq!(option_state(None, "root", &["status", "--dry-run"]), "none");
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "root", Some("allow"));
    fixture.command(&identity, "deploy", Some("block"));
    fixture.command(&identity, "--dry-run", Some("allow"));
    let mut request = fixture.request(&identity.source, "review", Some("root"));
    request.options = vec!["deploy".to_owned(), "--dry-run".to_owned()];
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["payload"]["state"], "blocked", "{reply}");
}

#[test]
fn a_catalog_without_option_rows_decides_as_before() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "root", Some("allow"));
    let mut request = fixture.request(&identity.source, "review", Some("root"));
    request.options = vec!["--anything".to_owned()];
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["payload"]["state"], "allowed");
}

#[test]
fn malformed_options_are_refused() {
    let fixture = Fixture::new();
    let identity = script();
    for options in [
        vec![String::new()],
        vec!["--é".to_owned()],
        vec!["-x".to_owned(); 33],
    ] {
        let mut request = fixture.request(&identity.source, "review", Some("root"));
        request.options = options;
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["code"], "native_local_cli_grant_command_invalid");
    }
}

fn owned(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|a| (*a).to_owned()).collect()
}

#[test]
fn invocation_options_reads_every_option_name_past_a_bare_double_dash() {
    let read = |arguments: &[&str]| super::super::options::invocation_options(&owned(arguments));
    // Many scripts never treat `--` as the end of options, so `--force` after
    // it still reaches them and is read.
    assert_eq!(
        read(&["deploy", "--repo=x/y", "-v", "-", "--repo", "--", "--force"]),
        ["--repo", "-v", "--force"]
    );
    assert_eq!(read(&["-abc", "--é", "-v"]), ["-?", "-v"]);
    // No catalog lists these, so they never read as unset options.
    assert_eq!(read(&["--help", "--version", "-h"]), ["-h"]);
    let many: Vec<String> = (0..40).map(|n| format!("--o{n}")).collect();
    let options = super::super::options::invocation_options(&many);
    assert_eq!(options.len(), 32);
    assert_eq!(options.last().map(String::as_str), Some("-?"));
}

#[test]
fn invocation_entries_reads_catalogued_commands_named_after_an_option() {
    let catalog: BTreeSet<String> = ["root", "other", "deploy", "deploy.prod", "--dry-run"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let read = |arguments: &[&str], command: &str| {
        super::super::invocation_entries(&owned(arguments), command, &catalog)
    };
    assert_eq!(
        read(&["--dry-run", "deploy"], "root"),
        ["deploy", "--dry-run"]
    );
    assert_eq!(
        read(&["deploy", "-v", "prod"], "deploy"),
        ["deploy.prod", "-v"]
    );
    // Commands before the first option are the command's own tokens, and the
    // reserved ids never come along.
    assert_eq!(read(&["deploy", "--dry-run"], "deploy"), ["--dry-run"]);
    assert_eq!(read(&["-v", "root", "other", "x"], "root"), ["-v"]);
    let mut many = vec!["-v".to_owned(), "deploy".to_owned()];
    many.extend((0..40).map(|n| format!("--o{n}")));
    let entries = super::super::invocation_entries(&many, "root", &catalog);
    assert_eq!(entries.len(), 32);
    assert_eq!(entries.first().map(String::as_str), Some("deploy"));
    assert_eq!(entries.last().map(String::as_str), Some("-?"));
}
