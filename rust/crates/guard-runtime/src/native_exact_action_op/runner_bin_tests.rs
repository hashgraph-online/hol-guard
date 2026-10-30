use super::{package_runner_target, runner_name};

fn target(tokens: &[&str]) -> Option<String> {
    package_runner_target(
        &tokens
            .iter()
            .map(|token| (*token).to_owned())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn a_runner_names_the_bin_it_launches() {
    assert_eq!(
        target(&["npx", "wrangler", "deploy"]).as_deref(),
        Some("wrangler")
    );
}

#[test]
fn an_exec_subcommand_is_stepped_over() {
    assert_eq!(
        target(&["npm", "exec", "--", "wrangler"]).as_deref(),
        Some("wrangler")
    );
    assert_eq!(
        target(&["pnpm", "x", "wrangler"]).as_deref(),
        Some("wrangler")
    );
}

#[test]
fn a_selector_option_names_no_bin() {
    assert_eq!(target(&["npx", "--package", "wrangler", "other"]), None);
    assert_eq!(target(&["npx", "-p", "wrangler", "other"]), None);
}

#[test]
fn the_yes_option_still_names_the_bin_after_it() {
    assert_eq!(
        target(&["npx", "-y", "wrangler"]).as_deref(),
        Some("wrangler")
    );
    assert_eq!(
        target(&["npx", "--yes", "wrangler"]).as_deref(),
        Some("wrangler")
    );
}

#[test]
fn a_runner_with_no_target_names_nothing() {
    assert_eq!(target(&["npx"]), None);
    assert_eq!(target(&[]), None);
}

#[test]
fn a_command_that_is_not_a_runner_names_nothing() {
    assert_eq!(target(&["wrangler", "deploy"]), None);
}

#[test]
fn a_windows_spelling_of_a_runner_is_the_same_runner() {
    assert_eq!(runner_name("npx.cmd"), Some("npx"));
    assert_eq!(runner_name("C:\\tools\\NPX.EXE"), Some("npx"));
    assert_eq!(
        target(&["npx.cmd", "wrangler"]).as_deref(),
        Some("wrangler")
    );
}

#[test]
fn a_path_spelled_runner_is_the_runner_it_names() {
    assert_eq!(runner_name("/usr/local/bin/pnpx"), Some("pnpx"));
    assert_eq!(runner_name("/usr/local/bin/wrangler"), None);
}
