use super::{manager_subcommands, usage_only};

fn admitted(manager: &str, line: &str) -> bool {
    let Some(subcommands) = manager_subcommands(manager) else {
        return false;
    };
    usage_only(subcommands, &line.split_whitespace().collect::<Vec<_>>())
}

#[test]
fn a_usage_page_the_manager_prints_itself_is_admitted() {
    for (manager, line) in [
        ("npm", "install --help"),
        ("npm", "uninstall -h"),
        ("npm", "help install"),
        ("npm", "--help"),
        ("pnpm", "add --help"),
        ("pnpm", "help add"),
        ("pip", "install --help"),
        ("pip3", "install --help"),
        ("pip", "help install"),
        ("cargo", "add --help"),
        ("cargo", "help add"),
        ("uv", "sync --help"),
        ("gem", "install --help"),
        ("brew", "install --help"),
        ("apt-get", "install --help"),
        ("apt", "remove --help"),
        ("go", "help build"),
    ] {
        assert!(admitted(manager, line), "{manager} {line}");
    }
}

#[test]
fn an_operand_a_missing_flag_or_a_word_the_manager_forwards_stays_reviewed() {
    for (manager, line) in [
        // A script, not a subcommand: npm hands the tail to it.
        ("npm", "run build --help"),
        ("npm", "test --help"),
        ("pnpm", "build --help"),
        // An external subcommand is a `cargo-<name>` binary of its own.
        ("cargo", "clippy --help"),
        // The flag has to follow the subcommand directly.
        ("npm", "install express --help"),
        ("npm", "install --help express"),
        ("pip", "install -r requirements.txt --help"),
        // No help flag at all is the work itself.
        ("npm", "install"),
        ("cargo", "add serde"),
        // `go` answers only the text verb here.
        ("go", "build --help"),
        ("go", "generate -h"),
    ] {
        assert!(!admitted(manager, line), "{manager} {line}");
    }
}

/// A manager whose help path loads project code before it prints keeps its
/// review, so none of them reaches a subcommand table at all.
#[test]
fn a_manager_that_loads_project_code_to_print_help_is_absent() {
    for manager in ["yarn", "poetry", "composer", "bundle", "bundler", "pipenv"] {
        assert!(manager_subcommands(manager).is_none(), "{manager}");
    }
}
