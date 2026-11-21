use super::{manager_subcommands, usage_only};

fn admitted(manager: &str, line: &str) -> bool {
    let Some(subcommands) = manager_subcommands(manager) else {
        return false;
    };
    usage_only(
        manager,
        subcommands,
        &line.split_whitespace().collect::<Vec<_>>(),
    )
}

#[test]
fn a_usage_page_the_manager_prints_itself_is_admitted() {
    for (manager, line) in [
        ("npm", "install --help"),
        ("npm", "uninstall -h"),
        ("npm", "--help"),
        ("pip", "install --help"),
        ("pip3", "install --help"),
        ("pip", "help install"),
        ("uv", "sync --help"),
        ("gem", "install --help"),
        ("gem", "help install"),
        ("brew", "install --help"),
        ("brew", "help install"),
        ("apt-get", "install --help"),
        ("apt", "remove --help"),
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
        // The flag has to follow the subcommand directly.
        ("npm", "install express --help"),
        ("npm", "install --help express"),
        ("pip", "install -r requirements.txt --help"),
        // No help flag at all is the work itself.
        ("npm", "install"),
        // npm's `help` verb opens its configured viewer, not stdout.
        ("npm", "help install"),
        ("npm", "help"),
        // A word the manager does not carry is answered by something else:
        // a tap's command, a `cargo-<name>` binary, a project script.
        ("brew", "help my-tap-command"),
        ("gem", "help whatever"),
        ("pip", "help nonsense"),
        // No manager here documents a second level under `help`.
        ("brew", "help install formula"),
    ] {
        assert!(!admitted(manager, line), "{manager} {line}");
    }
}

/// A manager whose help path loads project code, or lets the project choose
/// the binary that answers, keeps its review, so none of them reaches a
/// subcommand table at all.
#[test]
fn a_manager_the_project_can_answer_for_is_absent() {
    for manager in [
        "yarn", "poetry", "composer", "bundle", "bundler", "pipenv", "pnpm", "cargo", "go", "bun",
        "helm", "docker", "git", "uvx",
    ] {
        assert!(manager_subcommands(manager).is_none(), "{manager}");
    }
}

/// A flag that only renders the page leaves the page where it was.
#[test]
fn a_flag_that_only_shapes_the_page_keeps_the_usage_reading() {
    for (manager, line) in [
        ("npm", "--help --json"),
        ("npm", "--json --help"),
        ("npm", "install --help --json"),
        ("npm", "install --json --help"),
        ("npm", "install --help --silent"),
        ("pip", "install --help -q"),
        ("pip", "install --help --disable-pip-version-check"),
        ("pip3", "install -qq --help"),
        ("uv", "add --help --no-cache"),
        ("gem", "install --help --silent"),
        ("brew", "install --help --quiet"),
        ("apt", "list --help -q"),
        ("apt-get", "install -qq --help"),
        ("pip", "help install --no-color"),
    ] {
        assert!(admitted(manager, line), "{manager} {line}");
    }
}

/// The flags above carry no value of their own, so a word that does keeps
/// its value on the line and the reading still refuses it. A flag belonging
/// to another manager is nobody's to drop.
#[test]
fn an_option_carrying_a_value_or_another_managers_flag_stays_reviewed() {
    for (manager, line) in [
        // `--loglevel` takes the word after it, which this reading refuses.
        ("npm", "install --loglevel silly --help"),
        ("pip", "install --log /tmp/pip.log --help"),
        // Dropping a flag never drops an operand with it.
        ("npm", "install --json express --help"),
        ("brew", "install --quiet formula --help"),
        // npm has no `--no-cache`, so the word is npm's to answer.
        ("npm", "install --help --no-cache"),
        // Nothing but a rendering flag names no page at all.
        ("npm", "--json"),
        ("pip", "-q"),
    ] {
        assert!(!admitted(manager, line), "{manager} {line}");
    }
}
