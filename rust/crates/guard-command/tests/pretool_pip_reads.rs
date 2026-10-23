#![cfg(unix)]
//! Installed-metadata reads with pip.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-pip-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let project = root.join("home/project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\n",
    )
    .unwrap();
    std::fs::canonicalize(root.join("home")).unwrap()
}

/// The decision every shell harness reaches, or the disagreement.
fn decide(home: &Path, command: &str) -> String {
    decide_with(home, command, &[])
}

fn decide_with(home: &Path, command: &str, environment_names: &[&str]) -> String {
    decide_in(home, command, environment_names, None)
}

/// The same decision for a session that exports `XDG_CONFIG_HOME`, with the
/// directory the stamp carries for it.
fn decide_with_xdg(home: &Path, command: &str, stamped: Option<&str>) -> String {
    decide_in(home, command, &["XDG_CONFIG_HOME"], stamped)
}

fn decide_in(
    home: &Path,
    command: &str,
    environment_names: &[&str],
    xdg_config_home: Option<&str>,
) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: environment_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: xdg_config_home.map(str::to_owned),
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    let decisions: Vec<String> = ["omp", "claude-code", "codex"]
        .iter()
        .map(|harness| {
            evaluate_pre_tool_envelope_with_execution_context(
                harness,
                "PreToolUse",
                &json!({"tool_name": "bash", "tool_input": {"command": command}}),
                None,
                None,
                PathContext {
                    home_dir: home.to_str(),
                    cwd: project.to_str(),
                    cdpath_unset: false,
                    rustup_override_absent: false,
                    npm_config_inert: false,
                    pip_config_inert: false,
                    shell_home_matches: false,
                    ripgrep_config_absent: false,
                    psql_environment: Default::default(),
                },
                Some(&environment),
            )
            .minimum_action
        })
        .collect();
    if decisions.iter().all(|decision| decision == &decisions[0]) {
        decisions[0].clone()
    } else {
        format!("mixed: {decisions:?}")
    }
}

// Agents check what an environment already holds before and after real work.
// None of these resolves, downloads or installs anything.
#[test]
fn installed_metadata_queries_proceed() {
    let home = home();
    for command in [
        "pip list",
        "pip list --format=json",
        "pip list --format=freeze",
        "pip list --local --not-required",
        "pip3 list",
        "pip list | head -20",
        "pip list 2>&1 | tail -5",
        "pip freeze",
        "pip freeze --exclude setuptools",
        "pip freeze | grep requests",
        "pip show requests",
        "pip show -f requests",
        "pip show requests urllib3",
        "pip check",
        "pip cache dir",
        "pip cache info",
        "pip cache list requests",
        "pip --version",
    ] {
        assert_eq!(decide(&home, command), "allow", "{command}");
    }
}

// Installs, index queries and cache deletions keep their review.
#[test]
fn installs_index_queries_and_cache_writes_stay_reviewed() {
    let home = home();
    for command in [
        "pip install requests",
        "pip install -r requirements.txt",
        "pip install -e .",
        "pip uninstall -y requests",
        "pip download requests",
        "pip wheel .",
        "pip list --outdated",
        "pip list -o",
        "pip list --index-url https://example.invalid/simple",
        "pip list --path /tmp/site-packages",
        "pip --log /tmp/pip.log list",
        "pip config list",
        "pip config set global.index-url https://example.invalid/simple",
        "pip debug",
        "pip freeze -r requirements.txt",
        "pip show ./local-dir",
        "pip cache purge",
        "pip cache remove requests",
    ] {
        assert_ne!(decide(&home, command), "allow", "{command}");
    }
}

// pip's configuration is an option by another name: an inherited variable or
// a user configuration file sets the same options the command line does, so
// an admitted listing must inherit neither.
#[test]
fn inherited_pip_configuration_returns_a_listing_to_review() {
    let home = home();
    assert_eq!(decide(&home, "pip list"), "allow");
    for name in [
        "PIP_LOG",
        "PIP_OUTDATED",
        "PIP_INDEX_URL",
        // Each of these moves a directory pip resolves its configuration
        // files through, so none leaves the file check looking at the files
        // pip would actually read.
        "XDG_CONFIG_DIRS",
        "XDG_DATA_HOME",
        "XDG_DATA_DIRS",
    ] {
        assert_ne!(decide_with(&home, "pip list", &[name]), "allow", "{name}");
    }
    // Options that only change how pip prints leave the listing admitted, and
    // so do the session variables that name no directory pip reads
    // configuration from.
    assert_eq!(
        decide_with(
            &home,
            "pip list",
            &[
                "PIP_DISABLE_PIP_VERSION_CHECK",
                "PIP_REQUIRE_VIRTUALENV",
                "XDG_RUNTIME_DIR",
                "XDG_SESSION_TYPE",
            ],
        ),
        "allow"
    );
}

#[test]
fn a_user_configuration_file_that_adds_an_option_returns_a_listing_to_review() {
    for (directory, file, body, admitted) in [
        (".config/pip", "pip.conf", "[global]\nquiet = 1\n", true),
        (
            ".config/pip",
            "pip.conf",
            "[list]\noutdated = true\n",
            false,
        ),
        (
            ".config/pip",
            "pip.conf",
            "[global]\nlog = /tmp/pip.log\n",
            false,
        ),
        (
            ".pip",
            "pip.conf",
            "[global]\nindex-url = https://example.invalid/simple\n",
            false,
        ),
        // The user configuration directory pip asks platformdirs for is this
        // one on macOS, so a listing is admitted only when it holds nothing
        // either.
        (
            "Library/Application Support/pip",
            "pip.conf",
            "[global]\nquiet = 1\n",
            true,
        ),
        (
            "Library/Application Support/pip",
            "pip.conf",
            "[list]\noutdated = true\n",
            false,
        ),
    ] {
        let home = home();
        std::fs::create_dir_all(home.join(directory)).unwrap();
        std::fs::write(home.join(directory).join(file), body).unwrap();
        let decision = decide(&home, "pip list");
        if admitted {
            assert_eq!(decision, "allow", "{body}");
        } else {
            assert_ne!(decision, "allow", "{body}");
        }
    }
}

// Every session that follows the base directory specification exports
// `XDG_CONFIG_HOME`, and pip reads its user configuration from the directory
// that names. The proof follows it there rather than returning every listing
// such a session runs to review.
#[test]
fn a_redirected_configuration_directory_is_read_where_pip_would_read_it() {
    let home = home();
    let redirect = home.join("xdg");
    std::fs::create_dir_all(redirect.join("pip")).unwrap();
    let stamped = redirect.to_str().unwrap().to_owned();

    // Nothing there yet, so the listing pip prints is the whole effect.
    assert_eq!(decide_with_xdg(&home, "pip list", Some(&stamped)), "allow");

    // A file that only changes how pip prints leaves the listing admitted.
    std::fs::write(
        redirect.join("pip").join("pip.conf"),
        "[global]\nquiet = 1\n",
    )
    .unwrap();
    assert_eq!(decide_with_xdg(&home, "pip list", Some(&stamped)), "allow");

    // A file that adds an index query returns it to review, exactly as the
    // same file under the default directory does.
    std::fs::write(
        redirect.join("pip").join("pip.conf"),
        "[list]\noutdated = true\n",
    )
    .unwrap();
    assert_ne!(decide_with_xdg(&home, "pip list", Some(&stamped)), "allow");
}

// The redirect is provable only when the stamp carries a directory the proof
// can resolve. Without one, the file check cannot see the `pip.conf` pip will
// read, so the listing keeps its review.
#[test]
fn an_unresolvable_redirect_returns_a_listing_to_review() {
    let home = home();
    assert_ne!(decide_with_xdg(&home, "pip list", None), "allow");
    assert_ne!(
        decide_with_xdg(&home, "pip list", Some("relative/config")),
        "allow"
    );
}
