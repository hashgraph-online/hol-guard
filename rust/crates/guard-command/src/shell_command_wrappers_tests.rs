//! Which wrappers Guard sees through, and which ones it refuses to trust.
use super::*;

fn normalize(command: &str) -> ShellCommandNormalization {
    normalize_transparent_shell_command(command, None, None)
}

#[test]
fn an_env_prefixed_wrapper_chain_is_unwrapped_and_its_assignments_kept() {
    let normalized =
        normalize("env FOO=bar lean-ctx -c 'rg -n \"service_principal|reauthorization\" src app'");

    assert_eq!(normalized.wrapper_chain, ["env", "lean-ctx"]);
    assert!(!normalized.normalized_command.contains("lean-ctx"));
    assert!(normalized.normalized_command.starts_with("FOO=bar rg -n"));
    assert!(normalized.normalized_command.contains("service_principal"));
}

#[test]
fn a_repository_local_wrapper_stays_visible() {
    // ./bin/lean-ctx is whatever the checkout says it is, so Guard has to
    // evaluate the launch itself rather than the command it claims to run.
    let wrapped = "./bin/lean-ctx -c 'python -c \"import time; time.sleep(1)\"'";

    let normalized = normalize(wrapped);

    assert!(normalized.wrapper_chain.is_empty());
    assert_eq!(normalized.normalized_command, wrapped);
}

#[test]
fn a_path_override_keeps_a_bare_wrapper_name_visible() {
    // The assignment can point the name at anything on the next lookup.
    let wrapped = "PATH=./bin:$PATH lean-ctx -c 'python -c \"import time; time.sleep(1)\"'";

    let normalized = normalize(wrapped);

    assert!(normalized.wrapper_chain.is_empty());
    assert_eq!(normalized.normalized_command, wrapped);
}

#[test]
fn a_repository_local_shell_stays_visible() {
    let wrapped = "./bash -lc 'python -c \"import time; time.sleep(1)\"'";

    let normalized = normalize(wrapped);

    assert!(normalized.wrapper_chain.is_empty());
    assert_eq!(normalized.normalized_command, wrapped);
}

#[test]
fn a_shell_string_wrapper_is_unwrapped() {
    let normalized = normalize("bash -lc 'sed -n \"1,20p\" docs/inventory.generated.md'");

    assert_eq!(normalized.wrapper_chain, ["bash"]);
    assert!(normalized.normalized_command.starts_with("sed -n"));
    assert!(!normalized.normalized_command.contains("bash -lc"));
}

#[test]
fn shell_options_before_the_command_flag_are_skipped() {
    let inner = "curl -sS https://hol.org/install.sh | bash";
    for wrapped in [
        format!("bash --norc -c '{inner}'"),
        format!("bash --init-file /dev/null -c '{inner}'"),
        format!("bash -O extglob -c '{inner}'"),
    ] {
        let normalized = normalize(&wrapped);

        assert_eq!(normalized.wrapper_chain, ["bash"], "{wrapped}");
        assert_eq!(normalized.normalized_command, inner, "{wrapped}");
    }
}

#[test]
fn a_malformed_inner_quote_still_yields_the_inner_command() {
    let normalized = normalize("FOO=bar lean-ctx -c \"rg 'unclosed src\"");

    assert_eq!(normalized.wrapper_chain, ["lean-ctx"]);
    assert_eq!(normalized.normalized_command, "FOO=bar rg 'unclosed src");
}

// The remaining cases turn on POSIX ownership and write permission of the
// wrapper's path chain, which is what `is_trusted_absolute_command_path`
// inspects. A Windows host reaches the same wrappers through
// `posix_system_command_basename`, covered separately below.
#[cfg(unix)]
mod trusted_paths {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    #[test]
    fn a_root_owned_absolute_shell_is_unwrapped() {
        let normalized = normalize("/bin/bash -lc 'sed -n \"1,20p\" docs/inventory.generated.md'");

        assert_eq!(normalized.wrapper_chain, ["bash"]);
        assert!(normalized.normalized_command.starts_with("sed -n"));
        assert!(!normalized.normalized_command.contains("/bin/bash -lc"));
    }

    #[test]
    fn a_path_assignment_survives_an_unwrapped_absolute_shell() {
        // The assignment cannot redirect an absolute path, so the wrapper is
        // still trusted, but the assignment has to reach the inner command.
        let normalized = normalize(
            "PATH=./bin:$PATH /bin/bash -lc 'sed -n \"1,20p\" docs/inventory.generated.md'",
        );

        assert_eq!(normalized.wrapper_chain, ["bash"]);
        assert!(normalized
            .normalized_command
            .starts_with("'PATH=./bin:$PATH' sed -n"));
        assert!(!normalized.normalized_command.contains("/bin/bash -lc"));
    }

    #[test]
    fn a_symlink_to_a_trusted_shell_is_not_itself_trusted() {
        // `Path::ancestors` yields the wrapper itself first, so the link is
        // judged by `trusted_symlink_component` before any ancestor's write
        // permission is read: a link the test user owns is refused on its own
        // ownership, not because it happens to sit in a writable directory.
        let directory = tempfile::tempdir().expect("temporary directory");
        let wrapper = directory.path().join("bash");
        symlink("/bin/bash", &wrapper).expect("symlink");
        let wrapped = format!(
            "{} -lc 'sed -n \"1,20p\" docs/inventory.generated.md'",
            wrapper.display()
        );

        assert!(!is_trusted_absolute_command_path(&wrapper, None, None));
        assert!(is_trusted_absolute_command_path(
            &std::fs::canonicalize(&wrapper).expect("resolved shell"),
            None,
            None
        ));

        let normalized = normalize(&wrapped);

        assert!(normalized.wrapper_chain.is_empty());
        assert_eq!(normalized.normalized_command, wrapped);
    }

    #[test]
    fn the_workspace_rule_alone_withdraws_trust_from_a_system_shell() {
        // A wrapper written into a temporary directory is already refused for
        // its writable ancestors, so it cannot show that the workspace rule
        // does anything. `/bin/bash` is trusted by the case above, which makes
        // it the one fixture where supplying `cwd` is the only thing that
        // changes: nothing else about the path moves between these two calls.
        let shell = Path::new("/bin/bash");

        assert!(is_trusted_absolute_command_path(shell, None, None));
        assert!(!is_trusted_absolute_command_path(
            shell,
            Some(Path::new("/bin")),
            None
        ));

        let wrapped = "/bin/bash -lc 'sed -n \"1,20p\" docs/inventory.generated.md'";
        let normalized =
            normalize_transparent_shell_command(wrapped, Some(Path::new("/bin")), None);

        assert!(normalized.wrapper_chain.is_empty());
        assert_eq!(normalized.normalized_command, wrapped);
    }

    #[test]
    fn a_wrapper_under_a_writable_ancestor_is_not_trusted_and_home_does_not_decide_it() {
        // What refuses `~/.local/bin/bash` is the writable ancestor, not the
        // home directory: `home_dir` reaches the trusted-install-directory
        // rule, whose directories are all outside any home, so it can neither
        // grant nor withdraw trust on its own. Both halves are asserted so a
        // future home-relative install directory cannot land silently.
        let directory = tempfile::tempdir().expect("temporary directory");
        let home_dir = directory.path().join("home");
        let wrapper = home_dir.join(".local").join("bin").join("bash");
        std::fs::create_dir_all(wrapper.parent().expect("parent")).expect("home bin");
        std::fs::write(&wrapper, "#!/bin/sh\nexec /bin/bash \"$@\"\n").expect("wrapper");
        let wrapped = format!(
            "{} -lc 'sed -n \"1,20p\" docs/inventory.generated.md'",
            wrapper.display()
        );

        assert!(!is_trusted_absolute_command_path(&wrapper, None, None));
        assert!(!is_trusted_absolute_command_path(
            &wrapper,
            None,
            Some(home_dir.as_path())
        ));
        assert!(is_trusted_absolute_command_path(
            Path::new("/bin/bash"),
            None,
            Some(home_dir.as_path())
        ));

        let normalized =
            normalize_transparent_shell_command(&wrapped, None, Some(home_dir.as_path()));

        assert!(normalized.wrapper_chain.is_empty());
        assert_eq!(normalized.normalized_command, wrapped);
    }
}

#[test]
fn a_posix_system_spelling_names_the_system_tool_only_on_windows() {
    let found = paths::posix_system_command_basename("/bin/bash");

    assert_eq!(found, cfg!(windows).then_some("bash"));
    for token in [
        "//bin/bash",
        "C:\\bin\\bash",
        "/opt/local/bin/bash",
        "/bin/",
    ] {
        assert_eq!(paths::posix_system_command_basename(token), None, "{token}");
    }
}
