//! Lone version queries for common developer tools.
//!
//! A single version flag makes these programs print a banner and exit before
//! any subcommand, script, hook, or project file runs. The probe still
//! executes the named binary, so it follows the same identity rule as the
//! other bare-name probes (`node --version`, `rg`): only a bare basename with
//! no path separator, no environment prefix and no wrapper reaches this proof.
//! The caller enforces those preconditions.
//!
//! `node`, `python` and `wrangler` have their own argument proofs in
//! `safe_scalar` and `wrangler_reads`.
//!
//! Deliberately absent:
//! - `pytest`: it loads `conftest.py` files and ini-configured plugins before
//!   it prints its version, so the probe can run workspace code.
//! - `yarn` and `pnpm`: Yarn's `yarnPath` and Corepack's `packageManager`
//!   field select a workspace-supplied binary that the probe would execute.
//! - bare `kubectl version`: it contacts a server, and `kubectl_reads` admits
//!   that form after its kubeconfig checks. `docker_reads` admits
//!   `docker version`, whose daemon connection `docker ps` already uses.
//! - `cargo` and `rustc`: a workspace `rust-toolchain.toml` with a `path`
//!   makes the rustup proxy run that directory's binary. `rust_toolchain`
//!   admits their version queries only after checking the toolchain file.
//! - `go version`: a `go.mod` `toolchain` line makes `go` fetch and run a
//!   different toolchain.
//! - `-v` for tools where it means "verbose" rather than "version".
//! - `mysql` and `mysqldump`: their banner is printed by the same startup
//!   that reads the option files, and the long form prints what those files
//!   set, so the text can carry a configured credential. `help_probes`
//!   leaves them out for the same reason.
//!
//! The transfer and client tools below print their banner and exit before
//! they open a connection, read a transfer source or touch a destination, so
//! a lone version flag on one of them names no host and no path. `-V` is
//! admitted only where that spelling means version everywhere; `rsync -V`
//! and `psql -V` are newer spellings on some builds and older operands on
//! others, so only their long form is read as the question.

pub(super) fn safe_version_probe(basename: &str, arguments: &[String]) -> bool {
    match (basename, arguments) {
        // Server-contacting by default; `--client` keeps it local.
        ("kubectl", [subcommand, flag]) => {
            subcommand == "version" && matches!(flag.as_str(), "--client" | "--client=true")
        }
        (_, [flag]) => single_flag_probe(basename, flag),
        _ => false,
    }
}

/// A segment that is only a lone version query. The probe runs no project
/// file, so a verified `cd` before it changes nothing it does. `node` and
/// `python` use the interpreter proof in `safe_scalar`.
pub(super) fn lone_probe_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment.executable.as_deref().is_some_and(|executable| {
        safe_version_probe(executable, &segment.arguments)
            || super::safe_scalar::version_probe_arguments(executable, &segment.arguments)
    })
}

fn single_flag_probe(basename: &str, flag: &str) -> bool {
    let long = flag == "--version";
    match basename {
        "uv" | "pip" | "pip3" | "ruff" => long || flag == "-V",
        "npm" | "bun" | "deno" | "docker" => long || flag == "-v",
        "gh" | "jq" | "rg" | "fd" | "tsc" | "black" | "mypy" => long,
        "curl" | "wget" | "ssh" => long || flag == "-V",
        "scp" | "sftp" | "rsync" | "psql" | "redis-cli" | "cp" | "chown" => long,
        "git" => long || flag == "version",
        "helm" => flag == "version",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::safe_version_probe;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn lone_version_flags_are_admitted() {
        for (tool, flag) in [
            ("uv", "--version"),
            ("uv", "-V"),
            ("npm", "-v"),
            ("bun", "--version"),
            ("deno", "--version"),
            ("helm", "version"),
            ("pip", "--version"),
            ("ruff", "--version"),
            ("gh", "--version"),
            ("docker", "--version"),
            ("git", "--version"),
            ("git", "version"),
            ("jq", "--version"),
            ("rg", "--version"),
            ("fd", "--version"),
            ("curl", "--version"),
            ("curl", "-V"),
            ("wget", "--version"),
            ("ssh", "-V"),
            ("ssh", "--version"),
            ("scp", "--version"),
            ("sftp", "--version"),
            ("rsync", "--version"),
            ("psql", "--version"),
            ("redis-cli", "--version"),
            ("cp", "--version"),
            ("chown", "--version"),
        ] {
            assert!(safe_version_probe(tool, &args(&[flag])), "{tool} {flag}");
        }
        assert!(safe_version_probe(
            "kubectl",
            &args(&["version", "--client"])
        ));
    }

    #[test]
    fn ambiguous_server_or_workspace_selected_probes_are_refused() {
        for (tool, arguments) in [
            ("yarn", vec!["--version"]),
            ("pnpm", vec!["--version"]),
            ("kubectl", vec!["version"]),
            ("kubectl", vec!["--version"]),
            ("kubectl", vec!["version", "--output=yaml"]),
            ("pytest", vec!["--version"]),
            ("pytest", vec!["-v"]),
            ("pytest", vec!["-V", "extra"]),
            ("cargo", vec!["-v"]),
            ("cargo", vec!["--version"]),
            ("rustc", vec!["-V"]),
            ("rustc", vec!["--version"]),
            ("go", vec!["version"]),
            ("uv", vec!["--version", "run"]),
            ("uv", vec!["run", "--version"]),
            ("gh", vec!["version"]),
            ("go", vec!["--version"]),
            ("rg", vec!["-V"]),
            ("make", vec!["--version"]),
            ("npm", vec![]),
            // The banner is printed by the startup that reads the option
            // files, so it can carry what those files set.
            ("mysql", vec!["--version"]),
            ("mysqldump", vec!["--version"]),
            // `-V` is a version banner on some builds and an operand on
            // others, so only the long form is read as the question.
            ("rsync", vec!["-V"]),
            ("psql", vec!["-V"]),
            ("cp", vec!["-v"]),
            // A version flag with an operand behind it is a transfer.
            ("curl", vec!["--version", "https://example.test"]),
            ("scp", vec!["source", "--version"]),
        ] {
            assert!(
                !safe_version_probe(tool, &args(&arguments)),
                "{tool} {arguments:?}"
            );
        }
    }
}
