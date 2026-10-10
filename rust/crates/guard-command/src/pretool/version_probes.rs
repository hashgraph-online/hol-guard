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
//! - `docker version` and bare `kubectl version`: both contact a server.
//! - `cargo` and `rustc`: a workspace `rust-toolchain.toml` with an absolute
//!   `path` makes the rustup proxy run that directory's binary, and a
//!   `channel` makes it download a toolchain first.
//! - `go version`: a `go.mod` `toolchain` line makes `go` fetch and run a
//!   different toolchain.
//! - `-v` for tools where it means "verbose" rather than "version".

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

fn single_flag_probe(basename: &str, flag: &str) -> bool {
    let long = flag == "--version";
    match basename {
        "uv" | "pip" | "pip3" | "ruff" => long || flag == "-V",
        "npm" | "bun" | "deno" | "docker" => long || flag == "-v",
        "gh" | "jq" | "rg" | "fd" | "tsc" | "black" | "mypy" => long,
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
            ("docker", vec!["version"]),
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
        ] {
            assert!(
                !safe_version_probe(tool, &args(&arguments)),
                "{tool} {arguments:?}"
            );
        }
    }
}
