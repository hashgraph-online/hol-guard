//! Usage text: `uv add --help`, `npm install --help`, `curl --help`.
//!
//! A help flag makes these programs print their own usage and exit before the
//! verb in front of it resolves a name, contacts a registry, downloads an
//! archive or writes a lockfile. Nothing is installed, transferred, copied or
//! signalled, so the command is the same kind of question as the version
//! probe next door: a tool that takes no verb prints the same text whatever
//! host, file or process the operator was about to name.
//!
//! The probe still executes the named binary, so it keeps the identity rule
//! the other bare-name probes use: only a bare basename with no path
//! separator, no environment prefix and no wrapper reaches this proof, and
//! [`super::segment_proof::exact_safe_segment_with_context`] enforces those
//! preconditions before it asks.
//!
//! The verb in front of the flag is read against the manager that owns it,
//! never a shared list, because the same word means different things to
//! different launchers: `uv run pytest --help` loads every `conftest.py` the
//! collection reaches, `bun check --help` runs the workspace's `check`
//! script, and `helm audit --help` dispatches to a plugin of that name. So
//! each manager admits only verbs that are its own built-ins and that name no
//! program to run.
//!
//! A manager that documents a second level is read a level deeper, with the
//! second word judged against the first: `uv tool install --help` and `npm
//! cache clean --help` print the page the manager carries for that pair.
//! Reading the pair rather than two independent words is what keeps `uv tool
//! run --help` out, since `run` is carried by no parent, and it also keeps
//! out pairs the manager never documents and would answer with a usage error.
//!
//! Deliberately absent:
//! - `uvx`: it is `uv tool run`, so its first word is a package to fetch and
//!   execute. `uvx build --help` runs `build` from the index.
//! - `bun`: `bun <word>` falls back to `bun run <word>`, which runs the
//!   workspace's `package.json` script or a file of that name.
//! - `helm`: a plugin whose name matches the verb takes the command, so the
//!   usage text would come from a binary the command never names.
//! - `docker`: `docker --help` lists CLI plugins, and it discovers them by
//!   executing each one's metadata command. That holds for every usage page
//!   the client prints, not only the top-level one: the root help function
//!   adds the plugin stubs before it renders any of them, so `docker ps
//!   --help` runs the same binaries. `docker help <word>` is worse again,
//!   because it hands the page to the `docker-<word>` plugin to print.
//! - `yarn` and `pnpm`: Yarn's `yarnPath` and Corepack's `packageManager`
//!   field select a workspace-supplied binary that the probe would execute,
//!   for the same reason the version probe refuses them.
//! - `cargo` and `go`: a `rust-toolchain.toml` `path` or a `go.mod`
//!   `toolchain` line makes the launcher fetch and run a different toolchain.
//! - `git`: `git <verb> --help` opens the manual page through the configured
//!   pager, which runs a program the command never names.
//! - `npm help <verb>`: the `help` verb opens npm's configured viewer, which
//!   is `man` on Unix. Only the `--help` flag prints to stdout.
//! - `npm init` and `npm create`: they resolve a `create-*` package and run
//!   it, so the word after them is a program.
//! - `mysql` and `mysqldump`: their usage text lists the option files they
//!   read and the values those files set, so the help output can print a
//!   configured credential the command never asked for.
//! - `brew` and `apt-get`: a package manager's usage text is answered by the
//!   package lane, which already carries their proofs.
//! - `launchctl`: it sits under the privilege floor, which no usage text
//!   lowers.
//!
//! The tools in the second group below take no verb at all, so only the lone
//! flag is admitted and a short flag is admitted only where that spelling
//! means help everywhere: `rsync -h` is `--human-readable`, and `psql -h`,
//! `redis-cli -h` and `nc -h` name a host.

/// The tools whose usage text goes to stdout, with the spellings each one
/// reads as a request for that text rather than as something else.
fn help_flag(basename: &str, flag: &str) -> bool {
    match basename {
        // `-h` is the help flag for all of these.
        "uv" | "pip" | "pip3" | "npm" | "deno" | "ruff" | "black" | "mypy" | "rg" | "fd" | "jq"
        | "tsc" | "wget" => matches!(flag, "--help" | "-h"),
        // curl prints its bundled manual to stdout the same way.
        "curl" => matches!(flag, "--help" | "-h" | "--manual" | "-M"),
        // These print usage and exit without opening a connection, copying a
        // file or signalling a process. Their `-h` means something else, or
        // means different things on different builds, so only the long
        // spelling is read as a request for the text.
        "ssh" | "scp" | "sftp" | "rsync" | "psql" | "redis-cli" | "nc" | "cp" | "chown"
        | "kill" => flag == "--help",
        _ => false,
    }
}

/// A built-in verb of this manager that names no program to run, so the help
/// flag after it is read by the manager itself.
fn usage_only_verb(basename: &str, verb: &str) -> bool {
    match basename {
        "uv" => matches!(
            verb,
            "add"
                | "auth"
                | "build"
                | "cache"
                | "export"
                | "init"
                | "install"
                | "lock"
                | "pip"
                | "publish"
                | "python"
                | "remove"
                | "self"
                | "sync"
                | "tool"
                | "tree"
                | "uninstall"
                | "venv"
                | "version"
        ),
        "pip" | "pip3" => matches!(
            verb,
            "cache"
                | "check"
                | "config"
                | "download"
                | "freeze"
                | "index"
                | "inspect"
                | "install"
                | "list"
                | "show"
                | "uninstall"
                | "wheel"
        ),
        // npm resolves its own aliases from a table it carries, so `add` is
        // `install` and `info` is `view` before anything else happens. The
        // names below are those aliases, each standing for a verb this arm
        // already admits. The three npm aliases that name a program to run
        // stay out with the verbs they point at: `create` is `init`, `x` is
        // `exec`, and `run` is `run-script`.
        "npm" => matches!(
            verb,
            "access"
                | "add"
                | "audit"
                | "cache"
                | "ci"
                | "clean-install"
                | "config"
                | "ddp"
                | "dedupe"
                | "dist-tag"
                | "explain"
                | "i"
                | "ic"
                | "in"
                | "info"
                | "install"
                | "la"
                | "link"
                | "list"
                | "ll"
                | "ln"
                | "ls"
                | "org"
                | "outdated"
                | "owner"
                | "pkg"
                | "profile"
                | "prune"
                | "publish"
                | "r"
                | "remove"
                | "rm"
                | "show"
                | "team"
                | "token"
                | "un"
                | "uninstall"
                | "unlink"
                | "up"
                | "update"
                | "v"
                | "view"
                | "why"
        ),
        "deno" => matches!(
            verb,
            "add"
                | "check"
                | "fmt"
                | "info"
                | "install"
                | "lint"
                | "outdated"
                | "publish"
                | "remove"
                | "uninstall"
                | "upgrade"
        ),
        "ruff" => matches!(verb, "check" | "clean" | "config" | "format" | "linter"),
        // The single-purpose tools take no verb at all.
        _ => false,
    }
}

/// A verb carried by one of the manager's own verbs, where the pair names no
/// program to run.
///
/// `uv tool install --help` and `npm cache clean --help` print the page the
/// manager carries for that pair, the same way the first level does. The
/// table is written parent by parent rather than as one flat list because the
/// depth is where the difference lives: `uv tool run` and `uv run` both hand
/// the tail to a program the line names, so `run` appears under no parent,
/// while `install` is harmless under `tool` and under `pip` alike.
///
/// A verb that opens an editor is absent for the same reason a verb that runs
/// a package is: `npm config edit` and `pip config edit` both spawn the
/// program `EDITOR` names, and the reading cannot tell the page from the
/// editor that shares the name.
fn usage_only_subverb(basename: &str, parent: &str, verb: &str) -> bool {
    match (basename, parent) {
        ("uv", "pip") => matches!(
            verb,
            "check"
                | "compile"
                | "freeze"
                | "install"
                | "list"
                | "show"
                | "sync"
                | "tree"
                | "uninstall"
        ),
        // `uv tool run` is `uvx`: the verb after it is a package to fetch and
        // run, so it is absent here the way it is absent from the first level.
        ("uv", "tool") => matches!(
            verb,
            "dir" | "install" | "list" | "uninstall" | "upgrade" | "update-shell"
        ),
        ("uv", "python") => matches!(
            verb,
            "dir" | "find" | "install" | "list" | "pin" | "uninstall" | "upgrade"
        ),
        ("uv", "cache") => matches!(verb, "clean" | "dir" | "prune"),
        ("uv", "self") => matches!(verb, "update" | "version"),
        ("uv", "auth") => matches!(verb, "login" | "logout" | "token"),
        ("pip" | "pip3", "cache") => matches!(verb, "dir" | "info" | "list" | "purge" | "remove"),
        ("pip" | "pip3", "config") => matches!(verb, "debug" | "get" | "list" | "set" | "unset"),
        ("pip" | "pip3", "index") => verb == "versions",
        ("npm", "access") => matches!(verb, "get" | "grant" | "list" | "ls" | "revoke" | "set"),
        ("npm", "cache") => matches!(verb, "add" | "clean" | "ls" | "verify"),
        ("npm", "config") => matches!(verb, "delete" | "fix" | "get" | "list" | "ls" | "set"),
        ("npm", "dist-tag") => matches!(verb, "add" | "ls" | "rm"),
        ("npm", "org") => matches!(verb, "ls" | "rm" | "set"),
        ("npm", "owner") => matches!(verb, "add" | "ls" | "rm"),
        ("npm", "pkg") => matches!(verb, "delete" | "fix" | "get" | "set"),
        ("npm", "profile") => matches!(verb, "disable-2fa" | "enable-2fa" | "get" | "set"),
        ("npm", "team") => matches!(verb, "add" | "create" | "destroy" | "ls" | "rm"),
        ("npm", "token") => matches!(verb, "create" | "list" | "revoke"),
        _ => false,
    }
}

/// Whether this manager's startup reads a configuration the session could
/// have pointed elsewhere. npm and pip both load their configuration before
/// they print usage, so the probe asks for the whole proof the read listings
/// next door require, files included: npm runs an `onload-script` and honours
/// a redirected `userconfig` while it is still working out what to print, so
/// an environment that merely leaves the names alone is not enough.
pub(super) fn configuration_inert(basename: &str, context: super::PathContext<'_>) -> bool {
    match basename {
        "npm" => {
            context.npm_config_inert
                && context.shell_home_matches
                && super::npm_reads::configuration_inert(context)
        }
        "pip" | "pip3" => {
            context.pip_config_inert
                && context.shell_home_matches
                && super::pip_reads::configuration_inert(context)
        }
        _ => true,
    }
}

/// A lone help flag, or one behind a usage-only verb of the manager's, or
/// behind such a verb and one the parent carries.
///
/// The second word is read against the first rather than against the whole
/// list, so `uv tool install --help` is admitted while `uv tool run --help`
/// is not. A flat list would admit both, since `install` and `run` would each
/// be judged on their own; it would also admit pairs no manager documents,
/// such as `uv add sync --help`, which the manager answers with a usage error
/// rather than a page.
///
/// npm's and pip's admission also needs the files
/// [`configuration_inert`] reads, which no unit context names a directory
/// for, so their verbs are proved in the benign gate's fixture home.
/// `tests/fixtures/benign_false_positive_gate.json` carries the alias rows.
pub(crate) fn safe_help_probe(
    basename: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let Some((flag, verbs)) = arguments.split_last() else {
        return false;
    };
    help_flag(basename, flag)
        && usage_only_verbs(basename, verbs)
        && configuration_inert(basename, context)
}

/// The words between the executable and the help flag, read as a path through
/// the manager's own verbs.
fn usage_only_verbs(basename: &str, verbs: &[String]) -> bool {
    match verbs {
        [] => true,
        [verb] => usage_only_verb(basename, verb),
        [parent, verb] => {
            usage_only_verb(basename, parent) && usage_only_subverb(basename, parent, verb)
        }
        // No manager here documents a third level.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::safe_help_probe;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn context() -> super::super::PathContext<'static> {
        super::super::PathContext {
            npm_config_inert: true,
            pip_config_inert: true,
            ..Default::default()
        }
    }

    /// npm and pip read files this context names no directory for, so the
    /// shape tests below carry the managers whose usage text needs no proof
    /// beyond their own words. The two whose startup reads a configuration
    /// are admitted by the benign gate instead, where a fixture home holds
    /// the files the proof reads.
    #[test]
    fn a_configuration_the_session_can_write_refuses_the_probe() {
        let root = std::env::temp_dir().join(format!("guard-help-npmrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        // npm requires this file while it is still working out what to print.
        std::fs::write(project.join(".npmrc"), "onload-script=./onload.js\n").unwrap();
        let home = home.to_string_lossy().into_owned();
        let project = project.to_string_lossy().into_owned();
        let written = super::super::PathContext {
            npm_config_inert: true,
            pip_config_inert: true,
            shell_home_matches: true,
            home_dir: Some(&home),
            cwd: Some(&project),
            ..Default::default()
        };

        assert!(!safe_help_probe(
            "npm",
            &args(&["install", "--help"]),
            written
        ));
        // The refusal is the file, not the shape: a manager that reads no
        // configuration prints its usage from the same directory.
        assert!(safe_help_probe("jq", &args(&["--help"]), written));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_family_usage_text_is_admitted() {
        for (tool, arguments) in [
            ("uv", vec!["add", "--help"]),
            ("uv", vec!["add", "-h"]),
            ("uv", vec!["pip", "install", "--help"]),
            ("uv", vec!["sync", "--help"]),
            ("uv", vec!["--help"]),
            ("deno", vec!["install", "--help"]),
            ("ruff", vec!["check", "--help"]),
            ("jq", vec!["--help"]),
        ] {
            assert!(
                safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    /// The pairs each manager documents, which a flat verb list reached only
    /// where both words happened to sit in it.
    #[test]
    fn a_second_level_usage_page_is_admitted() {
        for (tool, arguments) in [
            ("uv", vec!["tool", "install", "--help"]),
            ("uv", vec!["tool", "list", "--help"]),
            ("uv", vec!["tool", "--help"]),
            ("uv", vec!["python", "list", "-h"]),
            ("uv", vec!["cache", "clean", "--help"]),
            ("uv", vec!["self", "update", "--help"]),
            ("uv", vec!["auth", "login", "--help"]),
            ("uv", vec!["pip", "compile", "--help"]),
            ("uv", vec!["pip", "list", "--help"]),
        ] {
            assert!(
                safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    /// npm and pip read a configuration before they print, so the pair is
    /// proved here against the verb tables and in the benign gate's fixture
    /// home against the files.
    #[test]
    fn a_second_level_verb_is_carried_by_its_own_parent() {
        for (tool, parent, verb) in [
            ("npm", "cache", "clean"),
            ("npm", "config", "get"),
            ("npm", "access", "list"),
            ("npm", "token", "list"),
            ("npm", "dist-tag", "ls"),
            ("pip", "cache", "dir"),
            ("pip", "config", "get"),
            ("pip3", "index", "versions"),
        ] {
            assert!(super::usage_only_verb(tool, parent), "{tool} {parent}");
            assert!(
                super::usage_only_subverb(tool, parent, verb),
                "{tool} {parent} {verb}"
            );
        }
    }

    /// The second word is read against the first, so a pair the manager never
    /// documents is refused even when both words are verbs of its own.
    #[test]
    fn a_pair_no_parent_carries_is_refused() {
        for (tool, arguments) in [
            ("uv", vec!["add", "sync", "--help"]),
            ("uv", vec!["pip", "venv", "--help"]),
            ("uv", vec!["cache", "install", "--help"]),
            ("uv", vec!["tool", "pin", "--help"]),
            ("uv", vec!["python", "clean", "--help"]),
            ("deno", vec!["install", "add", "--help"]),
            ("ruff", vec!["check", "format", "--help"]),
            // Three levels are past anything these managers document.
            ("uv", vec!["pip", "install", "list", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    /// A verb that opens `EDITOR` is absent from the second level for the
    /// reason a verb that runs a package is absent from the first.
    #[test]
    fn a_second_level_verb_that_opens_an_editor_is_refused() {
        for (tool, parent) in [("npm", "config"), ("pip", "config"), ("pip3", "config")] {
            assert!(
                !super::usage_only_subverb(tool, parent, "edit"),
                "{tool} {parent} edit"
            );
        }
    }

    #[test]
    fn verbless_tool_usage_text_is_admitted() {
        for (tool, arguments) in [
            ("curl", vec!["--help"]),
            ("curl", vec!["-h"]),
            ("curl", vec!["--manual"]),
            ("curl", vec!["-M"]),
            ("wget", vec!["--help"]),
            ("wget", vec!["-h"]),
            ("ssh", vec!["--help"]),
            ("scp", vec!["--help"]),
            ("sftp", vec!["--help"]),
            ("rsync", vec!["--help"]),
            ("psql", vec!["--help"]),
            ("redis-cli", vec!["--help"]),
            ("nc", vec!["--help"]),
            ("cp", vec!["--help"]),
            ("chown", vec!["--help"]),
            ("kill", vec!["--help"]),
        ] {
            assert!(
                safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn a_spelling_that_names_a_host_or_a_mode_is_refused() {
        for (tool, arguments) in [
            // `-h` names the host to connect to.
            ("psql", vec!["-h"]),
            ("redis-cli", vec!["-h"]),
            ("nc", vec!["-h"]),
            // rsync reads `-h` as `--human-readable`, which is a transfer.
            ("rsync", vec!["-h"]),
            // The usage text prints the values the option files set.
            ("mysql", vec!["--help"]),
            ("mysqldump", vec!["--help"]),
            // Under the privilege floor, which usage text does not lower.
            ("launchctl", vec!["--help"]),
            // The package lane answers for these.
            ("brew", vec!["--help"]),
            ("apt-get", vec!["--help"]),
            // The flag has to be the last word; anything after it is an
            // operand, and anything before it is a host or a path.
            ("curl", vec!["--help", "https://example.test"]),
            ("cp", vec!["--help", "src", "dst"]),
            ("ssh", vec!["host", "--help"]),
            ("cp", vec!["-h"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn verbs_that_name_a_program_to_run_are_refused() {
        for (tool, arguments) in [
            // The flag reaches pytest, which loads the workspace's conftest.
            ("uv", vec!["run", "pytest", "--help"]),
            ("uv", vec!["run", "--help"]),
            ("uv", vec!["tool", "run", "--help"]),
            ("npm", vec!["exec", "--help"]),
            ("npm", vec!["run", "test", "--help"]),
            // `npm init <name>` resolves and runs a `create-*` package.
            ("npm", vec!["init", "--help"]),
            // npm's own aliases for those three verbs point at the same
            // programs, so they are refused with them.
            ("npm", vec!["create", "--help"]),
            ("npm", vec!["x", "--help"]),
            // `uvx` is `uv tool run`: the verb is a package to fetch and run.
            ("uvx", vec!["build", "--help"]),
            ("uvx", vec!["pip", "--help"]),
            ("uvx", vec!["--help"]),
            // The script, not the manager, reads the flag.
            ("uv", vec!["run", "script.py", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    /// npm's own admission also reads its configuration, which this unit
    /// context names no directory for, so the shape test above cannot tell a
    /// refused verb from a refused configuration. The verb list answers for
    /// itself here: every word npm resolves to a package or a script stays
    /// out of it, whatever the configuration proof later decides.
    #[test]
    fn npm_verbs_that_run_a_program_stay_out_of_the_usage_list() {
        for verb in ["create", "x", "exec", "run", "run-script", "init"] {
            assert!(!super::usage_only_verb("npm", verb), "npm {verb}");
        }
        // The aliases that only print usage are still in it.
        for verb in [
            "add",
            "remove",
            "un",
            "in",
            "up",
            "info",
            "ln",
            "clean-install",
        ] {
            assert!(super::usage_only_verb("npm", verb), "npm {verb}");
        }
    }

    #[test]
    fn workspace_selected_launchers_and_pagers_are_refused() {
        for (tool, arguments) in [
            ("yarn", vec!["add", "--help"]),
            ("pnpm", vec!["add", "--help"]),
            ("cargo", vec!["add", "--help"]),
            ("go", vec!["install", "--help"]),
            ("git", vec!["commit", "--help"]),
            ("poetry", vec!["add", "--help"]),
            // `bun <word>` falls back to running that script or file.
            ("bun", vec!["add", "--help"]),
            ("bun", vec!["check", "--help"]),
            ("bun", vec!["init", "-h"]),
            // A plugin of the same name takes the command.
            ("helm", vec!["audit", "--help"]),
            // Help discovers Docker's CLI plugins by executing them.
            ("docker", vec!["build", "--help"]),
            ("docker", vec!["--help"]),
            // The flag has to be the last word; anything after it is an
            // operand the manager would act on.
            ("npm", vec!["install", "--help", "left-pad"]),
            ("uv", vec![]),
            ("npm", vec!["install"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn a_verb_belonging_to_another_manager_is_refused() {
        for (tool, arguments) in [
            // `npm sync` and `npm venv` are not npm commands; admitting them
            // from a shared list is what let a launcher's fallback through.
            ("npm", vec!["sync", "--help"]),
            ("npm", vec!["venv", "--help"]),
            ("pip", vec!["add", "--help"]),
            ("deno", vec!["sync", "--help"]),
            ("ruff", vec!["install", "--help"]),
            // The single-purpose tools take no verb at all.
            ("jq", vec!["install", "--help"]),
            ("rg", vec!["check", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn a_redirected_manager_configuration_keeps_the_question() {
        let npm_moved = super::super::PathContext {
            pip_config_inert: true,
            ..Default::default()
        };
        assert!(!safe_help_probe(
            "npm",
            &args(&["install", "--help"]),
            npm_moved
        ));
        let pip_moved = super::super::PathContext {
            npm_config_inert: true,
            ..Default::default()
        };
        assert!(!safe_help_probe(
            "pip",
            &args(&["install", "--help"]),
            pip_moved
        ));
        // A tool with no configuration of its own is unaffected.
        assert!(safe_help_probe("jq", &args(&["--help"]), pip_moved));
    }
}
