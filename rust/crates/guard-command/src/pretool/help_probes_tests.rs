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

/// A flag that only shapes the page is dropped before the shape is read.
#[test]
fn a_rendering_flag_beside_the_help_flag_keeps_the_probe() {
    for (tool, arguments) in [
        ("curl", vec!["--help", "--silent"]),
        ("curl", vec!["-s", "--help"]),
        ("curl", vec!["--help", "--no-progress-meter"]),
        ("uv", vec!["add", "--help", "--no-cache"]),
        ("uv", vec!["--quiet", "--help"]),
        ("uv", vec!["pip", "install", "--help", "--offline"]),
        ("wget", vec!["--help", "-q"]),
        ("deno", vec!["install", "--help", "--quiet"]),
        ("ruff", vec!["check", "--help", "--no-cache"]),
    ] {
        assert!(
            safe_help_probe(tool, &args(&arguments), context()),
            "{tool} {arguments:?}"
        );
    }
}

/// Dropping a flag drops nothing else: an option that carries a value keeps
/// it, a flag another tool owns is not this one's to drop, and an operand is
/// still an operand.
#[test]
fn a_value_an_operand_or_another_tools_flag_keeps_the_review() {
    for (tool, arguments) in [
        ("curl", vec!["--help", "--output", "page.txt"]),
        ("curl", vec!["--help", "--no-cache"]),
        ("uv", vec!["add", "--help", "requests"]),
        ("wget", vec!["--help", "--silent"]),
        ("jq", vec!["--help", "-q"]),
    ] {
        assert!(
            !safe_help_probe(tool, &args(&arguments), context()),
            "{tool} {arguments:?}"
        );
    }
}
