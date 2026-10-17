#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::FixtureCleanup;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const PACKAGE_JSON: &str =
    r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#;
pub(crate) const BUN_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fixture", "dependencies": { "left-pad": "^1.3.0" } },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-AAAA"],
  }
}
"#;
pub(crate) const PNPM_LOCK: &str = "lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-AAAA+/==}

snapshots:

  left-pad@1.3.0: {}
";
pub(crate) const PACKAGE_LOCK: &str = r#"{
  "name": "fixture",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "fixture", "dependencies": { "left-pad": "^1.3.0" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-AAAA"
    }
  }
}
"#;

pub(crate) const BUN: &str = "bun install --frozen-lockfile --ignore-scripts";
pub(crate) const PNPM: &str = "pnpm install --frozen-lockfile --ignore-scripts";
pub(crate) const NPM: &str = "npm ci --ignore-scripts --no-audit";

/// A project name, the files it holds and the install run in it.
type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str);

fn default_controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,
            "health":"protected",
            "revision":1,
            "managed_revision":0,
            "effective_digest":"",
            "layers":[{
                "schema_version":"1.0.0",
                "kind":"local-admin",
                "catalog_digest":program.catalog_digest,
                "global_lockdown":false,
                "controls":[]
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

pub(crate) struct Lab {
    pub(crate) home: PathBuf,
    _cleanup: FixtureCleanup,
}

impl Lab {
    pub(crate) fn new() -> Self {
        let unique = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("guard-lockfile-install-{unique}"));
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        Self {
            _cleanup: FixtureCleanup(root),
            home,
        }
    }

    /// A project at `name` below the lab's home holding `files`, where a
    /// leading `cd` can be proven.
    pub(crate) fn project(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let project = self.home.join(name);
        for (path, text) in files {
            let path = project.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        project
    }

    pub(crate) fn classify(
        &self,
        cwd: &Path,
        command: &str,
        names: &[&str],
    ) -> guard_contracts::PreToolResultV1 {
        let environment = guard_contracts::GuardExecutionEnvironmentV1 {
            path: std::env::var("PATH").unwrap(),
            environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
            environment_digest: "0".repeat(64),
            home: Some(self.home.to_str().unwrap().to_owned()),
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: true,
            library_search_paths: Default::default(),
        };
        evaluate_pre_tool_envelope_with_execution_context(
            "codex",
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&default_controls()),
            None,
            PathContext {
                home_dir: self.home.to_str(),
                cwd: cwd.to_str(),
                cdpath_unset: true,
                npm_config_inert: true,
                shell_home_matches: true,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
                ..PathContext::default()
            },
            Some(&environment),
        )
    }
}

#[test]
fn frozen_script_free_installs_from_registry_lockfiles_proceed() {
    let lab = Lab::new();
    let bun = lab.project(
        "bun",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let pnpm = lab.project(
        "pnpm",
        &[
            ("package.json", PACKAGE_JSON),
            ("pnpm-lock.yaml", PNPM_LOCK),
        ],
    );
    let npm = lab.project(
        "npm",
        &[
            ("package.json", PACKAGE_JSON),
            ("package-lock.json", PACKAGE_LOCK),
        ],
    );
    let mut refused = Vec::new();
    for (project, install) in [(&bun, BUN), (&pnpm, PNPM), (&npm, NPM)] {
        let cd = format!("cd {} && {install}", project.display());
        let piped = format!("{install} 2>&1 | tail -15");
        let both = format!("cd {} && {install} 2>&1 | tail -15", project.display());
        let names: &[&str] = &["BUN_INSTALL", "PNPM_HOME"];
        for (cwd, command, names) in [
            (project.as_path(), install, &[][..]),
            (project.as_path(), install, names),
            (project.as_path(), piped.as_str(), &[][..]),
            (lab.home.as_path(), cd.as_str(), &[][..]),
            (lab.home.as_path(), both.as_str(), &[][..]),
            (lab.home.as_path(), both.as_str(), names),
        ] {
            let result = lab.classify(cwd, command, names);
            if result.reason_code != "native_exact_safe_lockfile_install" {
                refused.push(format!("{command} {names:?}: {}", result.reason_code));
            }
        }
    }
    assert!(refused.is_empty(), "{}", refused.join("\n"));
}

/// The managed safety guide tells agents to install from a committed lockfile
/// with this exact command (`tests/test_native_package_review.py` checks that
/// the guide still names it), so it must stay one this proof lets continue.
#[test]
fn the_safety_guide_lockfile_install_proceeds() {
    let command = "npm ci --ignore-scripts";
    let lab = Lab::new();
    let npm = lab.project(
        "npm",
        &[
            ("package.json", PACKAGE_JSON),
            ("package-lock.json", PACKAGE_LOCK),
        ],
    );
    let result = lab.classify(&npm, command, &[]);
    assert_eq!(result.reason_code, "native_exact_safe_lockfile_install");
    assert_eq!(result.minimum_action, "allow");
}

#[test]
fn installs_that_run_scripts_or_add_packages_stay_reviewed() {
    let lab = Lab::new();
    let bun = lab.project(
        "bun",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    for command in [
        "bun install --frozen-lockfile",
        "bun install --ignore-scripts",
        "bun install --frozen-lockfile --ignore-scripts left-pad",
        "bun add left-pad --ignore-scripts",
        "bun install --frozen-lockfile --ignore-scripts --registry https://registry.example.invalid",
        "bun install --frozen-lockfile --ignore-scripts && node index.js",
        "echo registry=https://registry.example.invalid > .npmrc && bun install --frozen-lockfile --ignore-scripts",
        "npm ci",
        "pnpm install --frozen-lockfile",
    ] {
        let result = lab.classify(&bun, command, &[]);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
    for name in ["BUN_CONFIG_REGISTRY", "NPM_CONFIG_REGISTRY", "BUN_OPTIONS"] {
        let result = lab.classify(&bun, BUN, &[name]);
        assert_ne!(result.minimum_action, "allow", "{name}");
    }
}

#[test]
fn lockfiles_naming_other_sources_stay_reviewed() {
    let lab = Lab::new();
    let git_bun = BUN_LOCK.replace(
        r#""left-pad": ["left-pad@1.3.0", "", {}, "sha512-AAAA"],"#,
        r#""left-pad": ["left-pad@github:example/left-pad#abc", {}, "abc"],"#,
    );
    let mirrored_bun = BUN_LOCK.replace(
        r#"["left-pad@1.3.0", "","#,
        r#"["left-pad@1.3.0", "https://registry.example.invalid/","#,
    );
    let duplicate_bun = BUN_LOCK.replace(
        r#""packages": {"#,
        r#""packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-AAAA"],"#,
    );
    let tarball_pnpm = PNPM_LOCK.replace(
        "resolution: {integrity: sha512-AAAA+/==}",
        "resolution: {integrity: sha512-AAAA, tarball: https://registry.example.invalid/left-pad.tgz}",
    );
    let git_pnpm = PNPM_LOCK.replace(
        "resolution: {integrity: sha512-AAAA+/==}",
        "resolution:\n      type: git\n      repo: https://example.invalid/left-pad.git",
    );
    let flow_git_pnpm = PNPM_LOCK.replace(
        "  left-pad@1.3.0:\n    resolution: {integrity: sha512-AAAA+/==}",
        "  left-pad@1.3.0: {resolution: {type: git, repo: https://example.invalid/x.git, commit: abc}}",
    );
    let file_pnpm = PNPM_LOCK.replace("version: 1.3.0", "version: file:../left-pad");
    let link_pnpm = PNPM_LOCK
        .replace("specifier: ^1.3.0", "specifier: link:../left-pad")
        .replace("version: 1.3.0", "version: link:../left-pad");
    let unpinned_npm = PACKAGE_LOCK.replace(",\n      \"integrity\": \"sha512-AAAA\"", "");
    let git_npm = PACKAGE_LOCK.replace(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "git+ssh://git@example.invalid/left-pad.git#abc",
    );
    let mirrored_npm = PACKAGE_LOCK.replace(
        "https://registry.npmjs.org/",
        "https://registry.example.invalid/",
    );
    let cases: Vec<Case> = vec![
        ("bun-git", vec![("bun.lock", &git_bun)], BUN),
        ("bun-mirror", vec![("bun.lock", &mirrored_bun)], BUN),
        ("bun-duplicate", vec![("bun.lock", &duplicate_bun)], BUN),
        (
            "bun-binary",
            vec![("bun.lock", BUN_LOCK), ("bun.lockb", "")],
            BUN,
        ),
        (
            "bunfig-registry",
            vec![
                ("bun.lock", BUN_LOCK),
                (
                    "bunfig.toml",
                    "[install]\nregistry = \"https://registry.example.invalid/\"\n",
                ),
            ],
            BUN,
        ),
        (
            "npmrc-registry",
            vec![
                ("bun.lock", BUN_LOCK),
                (".npmrc", "registry=https://registry.example.invalid/\n"),
            ],
            BUN,
        ),
        (
            "pnpm-tarball",
            vec![("pnpm-lock.yaml", &tarball_pnpm)],
            PNPM,
        ),
        ("pnpm-git", vec![("pnpm-lock.yaml", &git_pnpm)], PNPM),
        (
            "pnpm-flow-git",
            vec![("pnpm-lock.yaml", &flow_git_pnpm)],
            PNPM,
        ),
        ("pnpm-file", vec![("pnpm-lock.yaml", &file_pnpm)], PNPM),
        ("pnpm-link", vec![("pnpm-lock.yaml", &link_pnpm)], PNPM),
        (
            "npm-unpinned",
            vec![("package-lock.json", &unpinned_npm)],
            NPM,
        ),
        (
            "pnpm-hooks",
            vec![
                ("pnpm-lock.yaml", PNPM_LOCK),
                (".pnpmfile.cjs", "module.exports = {}\n"),
            ],
            PNPM,
        ),
        (
            "pnpm-workspace-setting",
            vec![
                ("pnpm-lock.yaml", PNPM_LOCK),
                (
                    "pnpm-workspace.yaml",
                    "packages:\n  - app\npnpmfile: hooks.cjs\n",
                ),
            ],
            PNPM,
        ),
        ("npm-git", vec![("package-lock.json", &git_npm)], NPM),
        (
            "npm-mirror",
            vec![("package-lock.json", &mirrored_npm)],
            NPM,
        ),
        (
            "npm-shrinkwrap",
            vec![
                ("package-lock.json", PACKAGE_LOCK),
                ("npm-shrinkwrap.json", PACKAGE_LOCK),
            ],
            NPM,
        ),
        ("npm-missing-lock", vec![], NPM),
    ];
    for (name, files, command) in cases {
        let mut files = files;
        files.push(("package.json", PACKAGE_JSON));
        let project = lab.project(name, &files);
        let result = lab.classify(&project, command, &[]);
        assert_ne!(result.minimum_action, "allow", "{name}: {command}");
    }

    // A workspace root above the project would install with its own lockfile.
    lab.project(
        "monorepo",
        &[("package.json", r#"{"name":"root","workspaces":["app"]}"#)],
    );
    let member = lab.project(
        "monorepo/app",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let result = lab.classify(&member, BUN, &[]);
    assert_ne!(result.minimum_action, "allow", "workspace member");

    // An escaped key is still `workspaces` to the manager.
    lab.project(
        "escaped",
        &[(
            "package.json",
            r#"{"name":"root","work\u0073paces":["app"]}"#,
        )],
    );
    let member = lab.project(
        "escaped/app",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let result = lab.classify(&member, BUN, &[]);
    assert_ne!(result.minimum_action, "allow", "escaped workspace root");

    // Corepack downloads and runs a `packageManager` URL before the install.
    let corepack = lab.project(
        "corepack-url",
        &[
            (
                "package.json",
                r#"{"name":"fixture","packageManager":"pnpm@https://example.invalid/pnpm.tgz#sha512.abc"}"#,
            ),
            ("pnpm-lock.yaml", PNPM_LOCK),
        ],
    );
    let result = lab.classify(&corepack, PNPM, &[]);
    assert_ne!(result.minimum_action, "allow", "packageManager URL");
}

#[test]
fn workspace_links_and_pinned_package_managers_still_proceed() {
    let lab = Lab::new();
    let workspace_pnpm = PNPM_LOCK.replace(
        "      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0",
        "      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n      shared:\n        specifier: workspace:*\n        version: link:../shared",
    );
    let pinned = r#"{"name":"fixture","packageManager":"pnpm@9.12.0+sha512.0123abcdef","dependencies":{"left-pad":"^1.3.0"}}"#;
    let project = lab.project(
        "pnpm-workspace-link",
        &[
            ("package.json", pinned),
            ("pnpm-lock.yaml", &workspace_pnpm),
        ],
    );
    let result = lab.classify(&project, PNPM, &[]);
    assert_eq!(result.reason_code, "native_exact_safe_lockfile_install");
}
