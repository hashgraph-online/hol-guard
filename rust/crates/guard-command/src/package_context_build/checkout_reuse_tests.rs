//! A saved package approval follows the codebase and its lockfile, not the
//! directory it was granted in: other checkouts of the same `origin` with the
//! same lockfile build the same context, and edits that install nothing
//! different leave it alone.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{build_package_execution_context, BuildInput, BuiltContext};

const UV_LOCK: &str = "version = 1\n[[package]]\nname = \"httpx\"\nversion = \"0.28.1\"\n";
const PYPROJECT: &str = "[project]\nname = \"app\"\nversion = \"1.0.0\"\n\
dependencies = [\"httpx==0.28.1\"]\n\n[tool.ruff]\nline-length = 100\n";
const BUN_LOCK: &str =
    "{\"lockfileVersion\": 1, \"packages\": {\"left-pad\": [\"left-pad@1.3.0\"]}}\n";
const PACKAGE_JSON: &str = "{\"name\": \"app\", \"version\": \"1.0.0\",\
 \"scripts\": {\"dev\": \"next dev\"}, \"dependencies\": {\"left-pad\": \"1.3.0\"}}\n";

struct Lab {
    root: tempfile::TempDir,
}

impl Lab {
    fn new() -> Self {
        let lab = Self {
            root: tempfile::tempdir().unwrap(),
        };
        let bin = lab.path("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for manager in ["uv", "bun"] {
            let path = bin.join(manager);
            std::fs::write(&path, format!("#!/bin/sh\n# {manager}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir_all(lab.path("home")).unwrap();
        lab
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    /// A standalone clone whose `.git/config` lists `remotes` in order.
    fn clone(&self, name: &str, remotes: &[(&str, &str)]) -> PathBuf {
        let checkout = self.path(name);
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        let mut config = String::from("[core]\n\trepositoryformatversion = 0\n");
        for (remote, url) in remotes {
            config.push_str(&format!("[remote \"{remote}\"]\n\turl = {url}\n"));
        }
        std::fs::write(checkout.join(".git/config"), config).unwrap();
        checkout
    }

    /// A linked worktree of `primary`, as `git worktree add` lays it out.
    fn worktree(&self, primary: &Path, name: &str) -> PathBuf {
        let checkout = self.path(name);
        let git_dir = primary.join(".git/worktrees").join(name);
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::write(
            checkout.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();
        checkout
    }

    fn context(&self, workspace: &Path, manager: &str) -> BuiltContext {
        let home = self.path("home");
        let bin = self.path("bin");
        let environment = BTreeMap::from([
            ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
            ("PATH".to_owned(), bin.to_str().unwrap().to_owned()),
        ]);
        let metadata: Map<String, Value> = serde_json::from_value(json!({
            "package_manager": manager,
            "intent_kind": "install",
            "flags": [],
        }))
        .unwrap();
        build_package_execution_context(&BuildInput {
            workspace_dir: workspace.to_str().unwrap(),
            metadata: &metadata,
            executable: Some(manager),
            executable_args: &[],
            environment: &environment,
            process_cwd: workspace.to_str().unwrap(),
            process_home: home.to_str().unwrap(),
            process_home_env: home.to_str(),
            process_path: bin.to_str(),
        })
        .unwrap()
    }
}

fn write(checkout: &Path, name: &str, body: &str) {
    std::fs::write(checkout.join(name), body).unwrap();
}

fn python_project(checkout: &Path, pyproject: &str) {
    write(checkout, "pyproject.toml", pyproject);
    write(checkout, "uv.lock", UV_LOCK);
}

fn changed(left: &BuiltContext, right: &BuiltContext) -> Vec<String> {
    left.components
        .iter()
        .zip(&right.components)
        .filter(|(a, b)| a.digest != b.digest)
        .map(|(a, _)| a.name.clone())
        .collect()
}

#[test]
fn clone_at_another_path_with_extra_remotes_reuses_the_context() {
    let lab = Lab::new();
    let primary = lab.clone(
        "primary",
        &[
            ("origin", "git@github.com:Example/app.git"),
            ("fork", "https://github.com/someone/app.git"),
        ],
    );
    let clone = lab.clone(
        "elsewhere/clone",
        &[("origin", "https://token@GitHub.com/Example/app/")],
    );
    python_project(&primary, PYPROJECT);
    python_project(&clone, PYPROJECT);

    let first = lab.context(&primary, "uv");
    let second = lab.context(&clone, "uv");

    assert!(first.portable, "{:?}", first.non_portable_reason);
    assert_eq!(changed(&first, &second), Vec::<String>::new());
    assert_eq!(first.digest, second.digest);
}

#[test]
fn linked_worktree_survives_new_remotes_on_the_primary() {
    let lab = Lab::new();
    let primary = lab.clone(
        "primary",
        &[("origin", "https://example.test/team/app.git")],
    );
    let linked = lab.worktree(&primary, "linked");
    python_project(&primary, PYPROJECT);
    python_project(&linked, PYPROJECT);
    let before = lab.context(&linked, "uv");

    let mut config = std::fs::read_to_string(primary.join(".git/config")).unwrap();
    config.push_str("[remote \"upstream\"]\n\turl = https://example.test/upstream/app.git\n");
    std::fs::write(primary.join(".git/config"), config).unwrap();

    assert_eq!(before.digest, lab.context(&linked, "uv").digest);
    assert_eq!(before.digest, lab.context(&primary, "uv").digest);
}

#[test]
fn pyproject_edits_outside_install_sections_keep_the_context() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    python_project(&checkout, PYPROJECT);
    let before = lab.context(&checkout, "uv");

    let bumped = PYPROJECT
        .replace("version = \"1.0.0\"", "version = \"1.1.0\"")
        .replace(
            "line-length = 100",
            "line-length = 120\n[tool.pytest.ini_options]\naddopts = \"-q\"",
        );
    python_project(&checkout, &bumped);

    assert_eq!(
        changed(&before, &lab.context(&checkout, "uv")),
        Vec::<String>::new()
    );
}

#[test]
fn package_json_edits_outside_install_sections_keep_the_context() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    write(&checkout, "package.json", PACKAGE_JSON);
    write(&checkout, "bun.lock", BUN_LOCK);
    let before = lab.context(&checkout, "bun");

    let edited = PACKAGE_JSON.replace("\"1.0.0\"", "\"1.1.0\"").replace(
        "\"next dev\"",
        "\"next dev --turbo\", \"lint\": \"eslint .\"",
    );
    write(&checkout, "package.json", &edited);

    assert_eq!(
        changed(&before, &lab.context(&checkout, "bun")),
        Vec::<String>::new()
    );
}

#[test]
fn lockfile_dependency_and_hook_changes_still_ask_again() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    python_project(&checkout, PYPROJECT);
    let before = lab.context(&checkout, "uv");

    write(&checkout, "uv.lock", &UV_LOCK.replace("0.28.1", "0.28.2"));
    assert_eq!(
        changed(&before, &lab.context(&checkout, "uv")),
        ["manifests_and_lockfiles"]
    );

    python_project(
        &checkout,
        &PYPROJECT.replace("httpx==0.28.1", "httpx==0.28.2"),
    );
    assert_eq!(
        changed(&before, &lab.context(&checkout, "uv")),
        ["manifests_and_lockfiles", "workspace_configuration"]
    );

    python_project(
        &checkout,
        &format!("{PYPROJECT}\n[tool.uv]\nindex-url = \"https://mirror.example.test/simple\"\n"),
    );
    assert_ne!(before.digest, lab.context(&checkout, "uv").digest);

    let js = lab.clone("web", &[("origin", "https://example.test/team/web.git")]);
    write(&js, "package.json", PACKAGE_JSON);
    write(&js, "bun.lock", BUN_LOCK);
    let js_before = lab.context(&js, "bun");
    write(
        &js,
        "package.json",
        &PACKAGE_JSON.replace(
            "\"1.3.0\"}",
            "\"1.3.0\"}, \"trustedDependencies\": [\"left-pad\"]",
        ),
    );
    assert_ne!(js_before.digest, lab.context(&js, "bun").digest);
}

#[test]
fn identical_files_under_a_different_origin_do_not_share_the_context() {
    let lab = Lab::new();
    let first = lab.clone("first", &[("origin", "https://example.test/team/app.git")]);
    let second = lab.clone(
        "second",
        &[("origin", "https://example.test/other/app.git")],
    );
    python_project(&first, PYPROJECT);
    python_project(&second, PYPROJECT);

    assert_eq!(
        changed(&lab.context(&first, "uv"), &lab.context(&second, "uv")),
        ["repository_identity"]
    );
}

#[test]
fn remote_urls_reduce_to_host_and_path() {
    use super::repository::normalized_remote_url as normal;
    for spelling in [
        "git@github.com:Org/repo.git",
        "ssh://git@github.com:22/Org/repo.git",
        "https://user:secret@GITHUB.com/Org/repo/",
        "https://github.com/Org/repo",
    ] {
        assert_eq!(normal(spelling), "github.com/Org/repo", "{spelling}");
    }
    assert_eq!(normal("/srv/git/repo.git"), "/srv/git/repo");
    assert_eq!(normal("file:///srv/git/repo.git/"), "/srv/git/repo");
    assert_eq!(normal("../repo"), "../repo");
}

#[test]
fn relative_local_origins_name_the_repository_beside_each_checkout() {
    let lab = Lab::new();
    let first = lab.clone("a/app", &[("origin", "../upstream")]);
    let second = lab.clone("b/app", &[("origin", "../upstream")]);
    let linked = lab.worktree(&first, "linked");
    for checkout in [&first, &second, &linked] {
        python_project(checkout, PYPROJECT);
    }

    let primary = lab.context(&first, "uv");
    assert_eq!(
        changed(&primary, &lab.context(&second, "uv")),
        ["repository_identity"]
    );
    assert_eq!(primary.digest, lab.context(&linked, "uv").digest);
}

#[test]
fn pyproject_build_and_entry_point_settings_still_ask_again() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    let hooked = format!("{PYPROJECT}\n[tool.hatch.build.hooks.custom]\npath = \"hook.py\"\n");
    python_project(&checkout, &hooked);
    let before = lab.context(&checkout, "uv");

    python_project(&checkout, &hooked.replace("hook.py", "other_hook.py"));
    assert_ne!(before.digest, lab.context(&checkout, "uv").digest);

    let scripts = hooked.replace(
        "[tool.ruff]",
        "[project.scripts]\napp = \"app:main\"\n\n[tool.ruff]",
    );
    python_project(&checkout, &scripts);
    assert_ne!(before.digest, lab.context(&checkout, "uv").digest);
}

#[test]
fn a_variable_named_only_outside_install_sections_keeps_the_context() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    python_project(&checkout, PYPROJECT);
    let before = lab.context(&checkout, "uv");

    python_project(
        &checkout,
        &PYPROJECT.replace("line-length = 100", "line-length = 100 # see ${EDITOR}"),
    );
    assert_eq!(
        changed(&before, &lab.context(&checkout, "uv")),
        Vec::<String>::new()
    );
}

#[test]
fn scripts_an_install_hook_can_reach_still_ask_again() {
    let lab = Lab::new();
    let checkout = lab.clone("app", &[("origin", "https://example.test/team/app.git")]);
    let hooked = PACKAGE_JSON.replace(
        "\"next dev\"",
        "\"next dev\", \"postinstall\": \"npm run setup\", \"setup\": \"node a.js\"",
    );
    write(&checkout, "package.json", &hooked);
    write(&checkout, "bun.lock", BUN_LOCK);
    let before = lab.context(&checkout, "bun");

    write(
        &checkout,
        "package.json",
        &hooked.replace("node a.js", "node b.js"),
    );
    assert_ne!(before.digest, lab.context(&checkout, "bun").digest);

    write(&checkout, "package.json", PACKAGE_JSON);
    let plain = lab.context(&checkout, "bun");
    for hook in ["preprepare", "postprepare", "dependencies"] {
        let added = PACKAGE_JSON.replace(
            "\"next dev\"",
            &format!("\"next dev\", \"{hook}\": \"node c.js\""),
        );
        write(&checkout, "package.json", &added);
        assert_ne!(plain.digest, lab.context(&checkout, "bun").digest, "{hook}");
    }
}
