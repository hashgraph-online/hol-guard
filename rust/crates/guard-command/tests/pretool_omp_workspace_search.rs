#![cfg(unix)]

//! Oh My Pi `grep` and `glob` over an ordinary workspace that, like most
//! projects, keeps a gitignored `.env` at its root.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// Parallel tests can read the same clock value, so each fixture also takes a
// unique sequence number.
static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-workspace-search")
        .join(format!(
            "home-{}-{}-{}",
            std::process::id(),
            FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    write(home.join(".ssh/id_rsa"), "synthetic fixture\n");
    write(home.join("notes.sh"), "synthetic fixture\n");
    for name in ["app", "tracked", "custom"] {
        let workspace = home.join(name);
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        for file in [
            "deploy.sh",
            "scripts/registry-cleanup.sh",
            "src/index.ts",
            "node_modules/pkg/index.js",
            ".env",
            "config/.env.local",
        ] {
            write(workspace.join(file), "synthetic fixture\n");
        }
    }
    write(home.join("app/.gitignore"), ".env\n.env.*\nnode_modules/\n");
    write(home.join("tracked/.gitignore"), "node_modules/\n");
    write(
        home.join("custom/.gitignore"),
        ".env\n.env.*\nnode_modules/\n",
    );
    write(home.join("custom/.ignore"), "!.env\n");
    Fixture { root, home }
}

fn omp(f: &Fixture, cwd: &str, tool: &str, input: Value) -> PreToolResultV1 {
    let cwd = if cwd == "~" {
        f.home.clone()
    } else {
        f.home.join(cwd)
    };
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    )
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn grep_honors_the_gitignore_the_host_honors() {
    let f = fixture();
    for input in [
        json!({"pattern": "deploy", "path": "."}),
        json!({"pattern": "deploy"}),
        json!({"pattern": "deploy", "path": ".", "case": false, "gitignore": true}),
        json!({"pattern": "deploy", "path": "src; scripts"}),
    ] {
        let result = omp(&f, "app", "grep", input.clone());
        assert!(allowed(&result), "{input}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_bounded_search_scope");
    }
    // The host then searches every file, so the `.env` is in reach. The
    // pattern is one its content holds, so the search would print from it.
    assert!(!allowed(&omp(
        &f,
        "app",
        "grep",
        json!({"pattern": "fixture", "path": ".", "gitignore": false})
    )));
    // A `glob` or `type` override can re-include the gitignored `.env`.
    for input in [
        json!({"pattern": "fixture", "path": ".", "glob": ".env"}),
        json!({"pattern": "fixture", "path": ".", "glob": "*.sh"}),
        json!({"pattern": "fixture", "type": "sh"}),
    ] {
        assert!(!allowed(&omp(&f, "app", "grep", input.clone())), "{input}");
    }
    // Naming a secret still reviews it, ignored or not.
    for path in [".env", "src/index.ts;.env", "config/.env.local", "~/.ssh"] {
        let input = json!({"pattern": "KEY", "path": path});
        assert!(!allowed(&omp(&f, "app", "grep", input)), "{path}");
    }
    // A tracked `.env`, or a `.ignore` that can re-include one, is in reach.
    for cwd in ["tracked", "custom"] {
        let input = json!({"pattern": "fixture", "path": "."});
        assert!(!allowed(&omp(&f, cwd, "grep", input)), "{cwd}");
    }
}

#[test]
fn globs_list_names_below_the_workspace() {
    let f = fixture();
    for cwd in ["app", "tracked"] {
        for path in [
            "**/*.sh",
            "*.sh",
            "**/*{registry,deploy,cleanup}*",
            "src/**/*.ts",
            ".",
        ] {
            let result = omp(&f, cwd, "glob", json!({"path": path}));
            assert!(allowed(&result), "{cwd} {path}: {}", result.reason_code);
            assert_eq!(result.reason_code, "native_omp_directory_listing");
        }
    }
    // A walk from home or a credential directory stays on review.
    for path in ["**/*.sh", "*.sh", "**/*{notes,deploy}*"] {
        assert!(
            !allowed(&omp(&f, "~", "glob", json!({"path": path}))),
            "{path}"
        );
    }
    for path in ["~/.ssh/*", "~/{app,.ssh}/*", "../*", "{src,../..}/*"] {
        assert!(
            !allowed(&omp(&f, "app", "glob", json!({"path": path}))),
            "{path}"
        );
    }
}

#[test]
fn globs_pass_gitignored_links_that_leave_the_workspace() {
    let f = fixture();
    // A worktree package borrowing another checkout's installed packages.
    let shared = f.root.join("shared/node_modules");
    write(shared.join("pkg/index.js"), "synthetic fixture\n");
    let link = f.home.join("app/web/node_modules");
    write(f.home.join("app/web/package.json"), "{}\n");
    std::os::unix::fs::symlink(&shared, &link).unwrap();
    for path in ["**/*.sh", "**/*{registry,deploy,cleanup}*"] {
        let result = omp(&f, "app", "glob", json!({"path": path}));
        assert!(allowed(&result), "{path}: {}", result.reason_code);
    }
    // Without the gitignore the host walks the link, so it stays on review.
    let input = json!({"path": "**/*.sh", "gitignore": false});
    assert!(!allowed(&omp(&f, "app", "glob", input)));
    // A link the gitignore does not cover still may not leave the workspace.
    std::os::unix::fs::symlink(f.home.join(".ssh"), f.home.join("app/web/keys")).unwrap();
    assert!(!allowed(&omp(
        &f,
        "app",
        "glob",
        json!({"path": "**/*.sh"})
    )));
}

#[test]
fn globs_walk_a_workspace_larger_than_the_content_search_bound() {
    let f = fixture();
    // More entries than a content search walks, as in a mid-size repository.
    let large = f.home.join("app/src/generated");
    for directory in 0..120 {
        let directory = large.join(format!("d{directory}"));
        std::fs::create_dir_all(&directory).unwrap();
        for file in 0..180 {
            std::fs::File::create(directory.join(format!("f{file}.ts"))).unwrap();
        }
    }
    write(f.home.join("app/docs/AGENTS.md"), "synthetic fixture\n");
    for path in ["**/AGENTS*", "**/*.md", "src/**/f1.ts"] {
        let result = omp(&f, "app", "glob", json!({"path": path}));
        assert!(allowed(&result), "{path}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_omp_directory_listing");
    }
    // A content search over the same tree is still bounded.
    let input = json!({"pattern": "deploy", "path": "."});
    assert!(!allowed(&omp(&f, "app", "grep", input)));
    // A directory link that leaves the prefix still fails the larger walk.
    std::os::unix::fs::symlink(f.home.join(".ssh"), large.join("d7/keys")).unwrap();
    let result = omp(&f, "app", "glob", json!({"path": "**/AGENTS*"}));
    assert!(!allowed(&result), "{}", result.reason_code);
}

#[test]
fn globs_list_a_linked_worktree_of_a_workspace_repository() {
    let f = fixture();
    // The session runs in `org`; the agent checks the repository out beside it.
    let repository = f.home.join("org/repo");
    let worktree = f.home.join("repo-fix");
    let copy = f.home.join("repo-copy");
    let admin = repository.join(".git/worktrees/repo-fix");
    std::fs::create_dir_all(&admin).unwrap();
    write(admin.join("commondir"), "../..\n");
    write(
        admin.join("gitdir"),
        &format!("{}/.git\n", worktree.display()),
    );
    write(
        worktree.join(".git"),
        &format!("gitdir: {}\n", admin.display()),
    );
    std::fs::create_dir_all(copy.join(".git")).unwrap();
    for checkout in [&repository, &worktree, &copy] {
        write(
            checkout.join("tests/auth-journey.test.ts"),
            "synthetic fixture\n",
        );
        write(
            checkout.join("tests/fixtures/tls/server.key"),
            "synthetic fixture\n",
        );
    }
    let glob = |checkout: &Path| {
        let path = format!("{}/tests/*auth*journey*", checkout.display());
        omp(&f, "org", "glob", json!({"path": path, "gitignore": true}))
    };
    for checkout in [&repository, &worktree] {
        let result = glob(checkout);
        assert!(
            allowed(&result),
            "{}: {}",
            checkout.display(),
            result.reason_code
        );
    }
    // A checkout that is not a worktree of the session's repository keeps
    // the stricter walk, which a key fixture below the prefix fails.
    assert!(!allowed(&glob(&copy)));
    // So does a worktree whose admin entry does not name it back.
    write(admin.join("gitdir"), &format!("{}/.git\n", copy.display()));
    assert!(!allowed(&glob(&worktree)));
}

#[test]
fn one_level_globs_list_only_the_directory_they_name() {
    let f = fixture();
    // A worktree package borrowing another checkout's installed packages.
    let shared = f.root.join("shared/node_modules");
    write(shared.join("pkg/index.js"), "synthetic fixture\n");
    write(f.home.join("app/web/package.json"), "{}\n");
    std::os::unix::fs::symlink(&shared, f.home.join("app/web/node_modules")).unwrap();
    write(f.home.join("app/bun.lock"), "synthetic fixture\n");
    let root = f.home.join("app");
    let root = root.to_str().unwrap();
    // Below a literal directory the host runs one segment without recursion,
    // so with the gitignore off it still never follows the link.
    for path in [
        format!("{root}/*lock*"),
        "./*lock*".to_owned(),
        "web/*".to_owned(),
    ] {
        let input = json!({"path": path, "gitignore": false, "hidden": true, "limit": 20});
        let result = omp(&f, "app", "glob", input);
        assert!(allowed(&result), "{path}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_omp_directory_listing");
    }
    // A walk that reaches the link, a selector inside it, or one outside the
    // session folder still gets the full proof.
    for path in [
        format!("{root}/**/*lock*"),
        // Without a directory the host searches `**/*lock*` from the cwd.
        "*lock*".to_owned(),
        "web/*/pkg/*".to_owned(),
        // The literal directory is the link itself: its canonical path is
        // outside the session folder.
        "web/node_modules/*".to_owned(),
        "~/.ssh/*".to_owned(),
        "~/*".to_owned(),
    ] {
        let input = json!({"path": path, "gitignore": false, "hidden": true});
        assert!(!allowed(&omp(&f, "app", "glob", input)), "{path}");
    }
    // The host's glob schema has no recursion switch; a key it does not
    // define, or a `pattern` the walk proof covers, keeps the full proof.
    let path = format!("{root}/*lock*");
    for input in [
        json!({"path": path, "gitignore": false, "recursive": true}),
        json!({"path": path, "gitignore": false, "maxDepth": 8}),
        json!({"path": path, "gitignore": false, "pattern": "*"}),
    ] {
        assert!(!allowed(&omp(&f, "app", "glob", input.clone())), "{input}");
    }
}
