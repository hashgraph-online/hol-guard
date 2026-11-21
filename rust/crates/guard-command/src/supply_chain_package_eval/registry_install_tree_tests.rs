use super::*;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn document(value: Value) -> RegistryDocument {
    let Value::Object(object) = value else {
        panic!("registry document must be an object");
    };
    RegistryDocument {
        object,
        version_order: Vec::new(),
    }
}

/// A registry where `app-lib` needs `left` and `right`, and `right` 1.x needs
/// `leaf`. `right` 2.0.0 names a git dependency, and `shrink` ships a
/// shrinkwrap.
fn registry(name: &str) -> Option<RegistryDocument> {
    let value = match name {
        "app-lib" => json!({
            "dist-tags": {"latest": "1.1.0"},
            "versions": {
                "1.0.0": {"dependencies": {"left": "^1.0.0"}},
                "1.1.0": {"dependencies": {"left": "^1.0.0", "right": "~1.2.0"}},
            }
        }),
        "left" => json!({"versions": {"1.0.0": {}, "1.4.2": {"peerDependencies": {"leaf": "*"}}}}),
        "right" => json!({
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "1.2.0": {"optionalDependencies": {"leaf": ""}},
                "1.2.5": {"dependencies": {"leaf": ">=1 <2"}},
                "2.0.0": {"dependencies": {"leaf": "github:someone/leaf"}},
            }
        }),
        "leaf" => {
            json!({"versions": {"1.0.0": {}, "1.9.0-beta.1": {"dependencies": {"x": "git+https://example.test/x"}}}})
        }
        "shrink" => json!({"versions": {"1.0.0": {"_hasShrinkwrap": true}}}),
        "@scope/tool" => json!({"versions": {"3.0.0": {"dependencies": {"left": "1.0.0"}}}}),
        _ => return None,
    };
    Some(document(value))
}

fn walk(roots: &[(&str, &str)]) -> (bool, Vec<String>) {
    let mut fetched = Vec::new();
    let proven = registry_tree_is_git_free(
        roots
            .iter()
            .map(|(name, selector)| ((*name).to_owned(), (*selector).to_owned()))
            .collect(),
        &mut |name| {
            fetched.push(name.to_owned());
            registry(name)
        },
    );
    (proven, fetched)
}

#[test]
fn a_registry_only_tree_is_git_free() {
    let (proven, fetched) = walk(&[("app-lib", "latest"), ("@scope/tool", "^3")]);
    assert!(proven);
    // Each document is fetched once however many selectors reach it.
    let mut unique = fetched.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), fetched.len());
    assert!(fetched.contains(&"leaf".to_owned()));
}

#[test]
fn any_admitted_release_with_a_git_dependency_keeps_the_review() {
    // `latest` is 2.0.0, which names a git dependency.
    assert!(!walk(&[("right", "latest")]).0);
    // A range that admits 2.0.0 checks it even if npm might pick another.
    assert!(!walk(&[("right", ">=1.2.0")]).0);
    assert!(walk(&[("right", "~1.2.0")]).0);
    // Prereleases are outside a plain range, as npm resolves them.
    assert!(walk(&[("leaf", "^1.0.0")]).0);
}

#[test]
fn unreadable_unbounded_or_unresolvable_trees_keep_the_review() {
    assert!(!walk(&[("shrink", "1.0.0")]).0);
    assert!(!walk(&[("missing", "^1.0.0")]).0);
    assert!(!walk(&[("left", "^9.0.0")]).0);
    assert!(!walk(&[("Left", "^1.0.0")]).0);
    assert!(!walk(&[("left", "npm:other@1")]).0);

    let mut fetches = 0;
    let wide = registry_tree_is_git_free(vec![("pkg-0".to_owned(), "*".to_owned())], &mut |name| {
        fetches += 1;
        let index: usize = name.trim_start_matches("pkg-").parse().ok()?;
        let next = format!("pkg-{}", index + 1);
        Some(document(
            json!({"versions": {"1.0.0": {"dependencies": {next: "*"}}}}),
        ))
    });
    assert!(!wide);
    assert_eq!(fetches, MAX_TREE_PACKAGES);
}

static PROJECTS: AtomicUsize = AtomicUsize::new(0);

fn project(files: &[(&str, Value)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-npm-tree-{}-{}",
        std::process::id(),
        PROJECTS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    for (name, value) in files {
        std::fs::write(root.join(name), serde_json::to_vec(value).unwrap()).unwrap();
    }
    root
}

fn roots(root: &Path) -> Option<Vec<(String, String)>> {
    let roots = project_roots(root);
    std::fs::remove_dir_all(root).unwrap();
    roots
}

#[test]
fn every_project_dependency_joins_the_walk_whatever_the_lock_pins() {
    let root = project(&[
        (
            "package.json",
            json!({"dependencies": {"left": "^1.0.0", "right": "~1.2.0"}, "devDependencies": {"leaf": ""}}),
        ),
        (
            "package-lock.json",
            json!({"packages": {
                "": {"name": "app"},
                "node_modules/left": {"resolved": "https://registry.npmjs.org/left/-/left-1.4.2.tgz"},
                "node_modules/left/node_modules/inner": {"resolved": "https://registry.npmjs.org/inner/-/inner-1.0.0.tgz"},
                "node_modules/@scope/tool": {"resolved": "https://registry.npmjs.org/@scope/tool/-/tool-3.0.0.tgz"},
                "node_modules/bundled": {"inBundle": true},
            }}),
        ),
    ]);
    assert_eq!(
        roots(&root),
        Some(vec![
            ("left".to_owned(), "^1.0.0".to_owned()),
            ("right".to_owned(), "~1.2.0".to_owned()),
            ("leaf".to_owned(), "*".to_owned()),
        ])
    );
}

#[test]
fn project_sources_other_than_the_registry_keep_the_review() {
    let lock = |key: &str, entry: Value| json!({"packages": {"": {}, key: entry}});
    let left = |resolved: &str| lock("node_modules/left", json!({"resolved": resolved}));
    for files in [
        vec![(
            "package.json",
            json!({"dependencies": {"left": "github:someone/left"}}),
        )],
        vec![(
            "package.json",
            json!({"devDependencies": {"left": "file:../left"}}),
        )],
        vec![(
            "package.json",
            json!({"dependencies": {"left": "npm:other@1"}}),
        )],
        vec![("package.json", json!({"overrides": {"left": "1.0.0"}}))],
        vec![("package.json", json!({"workspaces": ["packages/*"]}))],
        vec![("package.json", json!({"dependencies": ["left"]}))],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("git+ssh://git@github.com/someone/left.git#abc"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.example.test/left/-/left-1.0.0.tgz"),
            ),
        ],
        // A registry tarball of another package under this name, directly
        // or through a noncanonical path.
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/other/-/other-1.0.0.tgz"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/../../other/-/other-1.0.0.tgz"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/%2e%2e/%2e%2e/other/-/other-1.0.0.tgz"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/other-1.0.0.tgz"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/left-1.0.0.tgz?x=../other"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/left-1.0.0.tgz#frag"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                left("https://registry.npmjs.org/left/-/left-.tgz"),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                lock("node_modules/left", json!({"link": true})),
            ),
        ],
        vec![
            ("package.json", json!({})),
            ("package-lock.json", lock("node_modules/left", json!({}))),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                lock(
                    "packages/left",
                    json!({"resolved": "https://registry.npmjs.org/left/-/left-1.0.0.tgz"}),
                ),
            ),
        ],
        vec![
            ("package.json", json!({})),
            ("npm-shrinkwrap.json", json!({"lockfileVersion": 1})),
        ],
        // npm builds a locked tree's edges from the lock entries themselves.
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                lock(
                    "node_modules/left",
                    json!({
                        "resolved": "https://registry.npmjs.org/left/-/left-1.0.0.tgz",
                        "dependencies": {"x": "github:someone/x"},
                    }),
                ),
            ),
        ],
        vec![
            ("package.json", json!({})),
            (
                "package-lock.json",
                json!({"packages": {"": {"optionalDependencies": {"x": "file:../x"}}}}),
            ),
        ],
        vec![],
    ] {
        let root = project(&files);
        assert_eq!(roots(&root), None, "{files:?}");
    }
}

#[test]
fn a_project_npm_could_install_from_a_workspace_root_keeps_the_review() {
    let workspace = project(&[("package.json", json!({"workspaces": ["app"]}))]);
    let member = workspace.join("app");
    std::fs::create_dir(&member).unwrap();
    std::fs::write(member.join("package.json"), b"{}").unwrap();
    assert_eq!(project_roots(&member), None);
    std::fs::write(workspace.join("package.json"), b"{}").unwrap();
    assert_eq!(project_roots(&member), Some(Vec::new()));
    assert_eq!(project_roots(Path::new("app")), None);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn lock_declared_edges_join_the_walk() {
    let root = project(&[
        ("package.json", json!({"dependencies": {"left": "^1.0.0"}})),
        (
            "package-lock.json",
            json!({"packages": {
                "": {"dependencies": {"left": "^1.0.0"}},
                "node_modules/left": {
                    "resolved": "https://registry.npmjs.org/left/-/left-1.0.0.tgz",
                    "peerDependencies": {"right": ">=1.2.0"},
                },
            }}),
        ),
    ]);
    let roots = roots(&root).unwrap();
    assert!(roots.contains(&("right".to_owned(), ">=1.2.0".to_owned())));
    // `right` 2.0.0 names a git dependency, so the lock's edge keeps the review.
    assert!(!registry_tree_is_git_free(roots, &mut registry));
}
