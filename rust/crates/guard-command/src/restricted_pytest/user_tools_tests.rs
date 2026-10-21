use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A scratch tree under the first base whose ancestry is sealed. `/tmp` is
/// world-writable on Linux, so the crate directory serves there; with no
/// sealed base, every grant below must be refused instead.
struct Tree {
    root: PathBuf,
    sealed: bool,
}

impl Tree {
    fn new() -> Self {
        let bases = [
            std::env::temp_dir(),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        ];
        let base = bases
            .iter()
            .filter_map(|base| base.canonicalize().ok())
            .find(|base| sealed_ancestry(base))
            .unwrap_or_else(|| std::env::temp_dir().canonicalize().unwrap());
        let root = base.join(format!(
            ".guard-user-tools-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            sealed: sealed_ancestry(&base),
            root,
        }
    }

    /// `relative`, creating each missing directory with `mode`.
    fn dir(&self, relative: &str, mode: u32) -> PathBuf {
        let mut path = self.root.clone();
        for component in Path::new(relative).components() {
            path.push(component);
            if !path.exists() {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        path.canonicalize().unwrap()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_sealed_user_tool_directory_is_granted() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let workspace = tree.dir("repo", 0o755);
    for tool in [
        ".local/bin",
        "sdk/google-cloud-sdk/bin",
        "bin",
        ".pyenv/shims",
        ".rye/shims",
        ".asdf/shims",
    ] {
        let entry = tree.dir(&format!("home/{tool}"), 0o755);
        let granted = tool_root(&entry, std::slice::from_ref(&home), &workspace);
        assert_eq!(granted, tree.sealed.then(|| entry.clone()), "{tool}");
    }
}

#[test]
fn writable_ancestors_are_refused() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let workspace = tree.dir("repo", 0o755);
    for (directory, mode) in [
        ("home/open", 0o777),
        ("home/shared", 0o775),
        ("home/group", 0o770),
    ] {
        let parent = tree.dir(directory, mode);
        let entry = parent.join("bin");
        fs::create_dir(&entry).unwrap();
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            tool_root(&entry, std::slice::from_ref(&home), &workspace),
            None,
            "{directory}"
        );
    }
    let entry = tree.dir("home/writable/bin", 0o755);
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o757)).unwrap();
    assert_eq!(
        tool_root(&entry, std::slice::from_ref(&home), &workspace),
        None
    );
}

#[test]
fn workspace_agent_state_and_credential_directories_are_refused() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let workspace = tree.dir("repo", 0o755);
    let homes = std::slice::from_ref(&home);
    for refused in [
        "repo/bin",
        "repo/node_modules/.bin",
        "home/.hol-guard/package-shims/bin",
        "home/.hol-guard/bin",
        "home/.claude/plugins/cache/tool/bin",
        "home/.codex/bin",
        "home/.codex/shims",
        "home/.hol-guard/shims",
        "home/.ssh/shims",
        "home/.omp/bin",
        "home/.ssh/bin",
        "home/.config/tool/bin",
        "home/Library/Keychains/bin",
        "home/tools",
    ] {
        let entry = tree.dir(refused, 0o755);
        assert_eq!(tool_root(&entry, homes, &workspace), None, "{refused}");
    }
    // A directory that holds the workspace exposes it whole.
    let outer = tree.dir("outer/bin", 0o755);
    let nested = tree.dir("outer/bin/project", 0o755);
    assert_eq!(tool_root(&outer, homes, &nested), None);
    // HOME itself is never a tool directory, whatever its name.
    let bin_home = tree.dir("bin", 0o755);
    assert_eq!(
        tool_root(&bin_home, std::slice::from_ref(&bin_home), &workspace),
        None
    );
    // Without a known HOME nothing is granted.
    let entry = tree.dir("home/.local/bin", 0o755);
    assert_eq!(tool_root(&entry, &[], &workspace), None);
}

#[test]
fn package_manager_homes_are_granted_below_library() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let workspace = tree.dir("repo", 0o755);
    for tool in ["Library/pnpm", ".local/share/pnpm"] {
        let entry = tree.dir(&format!("home/{tool}"), 0o755);
        let granted = tool_root(&entry, std::slice::from_ref(&home), &workspace);
        assert_eq!(granted, tree.sealed.then(|| entry.clone()), "{tool}");
    }
    let nested = tree.dir("home/Library/pnpm/global", 0o755);
    assert_eq!(
        tool_root(&nested, std::slice::from_ref(&home), &workspace),
        None
    );
}

#[test]
fn corepack_cache_is_granted_only_when_sealed_and_inside_home() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    assert_eq!(corepack_home(&home), None);
    let cache = tree.dir("home/.cache/node/corepack", 0o755);
    assert_eq!(corepack_home(&home), tree.sealed.then(|| cache.clone()));
    fs::set_permissions(home.join(".cache/node"), fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(corepack_home(&home), None);

    let other = tree.dir("other", 0o755);
    let elsewhere = tree.dir("elsewhere/node/corepack", 0o755);
    symlink(
        elsewhere.parent().unwrap().parent().unwrap(),
        other.join(".cache"),
    )
    .unwrap();
    assert_eq!(corepack_home(&other), None);
}

#[test]
fn the_go_module_cache_is_granted_only_when_sealed_and_inside_home() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    assert_eq!(go_module_cache(&home), None);
    let cache = tree.dir("home/go/pkg/mod", 0o755);
    assert_eq!(go_module_cache(&home), tree.sealed.then(|| cache.clone()));
    fs::set_permissions(home.join("go/pkg"), fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(go_module_cache(&home), None);

    // A GOPATH that leaves HOME takes the cache out of reach.
    let other = tree.dir("other", 0o755);
    let elsewhere = tree.dir("elsewhere/pkg/mod", 0o755);
    symlink(
        elsewhere.parent().unwrap().parent().unwrap(),
        other.join("go"),
    )
    .unwrap();
    assert_eq!(go_module_cache(&other), None);
}

#[test]
fn the_cargo_caches_and_rustup_are_granted_only_when_sealed() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    assert!(cargo_caches(&home).is_empty());
    assert_eq!(rustup_home(&home), None);

    let registry = tree.dir("home/.cargo/registry", 0o755);
    let git = tree.dir("home/.cargo/git", 0o755);
    let rustup = tree.dir("home/.rustup", 0o755);
    if !tree.sealed {
        assert!(cargo_caches(&home).is_empty());
        assert_eq!(rustup_home(&home), None);
        return;
    }
    assert_eq!(
        cargo_caches(&home),
        vec![("registry", registry), ("git", git)]
    );
    assert_eq!(rustup_home(&home), Some(rustup));

    // Credentials and the host config sit beside the caches and are never
    // named, so neither reaches the run.
    fs::write(tree.root.join("home/.cargo/credentials.toml"), "").unwrap();
    fs::write(tree.root.join("home/.cargo/config.toml"), "").unwrap();
    assert!(cargo_caches(&home)
        .iter()
        .all(|(name, _)| *name == "registry" || *name == "git"));

    // A writable `.cargo` lets anything be dropped into the granted trees.
    fs::set_permissions(home.join(".cargo"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(cargo_caches(&home).is_empty());
}

#[test]
fn shim_siblings_grant_the_machinery_a_shim_dispatches_to() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let homes = std::slice::from_ref(&home);
    let workspace = tree.dir("repo", 0o755);
    let shims = tree.dir("home/.pyenv/shims", 0o755);
    let versions = tree.dir("home/.pyenv/versions/3.12.1/bin", 0o755);
    let libexec = tree.dir("home/.pyenv/libexec", 0o755);
    let loose = tree.dir("home/.pyenv/plugins", 0o777);
    fs::write(tree.root.join("home/.pyenv/version"), "3.12.1\n").unwrap();
    let granted = shim_siblings(&shims, homes, &workspace);
    if !tree.sealed {
        assert!(granted.is_empty());
        return;
    }
    let versions_root = versions.parent().unwrap().parent().unwrap().to_path_buf();
    assert!(granted.contains(&versions_root), "{granted:?}");
    assert!(granted.contains(&libexec), "{granted:?}");
    // A world-writable sibling and a plain file beside the shims stay out.
    assert!(!granted.contains(&loose), "{granted:?}");
    assert!(granted.iter().all(|path| path.is_dir()), "{granted:?}");
    // Only a directory named `shims` brings its siblings along.
    let bin = tree.dir("home/.local/bin", 0o755);
    tree.dir("home/.local/share", 0o755);
    assert!(shim_siblings(&bin, homes, &workspace).is_empty());
    // A sibling that holds the workspace would expose it whole.
    let nested = tree.dir("home/.pyenv/projects/checkout", 0o755);
    let held = nested.parent().unwrap().to_path_buf();
    assert!(!shim_siblings(&shims, homes, &nested).contains(&held));
}

#[test]
fn shims_in_a_shared_directory_grant_no_siblings() {
    let tree = Tree::new();
    let home = tree.dir("home", 0o755);
    let homes = std::slice::from_ref(&home);
    let workspace = tree.dir("repo", 0o755);
    // HOME itself, a shared area and agent state each hold directories that
    // have nothing to do with the manager whose shims sit among them.
    for parent in ["home", "home/.local", "home/.cache", "home/.codex"] {
        let shims = tree.dir(&format!("{parent}/shims"), 0o755);
        tree.dir(&format!("{parent}/machinery"), 0o755);
        assert!(
            shim_siblings(&shims, homes, &workspace).is_empty(),
            "{parent}"
        );
    }
    // Without a known HOME the manager root cannot be identified.
    let shims = tree.dir("home/.pyenv/shims", 0o755);
    tree.dir("home/.pyenv/libexec", 0o755);
    assert!(shim_siblings(&shims, &[], &workspace).is_empty());
}
