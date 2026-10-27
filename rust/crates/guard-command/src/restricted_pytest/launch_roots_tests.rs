use super::*;
use std::os::unix::fs::PermissionsExt;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A fresh directory holding `workspace/` and `tools/`; neither `tools`
/// directory is a `bin` the toolchain rules could accept.
fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-launch-roots-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("workspace")).unwrap();
    fs::create_dir_all(root.join("tools")).unwrap();
    root.canonicalize().unwrap()
}

fn tool(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn outside(root: &Path, program: &str, search_path: &str) -> bool {
    let workspace = root.join("workspace");
    outside_from(root, program, search_path, vec![Some(workspace)])
}

/// Whether `program` is unreachable when the shell may be in any of `places`.
fn outside_from(
    root: &Path,
    program: &str,
    search_path: &str,
    places: Vec<Option<PathBuf>>,
) -> bool {
    let workspace = root.join("workspace");
    launches_outside_exec_roots([(program, places)], search_path, None, &workspace)
}

#[test]
fn a_program_found_only_outside_the_roots_is_unreachable() {
    let root = scratch();
    tool(&root.join("tools/lanectl"), "#!/bin/sh\n");
    let search_path = format!("{}:/usr/bin:/bin", root.join("tools").display());

    assert!(outside(&root, "lanectl", &search_path));
    assert!(outside(
        &root,
        root.join("tools/lanectl").to_str().unwrap(),
        "/usr/bin:/bin"
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn system_and_workspace_programs_stay_reachable() {
    let root = scratch();
    tool(&root.join("workspace/run.sh"), "#!/bin/sh\necho ok\n");

    assert!(!outside(&root, "sh", "/usr/bin:/bin"));
    assert!(!outside(&root, "./run.sh", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_name_the_shell_cannot_find_is_left_to_the_shell() {
    let root = scratch();

    assert!(!outside(&root, "cd-not-a-real-program", "/usr/bin:/bin"));
    assert!(!outside(&root, "$TOOL", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_workspace_script_whose_interpreter_is_outside_is_unreachable() {
    let root = scratch();
    let python = root.join("tools/python3");
    tool(&python, "");
    tool(
        &root.join("workspace/direct.py"),
        &format!("#!{}\nprint('x')\n", python.display()),
    );
    tool(
        &root.join("workspace/by-name.py"),
        "#!/usr/bin/env -S lanectl-python -u\n",
    );
    tool(&root.join("workspace/system.sh"), "#!/usr/bin/env sh\n");

    assert!(outside(&root, "./direct.py", "/usr/bin:/bin"));
    assert!(outside(&root, "./by-name.py", "/usr/bin:/bin"));
    assert!(!outside(&root, "./system.sh", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn an_env_interpreter_outside_the_roots_is_unreachable() {
    let root = scratch();
    let env = root.join("tools/env");
    tool(&env, "");
    tool(
        &root.join("workspace/by-env.py"),
        &format!("#!{} sh\n", env.display()),
    );
    tool(
        &root.join("workspace/quoted.py"),
        "#!/usr/bin/env -S -u FOO \"sh\"\n",
    );
    tool(
        &root.join("workspace/ambiguous.py"),
        "#!/usr/bin/env -S \"sh\n",
    );

    assert!(outside(&root, "./by-env.py", "/usr/bin:/bin"));
    assert!(!outside(&root, "./quoted.py", "/usr/bin:/bin"));
    assert!(outside(&root, "./ambiguous.py", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn relative_search_path_entries_resolve_from_the_session_directory() {
    let root = scratch();
    fs::create_dir_all(root.join("workspace/bin")).unwrap();
    tool(&root.join("workspace/bin/lanectl"), "#!/bin/sh\n");
    tool(&root.join("workspace/lanectl-here"), "#!/bin/sh\n");

    // Neither directory exists below this process's own working directory,
    // and the sandbox's search path has no relative entry to find them by.
    assert!(outside(&root, "lanectl", "bin:/usr/bin:/bin"));
    assert!(outside(&root, "lanectl-here", ":/usr/bin:/bin"));
    assert!(outside(&root, "lanectl-here", "/usr/bin:.:/bin"));
    assert!(!outside(&root, "lanectl-missing", "bin:/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_program_is_looked_up_from_every_directory_the_shell_may_be_in() {
    let root = scratch();
    let (workspace, tools) = (root.join("workspace"), root.join("workspace/tools"));
    fs::create_dir_all(&tools).unwrap();
    let python = root.join("tools/python3");
    tool(&python, "");
    tool(&tools.join("lanectl"), &format!("#!{}\n", python.display()));
    let path = "/usr/bin:/bin";

    assert!(!outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(workspace.clone())]
    ));
    assert!(outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(tools.clone())]
    ));
    assert!(outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(workspace), Some(tools)]
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_lookup_that_needs_an_unknown_directory_is_unreachable() {
    let root = scratch();
    let unknown = || vec![None];

    assert!(outside_from(&root, "./run.sh", "/usr/bin:/bin", unknown()));
    assert!(outside_from(&root, "sh", "bin:/usr/bin:/bin", unknown()));
    assert!(!outside_from(&root, "sh", "/usr/bin:/bin", unknown()));
    assert!(!outside_from(
        &root,
        "/bin/sh",
        "bin:/usr/bin:/bin",
        unknown()
    ));
    let _ = fs::remove_dir_all(root);
}

/// Make `workspace` a linked worktree of the checkout at `main`.
fn link_worktree(root: &Path) {
    let (main, workspace) = (root.join("main"), root.join("workspace"));
    let admin = main.join(".git/worktrees/wt");
    fs::create_dir_all(&admin).unwrap();
    fs::write(admin.join("commondir"), "../..\n").unwrap();
    fs::write(
        admin.join("gitdir"),
        format!("{}/.git\n", workspace.display()),
    )
    .unwrap();
    fs::write(
        workspace.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
}

#[test]
fn a_linked_worktree_runs_programs_from_its_main_checkout() {
    let root = scratch();
    let (main, workspace) = (root.join("main"), root.join("workspace"));
    fs::create_dir_all(main.join("node_modules/lanectl/bin")).unwrap();
    tool(
        &main.join("node_modules/lanectl/bin/lanectl"),
        "#!/bin/sh\n",
    );
    fs::create_dir_all(workspace.join("node_modules/.bin")).unwrap();
    std::os::unix::fs::symlink(
        main.join("node_modules/lanectl/bin/lanectl"),
        workspace.join("node_modules/.bin/lanectl"),
    )
    .unwrap();
    let launch = "./node_modules/.bin/lanectl";

    // Without the link the main checkout is just another directory.
    assert!(outside(&root, launch, "/usr/bin:/bin"));
    link_worktree(&root);
    assert!(!outside(&root, launch, "/usr/bin:/bin"));
    // Only the checkout opens: a sibling directory stays outside.
    tool(&root.join("tools/other"), "#!/bin/sh\n");
    assert!(outside(
        &root,
        root.join("tools/other").to_str().unwrap(),
        "/usr/bin:/bin"
    ));
    let _ = fs::remove_dir_all(root);
}

/// The sealed system directories beside `/usr/bin` hold the tools a session
/// reads its own machine with. `/usr` cannot be taken whole on macOS because
/// `/usr/local` is writable by an admin user, so each one is named; leaving
/// `/usr/sbin` and `/sbin` out made `sysctl -n hw.ncpu` unreachable and sent
/// a command that only reports the CPU count to review. Linux executes all of
/// `/usr` and `/sbin`, and the sandbox PATH keeps those entries there too.
#[test]
fn the_sealed_system_program_directories_are_reachable() {
    let root = scratch();
    for program in ["sysctl", "ifconfig", "ping", "netstat"] {
        if Path::new("/usr/sbin").join(program).exists()
            || Path::new("/sbin").join(program).exists()
        {
            assert!(
                !outside(&root, program, "/usr/bin:/bin:/usr/sbin:/sbin"),
                "{program}"
            );
        }
    }
    // `/usr/local` is not a program root: an admin user writes there, so a
    // command could run something it had just placed in it.
    tool(&root.join("tools").join("planted"), "#!/bin/sh\nexit 0\n");
    let tools = root.join("tools");
    assert!(outside(&root, "planted", tools.to_str().unwrap()));
    let _ = fs::remove_dir_all(&root);
}

/// The mode every fixture directory of a sealed tree is given. A grant
/// requires that no account but this user or root can write any directory
/// involved, and `create_dir_all` applies the process umask, so under a
/// group-writable umask such as `002` the fixtures would otherwise be
/// rejected for a reason the test is not about.
const SEALED_MODE: u32 = 0o755;

/// `path`, created with every directory it adds at or below `base` writable
/// by its owner alone.
fn sealed_dirs(base: &Path, path: &Path) {
    fs::create_dir_all(path).unwrap();
    for ancestor in path.ancestors().take_while(|dir| dir.starts_with(base)) {
        fs::set_permissions(ancestor, fs::Permissions::from_mode(SEALED_MODE)).unwrap();
    }
}

/// A scratch root under the build directory rather than the shared temporary
/// directory. A tool directory is only granted when every directory above it
/// is this user's or root's and no other account can write it, and `/tmp` is
/// world-writable, so a tree built there can never be accepted. The build
/// directory itself is sealed too, since the umask cargo created it under is
/// not this test's to choose.
fn sealed_scratch() -> PathBuf {
    let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let root = build.join("guard-launch-roots-sealed").join(format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    sealed_dirs(&build, &root.join("workspace"));
    root.canonicalize().unwrap()
}

/// Whether `program` is unreachable with `root` as the caller's HOME, so the
/// answer does not depend on the account the tests run under.
fn outside_at_home(root: &Path, program: &str, search_path: &str) -> bool {
    let workspace = root.join("workspace");
    launches_outside_exec_roots(
        [(program, vec![Some(workspace.clone())])],
        search_path,
        Some(root),
        &workspace,
    )
}

#[test]
fn a_tool_directory_inside_an_installed_package_tree_is_reachable() {
    // The layout a harness puts on the agent shell's PATH: a vendored
    // directory inside a platform package, named by the harness rather than
    // `bin` or `shims`, holding the tool it wants always found.
    let root = sealed_scratch();
    let vendored = root.join(
        "node_modules/@vendor/harness-cli-linux-x64/vendor/x86_64-unknown-linux-gnu/cli-path",
    );
    sealed_dirs(&root, &vendored);
    tool(&vendored.join("rg"), "#!/bin/sh\nexit 0\n");
    let search_path = format!("{}:/usr/bin:/bin", vendored.display());

    assert!(!outside_at_home(&root, "rg", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_link_directory_of_an_installed_package_tree_reaches_the_package_it_names() {
    // `node_modules/.bin` holds links into the packages beside it, so the
    // directory on PATH is not where the program it names actually lives.
    let root = sealed_scratch();
    let package = root.join("node_modules/harness-cli/bin");
    let links = root.join("node_modules/.bin");
    sealed_dirs(&root, &package);
    sealed_dirs(&root, &links);
    tool(&package.join("rg"), "#!/bin/sh\nexit 0\n");
    std::os::unix::fs::symlink(package.join("rg"), links.join("rg")).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", links.display());

    assert!(!outside_at_home(&root, "rg", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_package_another_account_can_write_grants_no_tree() {
    // The links in a `.bin` directory resolve into the packages beside it,
    // so those directories are where the run would execute from. Sealing the
    // directory on PATH says nothing about them: when one is writable by
    // another account, that account picks the program, and the tree is not
    // granted at all.
    let root = sealed_scratch();
    let package = root.join("node_modules/harness-cli/bin");
    let links = root.join("node_modules/.bin");
    sealed_dirs(&root, &package);
    sealed_dirs(&root, &links);
    tool(&package.join("rg"), "#!/bin/sh\nexit 0\n");
    std::os::unix::fs::symlink(package.join("rg"), links.join("rg")).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", links.display());
    assert!(!outside_at_home(&root, "rg", &search_path));

    fs::set_permissions(&package, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(outside_at_home(&root, "rg", &search_path));
    // The package directory itself, not only the link target's own file.
    fs::set_permissions(&package, fs::Permissions::from_mode(SEALED_MODE)).unwrap();
    let parent = package.parent().unwrap().to_path_buf();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(outside_at_home(&root, "rg", &search_path));

    fs::set_permissions(&parent, fs::Permissions::from_mode(SEALED_MODE)).unwrap();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_directory_outside_any_package_tree_is_still_unreachable() {
    // The grant is the installed dependency tree, not every sealed directory
    // the caller happens to put on PATH.
    let root = sealed_scratch();
    let loose = root.join("vendor/cli-path");
    sealed_dirs(&root, &loose);
    tool(&loose.join("rg"), "#!/bin/sh\nexit 0\n");
    let search_path = format!("{}:/usr/bin:/bin", loose.display());

    assert!(outside_at_home(&root, "rg", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_package_tree_inside_the_workspace_grants_no_root_of_its_own() {
    // The workspace is already executable inside the sandbox; a dependency
    // tree below it must not widen the grant to anything above the workspace.
    let root = sealed_scratch();
    let links = root.join("workspace/node_modules/.bin");
    let outer = root.join("node_modules/escaped/bin");
    sealed_dirs(&root, &links);
    sealed_dirs(&root, &outer);
    tool(&outer.join("rg"), "#!/bin/sh\nexit 0\n");
    std::os::unix::fs::symlink(outer.join("rg"), links.join("rg")).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", links.display());

    assert!(outside_at_home(&root, "rg", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_package_manager_behind_guards_shim_is_reachable() {
    // Guard's own package shims sit first on the PATH of every session it
    // supervises, and the sandbox executes from none of them, so reading the
    // shim as the program made `pnpm run build` unreachable on every machine
    // the shims are installed on. The program behind the shim is the one the
    // sandbox would run.
    let root = sealed_scratch();
    let shims = root.join(".hol-guard/package-shims/bin");
    let node = root.join(".nvm/versions/node/v25.2.1/bin");
    sealed_dirs(&root, &shims);
    sealed_dirs(&root, &node);
    tool(&shims.join("pnpm"), "#!/bin/sh\nexit 0\n");
    tool(&node.join("pnpm"), "#!/bin/sh\nexit 0\n");
    let search_path = format!("{}:{}:/usr/bin:/bin", shims.display(), node.display());

    assert!(!outside_at_home(&root, "pnpm", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_program_only_a_shim_answers_for_is_unreachable() {
    // Nothing stands behind the shim on this PATH, and the sandbox executes
    // nothing from the shim directory, so containing the command would trade
    // a review for a command the run cannot find.
    let root = sealed_scratch();
    let shims = root.join(".hol-guard/package-shims/bin");
    sealed_dirs(&root, &shims);
    tool(&shims.join("pnpm"), "#!/bin/sh\nexit 0\n");
    // Only the fixture shim is on PATH. A host `pnpm` in `/usr/bin` or
    // `/bin` would answer the retry and hide a shim that nothing stands
    // behind.
    let search_path = shims.display().to_string();

    assert!(outside_at_home(&root, "pnpm", &search_path));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_project_package_shim_directory_stays_reachable() {
    // The two trailing names are how Guard lays its shims out, and they are
    // also a directory a project is free to use. One inside the workspace is
    // a path the sandbox already executes, so it is not the shim layer the
    // retry strips.
    let root = sealed_scratch();
    let shims = root.join("workspace/package-shims/bin");
    sealed_dirs(&root, &shims);
    tool(&shims.join("pnpm"), "#!/bin/sh\nexit 0\n");
    let search_path = shims.display().to_string();

    assert!(!outside_at_home(&root, "pnpm", &search_path));
    let _ = fs::remove_dir_all(&root);
}
