use super::*;
use std::os::unix::fs::PermissionsExt;

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Layout {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    workspace: PathBuf,
}

impl Layout {
    fn new(tag: &str) -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root =
            std::env::temp_dir().join(format!("guard-grant-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let home = root.join("home");
        let bin = home.join("tools/bin");
        let workspace = root.join("work");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let program = bin.join("lanectl");
        std::fs::write(&program, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            home,
            bin,
            workspace,
        }
    }

    fn search_path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.display())
    }

    /// An executable file with `text` as its content.
    fn program(&self, path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn grant(capabilities: &[&str]) -> GrantInput {
    GrantInput {
        identity_hash: HASH.to_owned(),
        name: "lanectl".to_owned(),
        capabilities: capabilities.iter().map(|name| (*name).to_owned()).collect(),
    }
}

fn base_plan() -> Value {
    json!({
        "profile_version": "workspace-contained-v1",
        "exec_roots": [],
        "sandbox_path": "/usr/bin:/bin",
        "read_only_roots": [],
        "grant_identity_hash": null,
        "capabilities": [],
    })
}

fn widened(layout: &Layout, grant: &GrantInput, platform: &str) -> Result<Value, String> {
    let mut plan = base_plan();
    widen(
        &mut plan,
        grant,
        "lanectl",
        &layout.search_path(),
        Some(&layout.home),
        &layout.workspace,
        platform,
    )
    .map(|()| plan)
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn capability_names_must_be_known_sorted_and_distinct() {
    let names = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(grant_capabilities(&names(&[])).is_some());
    assert!(grant_capabilities(&names(&GRANT_CAPABILITIES)).is_some());
    for refused in [
        names(&["network"]),
        names(&["state-dir-write", "state-dir-read"]),
        names(&["loopback-network", "loopback-network"]),
    ] {
        assert!(grant_capabilities(&refused).is_none(), "{refused:?}");
    }
}

#[test]
fn the_plan_runs_the_granted_program_as_a_file() {
    let layout = Layout::new("exec");
    let plan = widened(
        &layout,
        &grant(&["loopback-network", "state-dir-read"]),
        "darwin",
    )
    .unwrap();
    assert_eq!(plan["profile_version"], GRANT_PROFILE);
    assert_eq!(plan["grant_identity_hash"], HASH);
    assert_eq!(
        plan["capabilities"],
        json!(["loopback-network", "state-dir-read"])
    );
    // The program's own file, not the directory it sits in; its interpreter,
    // `/bin/sh`, is reachable already.
    assert_eq!(
        plan["exec_roots"],
        json!([layout.bin.join("lanectl")]),
        "{plan}"
    );
    let sandbox_path = plan["sandbox_path"].as_str().unwrap();
    assert!(
        sandbox_path.starts_with(&format!("{}:", layout.bin.display())),
        "the session found it first: {sandbox_path}"
    );
    assert_eq!(
        plan["read_only_roots"],
        json!([layout.home.join(".lanectl")])
    );
}

#[test]
fn a_tool_in_a_shared_directory_opens_none_of_its_neighbours() {
    let layout = Layout::new("shared");
    let downloads = layout.home.join("Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    layout.program(&downloads.join("lanectl"), "#!/bin/sh\necho ok\n");
    std::fs::write(downloads.join("statement.txt"), "private").unwrap();
    let search_path = format!("{}:/usr/bin:/bin", downloads.display());
    let mut plan = base_plan();
    widen(
        &mut plan,
        &grant(&[]),
        "lanectl",
        &search_path,
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .unwrap();
    let roots: Vec<PathBuf> = serde_json::from_value(plan["exec_roots"].clone()).unwrap();
    assert_eq!(roots, vec![downloads.join("lanectl")]);
    assert!(!path_is_within_any(
        &downloads.join("statement.txt"),
        &roots
    ));
}

#[test]
fn a_link_named_unlike_its_target_is_found_by_its_name() {
    let layout = Layout::new("named");
    let real = layout.home.join("tools/real");
    let links = layout.home.join("links");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(&links).unwrap();
    layout.program(&real.join("lanectl-real"), "#!/bin/sh\necho ok\n");
    std::os::unix::fs::symlink("../tools/real/lanectl-real", links.join("lanectl")).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", links.display());
    let mut plan = base_plan();
    widen(
        &mut plan,
        &grant(&[]),
        "lanectl",
        &search_path,
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .unwrap();
    let roots: Vec<PathBuf> = serde_json::from_value(plan["exec_roots"].clone()).unwrap();
    assert_eq!(
        roots,
        vec![links.join("lanectl"), real.join("lanectl-real")]
    );
    // The shell finds the link by the name it typed, in the entry it was in.
    let sandbox_path = plan["sandbox_path"].as_str().unwrap();
    assert!(
        sandbox_path.starts_with(&format!("{}:", links.display())),
        "{sandbox_path}"
    );
    let found =
        super::super::workspace_grant_launch::found("lanectl", sandbox_path, &layout.workspace);
    assert_eq!(
        found.and_then(|path| path.canonicalize().ok()),
        Some(real.join("lanectl-real"))
    );
}

#[test]
fn every_link_on_the_way_to_the_program_is_opened() {
    let layout = Layout::new("chain");
    let real = layout.home.join("tools/real");
    let hop = layout.home.join("hop");
    let links = layout.home.join("links");
    for directory in [&real, &hop, &links] {
        std::fs::create_dir_all(directory).unwrap();
    }
    layout.program(&real.join("lanectl-real"), "#!/bin/sh\necho ok\n");
    std::os::unix::fs::symlink("../tools/real/lanectl-real", hop.join("step")).unwrap();
    std::os::unix::fs::symlink(hop.join("step"), links.join("lanectl")).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", links.display());
    let mut plan = base_plan();
    widen(
        &mut plan,
        &grant(&[]),
        "lanectl",
        &search_path,
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .unwrap();
    assert_eq!(
        plan["exec_roots"],
        json!([
            links.join("lanectl"),
            hop.join("step"),
            real.join("lanectl-real")
        ])
    );
}

#[test]
fn a_directory_link_on_the_way_is_never_opened() {
    let layout = Layout::new("dirlink");
    let linked = layout.home.join("linkbin");
    std::os::unix::fs::symlink(&layout.bin, &linked).unwrap();
    let search_path = format!("{}:/usr/bin:/bin", linked.display());
    let mut plan = base_plan();
    assert!(widen(
        &mut plan,
        &grant(&[]),
        "lanectl",
        &search_path,
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .is_err());
    assert_eq!(plan["exec_roots"], json!([]), "nothing was opened");
}

#[test]
fn a_script_interpreter_is_opened_as_a_file_too() {
    let layout = Layout::new("interpreter");
    let runtime = layout.home.join("tools/runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let interpreter = runtime.join("lane-interp");
    layout.program(&interpreter, "#!/bin/sh\nexit 0\n");
    std::fs::write(runtime.join("neighbour"), "data").unwrap();
    layout.program(
        &layout.bin.join("lanectl"),
        &format!("#!{}\necho ok\n", interpreter.display()),
    );
    let plan = widened(&layout, &grant(&[]), "darwin").unwrap();
    let roots: Vec<PathBuf> = serde_json::from_value(plan["exec_roots"].clone()).unwrap();
    assert_eq!(roots, vec![layout.bin.join("lanectl"), interpreter]);
    assert!(!path_is_within_any(&runtime.join("neighbour"), &roots));
}

#[test]
fn the_session_entry_goes_ahead_of_the_accepted_entries_it_came_before() {
    let layout = Layout::new("order");
    let other = layout.home.join("other/bin");
    std::fs::create_dir_all(&other).unwrap();
    layout.program(&other.join("lanectl"), "#!/bin/sh\necho other\n");
    let search_path = format!("{}:{}:/usr/bin:/bin", layout.bin.display(), other.display());
    let mut plan = base_plan();
    plan["sandbox_path"] = json!(format!("{}:/usr/bin:/bin", other.display()));
    widen(
        &mut plan,
        &grant(&[]),
        "lanectl",
        &search_path,
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .unwrap();
    assert_eq!(
        plan["sandbox_path"],
        json!(format!(
            "{}:{}:/usr/bin:/bin",
            layout.bin.display(),
            other.display()
        ))
    );
}

#[test]
fn linux_keeps_every_capability_denied() {
    let layout = Layout::new("linux");
    let plan = widened(&layout, &grant(&GRANT_CAPABILITIES), "linux").unwrap();
    assert_eq!(plan["capabilities"], json!([]));
    assert_eq!(plan["read_only_roots"], json!([]));
    assert_eq!(plan["exec_roots"], json!([layout.bin.join("lanectl")]));
}

#[test]
fn an_invalid_grant_or_unlocatable_program_is_refused() {
    let layout = Layout::new("refused");
    assert!(widened(&layout, &grant(&["network"]), "darwin").is_err());
    let mut short = grant(&[]);
    short.identity_hash = "abc".to_owned();
    assert!(widened(&layout, &short, "darwin").is_err());
    let mut plan = base_plan();
    assert!(widen(
        &mut plan,
        &grant(&[]),
        "missing-cli",
        &layout.search_path(),
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .is_err());
    // A shared directory name grants no state, though the network grant holds.
    let mut shared = grant(&["state-dir-read"]);
    shared.name = "ssh".to_owned();
    assert!(widened(&layout, &shared, "darwin").is_err());
    shared.capabilities = vec!["loopback-network".to_owned()];
    assert!(widened(&layout, &shared, "darwin").is_ok());
}

#[test]
fn the_state_directory_is_a_plain_name_inside_home() {
    let layout = Layout::new("state");
    assert_eq!(
        state_dir("lanectl", &layout.home),
        Some(layout.home.join(".lanectl"))
    );
    for name in [
        "", "x", "Lanectl", "lane.ctl", "../x", "lane/ctl", "ssh", "aws", "config",
    ] {
        assert_eq!(state_dir(name, &layout.home), None, "{name}");
    }
    assert_eq!(state_dir("lanectl", Path::new("relative")), None);
    // A link in place of the directory is never followed.
    std::os::unix::fs::symlink(&layout.workspace, layout.home.join(".linked")).unwrap();
    assert_eq!(state_dir("linked", &layout.home), None);
}

#[test]
fn profile_rules_accept_only_the_state_directory_of_a_state_grant() {
    let layout = Layout::new("rules");
    let state = layout.home.join(".lanectl");
    let caps = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    let rules = super::rules(
        &caps(&["state-dir-write"]),
        std::slice::from_ref(&state),
        Some(&layout.home),
    )
    .unwrap();
    assert_eq!(rules.reads, vec![state.clone()]);
    assert_eq!(rules.writes, vec![state.clone()]);
    assert!(rules.network.is_empty());
    let read = super::rules(
        &caps(&["state-dir-read"]),
        std::slice::from_ref(&state),
        Some(&layout.home),
    )
    .unwrap();
    assert!(read.writes.is_empty());
    for (capabilities, roots) in [
        (caps(&[]), vec![state.clone()]),
        (caps(&["state-dir-read"]), vec![layout.home.clone()]),
        (
            caps(&["state-dir-read"]),
            vec![layout.home.join(".other"), state.clone()],
        ),
        (
            caps(&["state-dir-read"]),
            vec![layout.workspace.join(".lanectl")],
        ),
        (caps(&["network"]), vec![]),
    ] {
        assert!(
            super::rules(&capabilities, &roots, Some(&layout.home)).is_err(),
            "{capabilities:?} {roots:?}"
        );
    }
    let loopback = super::rules(&caps(&["loopback-network"]), &[], Some(&layout.home)).unwrap();
    assert_eq!(loopback.network, loopback_any_port());
}
