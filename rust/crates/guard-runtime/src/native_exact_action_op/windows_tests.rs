//! Windows exact-action proofs on a real `C:\` workspace.
//!
//! The requests carry what a Windows harness sends (drive-rooted paths, the
//! process `PATH` with `;` separators and `PATHEXT`) and run through the
//! resident engines, so a saved "Always" for an ordinary file tool mints a
//! token while every spelling Windows would open as a different file, or that
//! Guard cannot pin, stays a one-time decision.

use std::collections::BTreeMap;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use guard_contracts::{NativeExactActionQueryV1, NativePolicyBindingV1, NativeReviewFactsV1};
use serde_json::{json, Value};

use super::exact_action_token;

/// A scratch tree: `ws` is the workspace, `home` and `outside` sit beside it.
struct Tree {
    root: String,
}

impl Tree {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "eaw-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for dir in ["ws\\src", "home", "outside"] {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        let root = path.canonicalize().unwrap();
        let root = root
            .to_str()
            .unwrap()
            .trim_start_matches(r"\\?\")
            .to_owned();
        let tree = Self { root };
        tree.write("ws\\src\\main.rs", "fn main() {}\n");
        tree.write("ws\\src\\lib.rs", "pub fn lib() {}\n");
        tree.write("ws\\src\\long-file-name-here.txt", "notes\n");
        tree.write("outside\\notes.txt", "elsewhere\n");
        tree
    }

    fn path(&self, relative: &str) -> String {
        format!("{}\\{relative}", self.root)
    }

    fn write(&self, relative: &str, text: &str) {
        std::fs::write(self.path(relative), text).unwrap();
    }

    fn ws(&self) -> String {
        self.path("ws")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn cmd(cwd: &str, line: &str) -> String {
    let output = Command::new("cmd.exe")
        .raw_arg(format!("/d /c {line}"))
        .current_dir(cwd)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn environment() -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = ["PATH", "PATHEXT", "SystemRoot", "USERPROFILE"]
        .into_iter()
        .filter_map(|name| Some((name.to_owned(), std::env::var(name).ok()?)))
        .collect();
    if let Some(path) = env.get_mut("PATH") {
        *path = system_and_install_dirs(path);
    }
    env
}

/// Keep only the `PATH` entries under the Windows folder or Program Files,
/// whose DLLs the launch proof does not bind. Toolchain, cargo and tool-cache
/// folders (a CI image puts dozens on `PATH`) would exceed the binding caps of
/// every launch, so the tests would depend on the host's `PATH`.
fn system_and_install_dirs(path: &str) -> String {
    let roots: Vec<String> = [
        "SystemRoot",
        "ProgramFiles",
        "ProgramW6432",
        "ProgramFiles(x86)",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok())
    .map(|root| format!("{}\\", root.trim_end_matches('\\').to_ascii_lowercase()))
    .collect();
    path.split(';')
        .filter(|entry| {
            let lowered = format!("{}\\", entry.trim_end_matches('\\').to_ascii_lowercase());
            roots.iter().any(|root| lowered.starts_with(root.as_str()))
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn query(
    tree: &Tree,
    tool: &str,
    command: Option<&str>,
    input: Value,
    cwd: &str,
) -> NativeExactActionQueryV1 {
    let tool_input = input.as_object().map(|map| {
        map.iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    });
    NativeExactActionQueryV1::ExactAction {
        harness: "claude-code".to_owned(),
        tool_name: tool.to_owned(),
        command: command.map(str::to_owned),
        tool_input,
        raw_tool_input: None,
        payload_cwd: Some(cwd.to_owned()),
        workspace: Some(tree.ws()),
        home_dir: Some(tree.path("home")),
        environment: environment(),
        facts: NativeReviewFactsV1 {
            decision: Some("require-reapproval".to_owned()),
            minimum_action: Some("review".to_owned()),
            policy_action: Some("review".to_owned()),
            reason_code: Some("first_seen_tool".to_owned()),
            action_type: Some("file_read".to_owned()),
        },
        policy_binding: NativePolicyBindingV1::Bound {
            value: json!({"rule_digest": "d".repeat(64), "command_extensions": []}),
        },
        extension_control_digest: "e".repeat(64),
        budget_ms: 20_000,
    }
}

fn read(tree: &Tree, path: &str) -> Result<String, &'static str> {
    exact_action_token(&query(
        tree,
        "Read",
        None,
        json!({"file_path": path}),
        &tree.ws(),
    ))
}

fn search(tree: &Tree, tool: &str, input: Value) -> Result<String, &'static str> {
    exact_action_token(&query(tree, tool, None, input, &tree.ws()))
}

fn shell(tree: &Tree, command: &str) -> Result<String, &'static str> {
    exact_action_token(&query(tree, "Bash", Some(command), json!(null), &tree.ws()))
}

#[test]
fn ordinary_windows_file_tools_mint_a_token() {
    let tree = Tree::new();
    let main = tree.path("ws\\src\\main.rs");
    let token = read(&tree, &main).expect("a workspace read mints a token");
    assert_eq!(read(&tree, &main), Ok(token.clone()), "the token is stable");
    // Every spelling Windows opens as the same file binds the same token.
    let lowered = format!("{}{}", &main[..1].to_lowercase(), &main[1..]);
    assert_eq!(read(&tree, &lowered.replace('\\', "/")), Ok(token.clone()));
    assert_eq!(read(&tree, "src\\main.rs"), Ok(token.clone()));
    assert_eq!(read(&tree, "src/./main.rs"), Ok(token.clone()));
    assert_eq!(read(&tree, &main.to_uppercase()), Ok(token.clone()));
    assert_eq!(read(&tree, &format!(r"\\?\{main}")), Ok(token.clone()));
    // A different file never shares it.
    let lib = read(&tree, &tree.path("ws\\src\\lib.rs")).unwrap();
    assert_ne!(lib, token);
    // A file that does not exist yet is bound as its own target.
    assert!(read(&tree, "src\\new.rs").is_ok());
    assert!(search(
        &tree,
        "Glob",
        json!({"pattern": "**\\*.rs", "path": tree.ws()})
    )
    .is_ok());
    assert!(search(&tree, "Grep", json!({"pattern": "fn main", "path": "src"})).is_ok());
    assert!(search(&tree, "LS", json!({"path": tree.path("ws\\src")})).is_ok());
    assert!(search(&tree, "TodoWrite", json!({"todos": []})).is_ok());
    // The payload cwd may be spelled with `/` and a lowercase drive.
    let cwd = tree.ws().replace('\\', "/").to_lowercase();
    let spelled = exact_action_token(&query(
        &tree,
        "Read",
        None,
        json!({"file_path": main}),
        &cwd,
    ));
    assert_eq!(spelled, Ok(token));
}

#[test]
fn a_short_name_spelling_binds_the_long_file() {
    let tree = Tree::new();
    let src = tree.path("ws\\src");
    let short = cmd(&src, "for %A in (long-file-name-here.txt) do @echo %~snxA");
    if short.is_empty() || short.eq_ignore_ascii_case("long-file-name-here.txt") {
        eprintln!("8.3 names are disabled on this volume; nothing to compare");
        return;
    }
    let long = read(&tree, "src\\long-file-name-here.txt").unwrap();
    assert_eq!(read(&tree, &format!("src\\{short}")), Ok(long));
}

#[test]
fn windows_spellings_guard_cannot_pin_stay_one_time() {
    let tree = Tree::new();
    let main = tree.path("ws\\src\\main.rs");
    let drive = &main[..2];
    let rest = &main[2..];
    for path in [
        format!("{main}:hidden"),
        format!("{main}::$DATA"),
        format!("{main}."),
        format!("{main} "),
        tree.path("ws\\src\\NUL"),
        tree.path("ws\\src\\con.txt"),
        tree.path("ws\\src\\COM1"),
        tree.path("ws\\src\\*.rs"),
        format!("{drive}{}", rest.trim_start_matches('\\')),
        rest.to_owned(),
        format!(r"\\?\{}\src\..\src\main.rs", tree.ws()),
        r"\\.\pipe\guard".to_owned(),
        format!(
            r"\\localhost\{}$\{}",
            &drive[..1],
            rest.trim_start_matches('\\')
        ),
        tree.path("ws\\src\\MISSIN~1.RS"),
    ] {
        assert_eq!(read(&tree, &path), Err("unproven_launch"), "{path}");
    }
}

#[test]
fn windows_paths_outside_the_workspace_are_broad() {
    let tree = Tree::new();
    let ws = tree.ws();
    let outside = tree.path("outside");
    assert_eq!(
        read(&tree, &tree.path("outside\\notes.txt")),
        Err("broad_scope")
    );
    assert_eq!(read(&tree, "..\\outside\\notes.txt"), Err("broad_scope"));
    assert_eq!(
        read(&tree, "src\\..\\..\\outside\\notes.txt"),
        Err("broad_scope")
    );
    // A junction inside the workspace is followed to where Windows opens it.
    cmd(&ws, &format!("mklink /J escape \"{outside}\""));
    assert!(Path::new(&format!("{ws}\\escape\\notes.txt")).is_file());
    assert_eq!(read(&tree, "escape\\notes.txt"), Err("broad_scope"));
    for pattern in ["..\\*", "src\\..\\..\\*", "C:\\*", "\\*", "C:*"] {
        let input = json!({"pattern": pattern, "path": ws});
        assert_eq!(
            search(&tree, "Glob", input),
            Err("broad_scope"),
            "{pattern}"
        );
    }
}

#[path = "windows_git_tests.rs"]
mod git;
#[path = "windows_launch_tests.rs"]
mod launch;
