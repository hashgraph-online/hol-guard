//! Which command lines count as Guard's Grok hook: the generated native,
//! frozen and signed Desktop forms bound to their owner, and the orphaned
//! clients a repair retires.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tempfile::TempDir;

use super::super::{durable_runtime, Ctx};
use super::{Checker, Owner};
use crate::harness_shell_command::platform_command_line;
use crate::native_install_verdict::{Invocation, Ran, Runner};

const RUNTIME: &str = "/rt/hol-guard-runtime";
const PACKAGE: &str = "/opt/guard/site";
const PYTHON: &str = "/py/bin/python";
const FROZEN_CLI: &str = "/g/bin/hol-guard-core";
const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// Answers `codesign` with the team each path is signed by; a path with no
/// entry does not verify.
#[derive(Default)]
struct Signed(BTreeMap<PathBuf, &'static str>);

impl Runner for Signed {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        let path = Path::new(invocation.arguments.last().expect("a path"));
        let team = self.0.get(path);
        let stderr = team.map(|team| format!("TeamIdentifier={team}\n"));
        Ok(Ran {
            success: team.is_some(),
            stdout: Vec::new(),
            stderr: stderr.unwrap_or_default().into_bytes(),
        })
    }
}

struct Rig {
    _dir: TempDir,
    root: PathBuf,
}

impl Rig {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        Self { _dir: dir, root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn guard(&self) -> PathBuf {
        self.root.join("guard")
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    /// A caller whose process home is `home`, with the stamped runtime that
    /// advertises the bounded hook bridge.
    fn source(&self) -> Ctx {
        self.caller(false, json!({"path": RUNTIME, "size": 3, "sha256": SHA, "features": ["bounded-hook-bridge-v1"]}))
    }

    /// A frozen caller whose native runtime is a real three-byte file, so the
    /// durable copy under the Guard home can be published.
    fn frozen(&self) -> (Ctx, String) {
        let bundled = self.root.join("bundle").join("hol-guard-runtime");
        fs::create_dir_all(bundled.parent().unwrap()).unwrap();
        fs::write(&bundled, b"abc").unwrap();
        let identity = durable_runtime::Identity {
            path: &bundled,
            size: 3,
            sha256: SHA,
        };
        let copy = durable_runtime::hook_runtime(&identity, &self.guard()).unwrap();
        let runtime = json!({"path": bundled, "size": 3, "sha256": SHA, "features": ["bounded-hook-bridge-v1"]});
        (
            self.caller(true, runtime),
            copy.to_string_lossy().into_owned(),
        )
    }

    fn caller(&self, frozen: bool, runtime: Value) -> Ctx {
        Ctx::parse(Some(&json!({
            "home": self.home(),
            "workspace": null,
            "guard_home": self.guard(),
            "home_override_explicit": false,
            "cwd": self.root,
            "user_home": self.home(),
            "env": {},
            "caller": {
                "executable": PYTHON,
                "executable_resolved": PYTHON,
                "frozen": frozen,
                "launcher": PYTHON,
                "frozen_launcher": frozen.then_some(FROZEN_CLI),
                "cli_executable": if frozen { FROZEN_CLI } else { PYTHON },
                "package_root": PACKAGE,
                "version": "0.0.0",
                "native_runtime": runtime,
            },
        })))
        .unwrap()
    }
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The bridge config Guard serializes for a Grok hook; `home` and `workspace`
/// are the optional pinned options.
fn config(
    guard_home: &Path,
    home: Option<&Path>,
    workspace: Option<&Path>,
    executable: &str,
    frozen: bool,
) -> Value {
    let mut args = vec![
        "guard".to_owned(),
        "hook".to_owned(),
        "--harness".to_owned(),
        "grok".to_owned(),
        "--guard-home".to_owned(),
        text(guard_home),
    ];
    for (name, value) in [("--home", home), ("--workspace", workspace)] {
        if let Some(value) = value {
            args.extend([name.to_owned(), text(value)]);
        }
    }
    args.push("--json".to_owned());
    json!({
        "harness": "grok",
        "guard_home": guard_home,
        "package_root": PACKAGE,
        "python_executable": executable,
        "frozen_launcher": frozen,
        "timeout_seconds": 85,
        "cli_args": args,
    })
}

fn line(parts: &[&str]) -> String {
    platform_command_line(
        &parts
            .iter()
            .map(|part| (*part).to_owned())
            .collect::<Vec<_>>(),
    )
}

fn bridge(runtime: &str, config: &Value) -> String {
    line(&[runtime, "bounded-hook-bridge", &config.to_string()])
}

fn recognizes(ctx: &Ctx, command: &str, owner: Option<&Owner<'_>>) -> bool {
    Checker::new(ctx, false, &mut Signed::default()).recognizes(command, owner)
}

fn is_missing(ctx: &Ctx, command: &str, replacement: &str) -> bool {
    Checker::new(ctx, false, &mut Signed::default()).is_missing(command, replacement)
}

fn owner<'a>(guard: &'a Path, home: &'a Path, workspace: Option<&'a Path>) -> Owner<'a> {
    Owner {
        guard_home: guard,
        home,
        workspace,
    }
}

#[test]
fn a_generated_hook_is_recognized() {
    let rig = Rig::new();
    let ctx = rig.source();
    let command = bridge(
        RUNTIME,
        &config(&rig.guard(), Some(&rig.home()), None, PYTHON, false),
    );
    assert!(recognizes(&ctx, &command, None));
    assert!(recognizes(
        &ctx,
        &command,
        Some(&owner(&rig.guard(), &rig.home(), None))
    ));
}

#[test]
fn modified_or_marker_only_invocations_are_rejected() {
    let rig = Rig::new();
    let ctx = rig.source();
    let good = config(&rig.guard(), Some(&rig.home()), None, PYTHON, false);
    let edit = |change: &dyn Fn(&mut Value)| {
        let mut changed = good.clone();
        change(&mut changed);
        bridge(RUNTIME, &changed)
    };
    let rejected = [
        bridge("/rt/other-runtime", &good),
        line(&[RUNTIME, "claude-hook-bridge", &good.to_string()]),
        edit(&|config| config["python_executable"] = json!("/bin/echo")),
        edit(&|config| config["cli_args"][3] = json!("pi")),
        edit(&|config| config["guard_home"] = json!(text(&rig.root.join("another")))),
        edit(&|config| {
            config["cli_args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--help"))
        }),
        edit(&|config| config["package_root"] = json!("/elsewhere/site")),
        edit(&|config| config["timeout_seconds"] = json!(121)),
        edit(&|config| config["timeout_seconds"] = json!(true)),
        edit(&|config| config["frozen_launcher"] = json!(true)),
        line(&["sh", "-c", "echo hol-guard hook"]),
        "'unterminated".to_owned(),
        "hol-guard hook grok".to_owned(),
        format!("{} ; echo other", bridge(RUNTIME, &good)),
    ];
    for command in rejected {
        assert!(!recognizes(&ctx, &command, None), "{command}");
    }
}

#[test]
fn a_frozen_hook_names_the_durable_runtime_under_its_guard_home() {
    let rig = Rig::new();
    let (ctx, copy) = rig.frozen();
    let command = bridge(
        &copy,
        &config(&rig.guard(), Some(&rig.home()), None, FROZEN_CLI, true),
    );
    assert!(recognizes(
        &ctx,
        &command,
        Some(&owner(&rig.guard(), &rig.home(), None))
    ));
    // A frozen caller with no Guard home to name keeps its own launcher.
    assert!(!recognizes(&ctx, &command, None));
    let bundled = bridge(
        &text(&rig.root.join("bundle/hol-guard-runtime")),
        &config(&rig.guard(), Some(&rig.home()), None, FROZEN_CLI, true),
    );
    assert!(!recognizes(
        &ctx,
        &bundled,
        Some(&owner(&rig.guard(), &rig.home(), None))
    ));
}

#[test]
fn a_hook_is_bound_to_its_owner() {
    let rig = Rig::new();
    let ctx = rig.source();
    let command = bridge(
        RUNTIME,
        &config(
            &rig.guard(),
            Some(&rig.home()),
            Some(&rig.workspace()),
            PYTHON,
            false,
        ),
    );
    let own = owner(&rig.guard(), &rig.home(), Some(&rig.workspace()));
    assert!(recognizes(&ctx, &command, Some(&own)));
    let other = rig.root.join("other");
    let other_guard = rig.root.join("other-guard");
    assert!(!recognizes(
        &ctx,
        &command,
        Some(&owner(&other_guard, &other, None))
    ));
}

#[test]
fn paired_path_redirects_cannot_authorize_another_context() {
    let rig = Rig::new();
    let redirected = rig.root.join("redirected");
    let own_workspace = rig.workspace();
    let own = owner(&rig.guard(), &rig.home(), Some(&own_workspace));
    for frozen in [false, true] {
        let (ctx, runtime, executable) = if frozen {
            let (ctx, copy) = rig.frozen();
            (ctx, copy, FROZEN_CLI)
        } else {
            (rig.source(), RUNTIME.to_owned(), PYTHON)
        };
        for option in ["--guard-home", "--home", "--workspace"] {
            let mut hook = config(
                &rig.guard(),
                Some(&rig.home()),
                Some(&own_workspace),
                executable,
                frozen,
            );
            assert!(recognizes(&ctx, &bridge(&runtime, &hook), Some(&own)));
            let args = hook["cli_args"].as_array_mut().unwrap();
            let index = args.iter().position(|arg| arg == option).unwrap() + 1;
            args[index] = json!(text(&redirected));
            if option == "--guard-home" {
                hook["guard_home"] = json!(text(&redirected));
            }
            let command = bridge(&runtime, &hook);
            assert!(
                recognizes(&ctx, &command, None) == !frozen,
                "{option} frozen={frozen}"
            );
            assert!(
                !recognizes(&ctx, &command, Some(&own)),
                "{option} frozen={frozen}"
            );
        }
    }
}

#[test]
fn a_workspace_pinned_hook_is_not_machine_wide_and_the_reverse() {
    let rig = Rig::new();
    let ctx = rig.source();
    for pinned in [false, true] {
        let workspace = rig.workspace();
        let hook = config(
            &rig.guard(),
            Some(&rig.home()),
            pinned.then_some(&workspace),
            PYTHON,
            false,
        );
        let command = bridge(RUNTIME, &hook);
        let same = owner(&rig.guard(), &rig.home(), pinned.then_some(&workspace));
        let flipped = owner(&rig.guard(), &rig.home(), (!pinned).then_some(&workspace));
        assert!(recognizes(&ctx, &command, Some(&same)));
        assert!(!recognizes(&ctx, &command, Some(&flipped)));
    }
}

#[test]
fn an_implicit_home_must_match_the_current_user() {
    let rig = Rig::new();
    let ctx = rig.source();
    let command = bridge(RUNTIME, &config(&rig.guard(), None, None, PYTHON, false));
    assert!(recognizes(
        &ctx,
        &command,
        Some(&owner(&rig.guard(), &rig.home(), None))
    ));
    let other = rig.root.join("other-home");
    assert!(!recognizes(
        &ctx,
        &command,
        Some(&owner(&rig.guard(), &other, None))
    ));
}

struct Desktop {
    bundle: PathBuf,
    proxy: PathBuf,
    core: PathBuf,
}

impl Desktop {
    fn new(rig: &Rig) -> Self {
        let bundle = rig.home().join("Guard.app");
        let macos = bundle.join("Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        let (proxy, core) = (macos.join("proxy"), macos.join("core"));
        for path in [&proxy, &core] {
            fs::write(path, "binary").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            bundle,
            proxy,
            core,
        }
    }

    fn signed(&self, team: Option<&'static str>) -> Signed {
        let mut signed = Signed::default();
        for path in [&self.bundle, &self.proxy, &self.core] {
            if let Some(team) = team {
                signed.0.insert(path.clone(), team);
            }
        }
        signed
    }

    fn argv(&self, hook: &Value) -> Vec<String> {
        let launch = crate::desktop_hook_proxy::dispatch(&json!({"op": "script"})).unwrap();
        let (script, name) = (
            launch["script"].as_str().unwrap(),
            launch["name"].as_str().unwrap(),
        );
        [
            "/bin/sh",
            "-c",
            script,
            name,
            &text(&self.proxy),
            "TEAM123",
            &text(&self.bundle),
            &hook.to_string(),
            &text(&self.core),
            "1",
        ]
        .iter()
        .map(|part| (*part).to_owned())
        .collect()
    }
}

fn desktop_recognizes(
    ctx: &Ctx,
    argv: &[String],
    runner: &mut Signed,
    owner: Option<&Owner<'_>>,
) -> bool {
    Checker::new(ctx, true, runner).recognizes(&platform_command_line(argv), owner)
}

#[test]
fn the_desktop_proxy_needs_every_signature_and_its_require_flag() {
    let rig = Rig::new();
    let ctx = rig.source();
    let desktop = Desktop::new(&rig);
    let hook = config(
        &rig.guard(),
        Some(&rig.home()),
        None,
        &text(&desktop.core),
        true,
    );
    let argv = desktop.argv(&hook);
    let own = owner(&rig.guard(), &rig.home(), None);
    assert!(desktop_recognizes(
        &ctx,
        &argv,
        &mut desktop.signed(Some("TEAM123")),
        None
    ));
    assert!(desktop_recognizes(
        &ctx,
        &argv,
        &mut desktop.signed(Some("TEAM123")),
        Some(&own)
    ));
    // The launch script reads the require flag as $6, so a launch without it never runs.
    assert!(!desktop_recognizes(
        &ctx,
        &argv[..9],
        &mut desktop.signed(Some("TEAM123")),
        None
    ));
    assert!(!desktop_recognizes(
        &ctx,
        &argv,
        &mut desktop.signed(None),
        None
    ));
    let mut altered = argv.clone();
    altered[2] = "echo hol-guard hook".to_owned();
    assert!(!desktop_recognizes(
        &ctx,
        &altered,
        &mut desktop.signed(Some("TEAM123")),
        None
    ));
    // A host that is not macOS cannot verify a signature.
    let line = platform_command_line(&argv);
    assert!(
        !Checker::new(&ctx, false, &mut desktop.signed(Some("TEAM123"))).recognizes(&line, None)
    );
}

#[test]
fn a_desktop_proxy_redirect_cannot_authorize_another_context() {
    let rig = Rig::new();
    let ctx = rig.source();
    let desktop = Desktop::new(&rig);
    let redirected = rig.root.join("redirected");
    let own_workspace = rig.workspace();
    let own = owner(&rig.guard(), &rig.home(), Some(&own_workspace));
    for option in ["--guard-home", "--home", "--workspace"] {
        let mut hook = config(
            &rig.guard(),
            Some(&rig.home()),
            Some(&own_workspace),
            &text(&desktop.core),
            true,
        );
        assert!(desktop_recognizes(
            &ctx,
            &desktop.argv(&hook),
            &mut desktop.signed(Some("TEAM123")),
            Some(&own)
        ));
        let args = hook["cli_args"].as_array_mut().unwrap();
        let index = args.iter().position(|arg| arg == option).unwrap() + 1;
        args[index] = json!(text(&redirected));
        if option == "--guard-home" {
            hook["guard_home"] = json!(text(&redirected));
        }
        let argv = desktop.argv(&hook);
        assert!(
            desktop_recognizes(&ctx, &argv, &mut desktop.signed(Some("TEAM123")), None),
            "{option}"
        );
        assert!(
            !desktop_recognizes(
                &ctx,
                &argv,
                &mut desktop.signed(Some("TEAM123")),
                Some(&own)
            ),
            "{option}"
        );
    }
}

/// The interpreter-wrapped client older installs wrote.
fn old_client(guard_home: &Path, workspace: Option<&Path>) -> String {
    let hook = config(guard_home, None, workspace, PYTHON, false);
    let script = guard_home.join("managed/bounded-hooks/grok.py");
    line(&[PYTHON, "-I", &text(&script), &hook.to_string()])
}

fn native_replacement(guard_home: &Path, frozen: bool) -> String {
    let executable = if frozen { FROZEN_CLI } else { PYTHON };
    bridge(RUNTIME, &config(guard_home, None, None, executable, frozen))
}

#[test]
fn a_missing_client_is_orphaned_but_never_operational_evidence() {
    let rig = Rig::new();
    let ctx = rig.source();
    let stale = old_client(&rig.root.join("deleted"), None);
    assert!(is_missing(
        &ctx,
        &stale,
        &native_replacement(&rig.root.join("current"), false)
    ));
    assert!(!recognizes(&ctx, &stale, None));
}

#[test]
fn a_workspace_fallback_difference_does_not_keep_the_missing_global_client() {
    let rig = Rig::new();
    let ctx = rig.source();
    let replacement = bridge(
        RUNTIME,
        &config(
            &rig.root.join("new"),
            None,
            Some(&rig.workspace()),
            PYTHON,
            false,
        ),
    );
    assert!(is_missing(
        &ctx,
        &old_client(&rig.root.join("old"), None),
        &replacement
    ));
}

#[test]
fn a_frozen_replacement_retires_an_orphaned_client() {
    let rig = Rig::new();
    let ctx = rig.source();
    for frozen in [false, true] {
        let stale = old_client(&rig.root.join("old"), None);
        assert!(is_missing(
            &ctx,
            &stale,
            &native_replacement(&rig.root.join("new"), frozen)
        ));
    }
}

#[test]
fn a_client_that_is_not_an_orphan_is_kept() {
    let rig = Rig::new();
    let ctx = rig.source();
    let old = rig.root.join("old");
    let replacement = native_replacement(&rig.root.join("new"), false);
    assert!(is_missing(&ctx, &old_client(&old, None), &replacement));
    let kept = |stale: &str| !is_missing(&ctx, stale, &replacement);
    // The client still exists.
    let script = old.join("managed/bounded-hooks/grok.py");
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::write(&script, "# existing client\n").unwrap();
    assert!(kept(&old_client(&old, None)));
    fs::remove_file(&script).unwrap();
    let stale = old_client(&old, None);
    // Other shell syntax, another script, another harness or another home.
    assert!(kept(&format!("{stale} ; echo other")));
    assert!(kept(
        &stale.replace("bounded-hooks/grok.py", "bounded-hooks/user.py")
    ));
    assert!(kept(
        &stale.replace("\"harness\":\"grok\"", "\"harness\":\"other\"")
    ));
    let homed = stale.replace(
        "\"--harness\"",
        &format!("\"--home\",\"{}\",\"--harness\"", rig.root.display()),
    );
    assert!(kept(&homed));
    // Not a Python interpreter, and not the native bridge either.
    assert!(kept(&stale.replace(PYTHON, "/bin/echo")));
    assert!(kept("echo custom-check"));
    assert!(!is_missing(&ctx, &replacement, &replacement));
}
