//! The signed Desktop proxy form of Grok's hook: every signature and the
//! require flag, and the redirects that cannot authorize another context.

use super::*;

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
    let guard_dir = rig.guard();
    let home_dir = rig.home();
    let own = owner(&guard_dir, &home_dir, None);
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
    let guard_dir = rig.guard();
    let home_dir = rig.home();
    let own = owner(&guard_dir, &home_dir, Some(&own_workspace));
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
