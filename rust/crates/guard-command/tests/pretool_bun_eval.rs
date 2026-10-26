#![cfg(unix)]
//! `bun -e` constant prints proceed only when no Bun preload can run first.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a project and a `bin` directory with a stand-in `bun`. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-bun-eval")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/sub")).unwrap();
    std::fs::create_dir_all(home.join("project/.git")).unwrap();
    std::fs::create_dir_all(home.join("bin")).unwrap();
    let bun = home.join("bin/bun");
    std::fs::write(&bun, "#!/bin/sh\n").unwrap();
    set_executable(&bun);
    std::fs::canonicalize(home).unwrap()
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn environment(
    home: &Path,
    path: &Path,
    names: &[&str],
) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_str().unwrap().to_owned(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

fn classify(
    home: &Path,
    cwd: &str,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let cwd = home.join(cwd);
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        environment,
    )
}

const PRINTS: &[&str] = &[
    "bun -e \"console.log('bun-ok')\"",
    "bun -e \"console.log('bun-eval-ok', 1+1)\"",
    "bun -e \"console.log('bun-ok', Bun.version)\"",
    "bun -e 'console.log(process.platform, process.arch)' 2>&1",
];

#[test]
fn constant_prints_proceed_without_a_preload() {
    let home = home();
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH", "BUN_INSTALL"]);
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in PRINTS {
            let result = classify(&home, "project", Some(&plain), harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
    for command in [
        "bun -e \"console.log(require('fs').readFileSync('.env', 'utf8'))\"",
        "bun -e \"console.log(Bun.env)\"",
        "bun -e \"console.log('ok'); process.exit(1)\"",
        "bun -e \"console.log(Bun.file('.env'))\"",
        "bun -e \"console.log('a,b', Bun.spawnSync(['id']))\"",
        "bun --preload ./x.js -e \"console.log('ok')\"",
        "bun -e \"console.log('ok')\" | sh",
        "BUN_OPTIONS=--preload=./x.js bun -e \"console.log('ok')\"",
        "./bun -e \"console.log('ok')\"",
        "sudo bun -e \"console.log('ok')\"",
    ] {
        let result = classify(&home, "project", Some(&plain), "zcode", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn any_preload_source_keeps_the_review() {
    let home = home();
    let command = PRINTS[0];
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    assert_eq!(
        classify(&home, "project", Some(&plain), "zcode", command).decision,
        "allow"
    );
    // No stamped environment, an inherited BUN_OPTIONS, or a `bun` the
    // project supplies.
    assert_ne!(
        classify(&home, "project", None, "zcode", command).decision,
        "allow"
    );
    let options = environment(&home, &home.join("bin"), &["HOME", "PATH", "BUN_OPTIONS"]);
    assert_ne!(
        classify(&home, "project", Some(&options), "zcode", command).decision,
        "allow"
    );
    std::fs::create_dir_all(home.join("project/bin")).unwrap();
    std::fs::write(home.join("project/bin/bun"), "#!/bin/sh\n").unwrap();
    let local = environment(&home, &home.join("project/bin"), &["HOME", "PATH"]);
    assert_ne!(
        classify(&home, "project", Some(&local), "zcode", command).decision,
        "allow"
    );
    // Configuration beside the working directory, above it, or global.
    for config in [
        "project/sub/bunfig.toml",
        "project/bunfig.toml",
        ".bunfig.toml",
        ".config/.bunfig.toml",
    ] {
        let file = home.join(config);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&file, "preload = [\"./x.js\"]\n").unwrap();
        let result = classify(&home, "project/sub", Some(&plain), "zcode", command);
        assert_ne!(result.decision, "allow", "{config}");
        std::fs::remove_file(file).unwrap();
    }
    assert_eq!(
        classify(&home, "project/sub", Some(&plain), "zcode", command).decision,
        "allow"
    );
    // A relative or empty PATH entry can hide a repository `bun`.
    let relative = format!(".:{}", home.join("bin").display());
    let relative = environment(&home, Path::new(&relative), &["HOME", "PATH"]);
    assert_ne!(
        classify(&home, "project", Some(&relative), "zcode", command).decision,
        "allow"
    );
    // The shell skips a non-executable file and can then run a project `bun`.
    let decoy = home.join("decoy");
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::write(decoy.join("bun"), "#!/bin/sh\n").unwrap();
    let project_bun = home.join("project/bun");
    std::fs::write(&project_bun, "#!/bin/sh\n").unwrap();
    set_executable(&project_bun);
    let skipped = format!("{}:{}", decoy.display(), home.join("project").display());
    let skipped = environment(&home, Path::new(&skipped), &["HOME", "PATH"]);
    assert_ne!(
        classify(&home, "project", Some(&skipped), "zcode", command).decision,
        "allow"
    );
    // `bun` above the cwd and inside the repository is still the project's.
    std::fs::create_dir_all(home.join("project/.git")).unwrap();
    let repo_bin = home.join("project/node_modules/.bin");
    std::fs::create_dir_all(&repo_bin).unwrap();
    let repo_bun = repo_bin.join("bun");
    std::fs::write(&repo_bun, "#!/bin/sh\n").unwrap();
    set_executable(&repo_bun);
    let repo = environment(&home, &repo_bin, &["HOME", "PATH"]);
    assert_ne!(
        classify(&home, "project/sub", Some(&repo), "zcode", command).decision,
        "allow"
    );
    for name in ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"] {
        let injected = environment(&home, &home.join("bin"), &["HOME", "PATH", name]);
        assert_ne!(
            classify(&home, "project", Some(&injected), "zcode", command).decision,
            "allow",
            "{name}"
        );
    }
    let stamped = home.join("stamped-home");
    std::fs::create_dir_all(stamped.join(".config")).unwrap();
    std::fs::write(
        stamped.join(".config/.bunfig.toml"),
        "preload = [\"./x.js\"]\n",
    )
    .unwrap();
    let mut stamped_environment = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    stamped_environment.home = Some(stamped.to_str().unwrap().to_owned());
    assert_ne!(
        classify(
            &home,
            "project",
            Some(&stamped_environment),
            "zcode",
            command
        )
        .decision,
        "allow"
    );
}

#[test]
fn node_prints_accept_the_same_constants() {
    let home = home();
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    for command in [
        "node -e \"console.log('node-ok', 1+1)\"",
        "node -e 'console.log(process.version)'",
    ] {
        let result = classify(&home, "project", Some(&plain), "codex", command);
        assert_eq!(result.decision, "allow", "{command}");
    }
    let preloaded = environment(&home, &home.join("bin"), &["HOME", "PATH", "NODE_OPTIONS"]);
    assert_ne!(
        classify(
            &home,
            "project",
            Some(&preloaded),
            "codex",
            "node -e 'console.log(process.version)'"
        )
        .decision,
        "allow"
    );
    for command in [
        "node -e \"console.log(Bun.version)\"",
        "python3 -c \"print('py-ok', 2)\"",
        "python3 -c \"print('aws batch delete-job --job-id example')\"",
        "python3 -c \"print('ok', open('.env').read())\"",
        "python3 -c \"print(process.version)\"",
    ] {
        let result = classify(&home, "project", Some(&plain), "codex", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn a_repository_that_contains_the_session_home_is_not_proven() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-bun-eval")
        .join(format!(
            "contained-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let repo = root.join("workspace");
    let bin = repo.join("node_modules/.bin");
    std::fs::create_dir_all(repo.join("sub")).unwrap();
    std::fs::create_dir_all(repo.join(".home")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let bun = bin.join("bun");
    std::fs::write(&bun, "#!/bin/sh\n").unwrap();
    set_executable(&bun);
    let command = PRINTS[0];
    let repo_home = std::fs::canonicalize(&repo).unwrap();
    let nested_home = std::fs::canonicalize(repo.join(".home")).unwrap();
    for (home, cwd) in [(&repo_home, "sub"), (&nested_home, "../sub")] {
        let plain = environment(home, &bin, &["HOME", "PATH"]);
        assert_ne!(
            classify(home, cwd, Some(&plain), "zcode", command).decision,
            "allow",
            "{}",
            home.display()
        );
    }
}

const BUN_EVAL: &str = "native_bun_eval_readonly_containment_required";

/// File reads leave the command contained rather than allowed.
const CONTAINED: &[&str] = &[
    "bun -e \"const fs = require('fs'); console.log(JSON.parse(fs.readFileSync('package.json', 'utf8')).name)\"",
    "bun --eval \"console.log(require('fs').readdirSync('.'))\"",
    "bun -p \"require('fs').existsSync('bun.lock')\"",
    "bun --print \"require('fs').statSync('package.json').size\"",
];

/// Programs that reach for writes, requests, processes, the environment or
/// code generation fail the screen and keep the ordinary review.
const SCREENED: &[&str] = &[
    "bun -e \"await Bun.write('out.txt', 'x')\"",
    "bun -e \"await fetch('https://example.com')\"",
    "bun -e \"Bun.spawn(['sh', '-c', 'id'])\"",
    "bun -e \"console.log(Bun.version.constructor('return 1')())\"",
    "bun -e \"require('fs').writeFileSync('x', 'y')\"",
    "bun -e \"console.log(process.env.HOME)\"",
    "bun -e \"const { writeFileSync: w } = require('fs'); w('x', 'y')\"",
    "bun -e \"const { rmSync: r } = require('fs'); r('x')\"",
];

#[test]
fn bun_inline_eval_shares_the_node_eval_boundary() {
    let home = home();
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in CONTAINED {
            let result = classify(&home, "project", Some(&plain), harness, command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(result.minimum_action, "sandbox-required", "{command}");
                assert_eq!(result.reason_code, BUN_EVAL, "{command}");
            }
        }
        for command in SCREENED {
            let result = classify(&home, "project", Some(&plain), harness, command);
            assert_ne!(result.reason_code, BUN_EVAL, "{harness}: {command}");
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(result.minimum_action, "sandbox-required", "{command}");
        }
    }
    let read = CONTAINED[0];
    for command in [
        format!("BUN_OPTIONS=--preload=./x.js {read}"),
        format!("{read} > out.txt"),
        format!("{read} && rm -rf build"),
        format!("sudo {read}"),
        read.replacen("bun -e", "bun --smol -e", 1),
        read.replacen("bun -e", "bun run -e", 1),
        read.replacen("bun -e", "bunx -e", 1),
        format!("{read} extra"),
    ] {
        let result = classify(&home, "project", Some(&plain), "zcode", &command);
        assert_ne!(result.reason_code, BUN_EVAL, "{command}");
        assert_ne!(result.decision, "allow", "{command}");
    }
}

/// With the packaged extension program Bun reports the Node package
/// permission. Only an exact `bun -e/-p` keeps the evaluation boundary.
#[test]
fn bun_package_permission_is_accepted_only_for_exact_inline_eval() {
    use guard_command::native_command_controls::CompiledNativeCommandControls;
    use guard_command::native_command_program::packaged_command_program;
    let program = packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest, "health": "protected",
            "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let home = home();
    let cwd = home.join("project");
    let evaluate = |command: &str| {
        evaluate_pre_tool_envelope_with_execution_context(
            "zcode",
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: cwd.to_str(),
                ..PathContext::default()
            },
            None,
        )
    };
    let read = CONTAINED[0];
    let result = evaluate(read);
    assert_ne!(result.decision, "allow");
    if cfg!(target_os = "macos") {
        assert_eq!(result.reason_code, BUN_EVAL);
        assert_eq!(result.minimum_action, "sandbox-required");
    }
    // The clock bounds how long the eval may run, not what it may touch, so
    // the wrapped form reaches the same contained profile. A `timeout` named
    // by path is a different file and keeps the command under review.
    let wrapped = format!("timeout 30 {read}");
    let result = evaluate(&wrapped);
    assert_ne!(result.decision, "allow", "{wrapped}");
    if cfg!(target_os = "macos") {
        assert_eq!(result.reason_code, BUN_EVAL, "{wrapped}");
        assert_eq!(result.minimum_action, "sandbox-required", "{wrapped}");
    }
    let by_path = format!("./timeout 30 {read}");
    let result = evaluate(&by_path);
    assert_ne!(result.reason_code, BUN_EVAL, "{by_path}");
    assert_ne!(result.decision, "allow", "{by_path}");
}
