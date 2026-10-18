use super::super::authority::runtime_roots;
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("guard-venv-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

/// A system interpreter inside the trusted roots. CI must provide one so these
/// tests never pass vacuously; elsewhere a missing interpreter is reported.
fn trusted_python() -> Option<PathBuf> {
    let base = Path::new("/usr/bin/python3")
        .canonicalize()
        .ok()
        .filter(|base| path_is_within_any(base, &TRUSTED_EXECUTABLE_ROOTS) && python_named(base));
    if base.is_none() {
        assert!(
            env::var_os("CI").is_none(),
            "venv admission tests need a trusted /usr/bin/python3 on CI"
        );
        eprintln!("skipping venv admission test: no trusted /usr/bin/python3");
    }
    base
}

/// A trusted `bin` a venv can name as its home, with the prefix holding it.
/// The grant names the launcher directory and the standard library beside it,
/// so the directory has to be one an install really starts Python from: a
/// trusted path that happens to hold no interpreter is not a runtime, and a
/// host where none of these does is skipped.
fn trusted_prefix() -> Option<(PathBuf, PathBuf)> {
    ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"]
        .iter()
        .filter_map(|bin| Path::new(bin).canonicalize().ok())
        .filter(|bin| path_is_within_any(bin, &TRUSTED_EXECUTABLE_ROOTS) && interpreter_home(bin))
        .find_map(|bin| {
            let prefix = bin.parent()?.to_path_buf();
            (!managed_prefix(&prefix)).then_some((prefix, bin))
        })
}

/// An install of one runtime's own below a trusted root, such as a
/// tool-cache or Homebrew formula directory, with the `bin` it installs.
fn managed_prefix_install() -> Option<(PathBuf, PathBuf)> {
    let parents = [
        "/opt/hostedtoolcache/Python",
        "/opt/homebrew/opt",
        "/usr/local/opt",
    ];
    parents
        .iter()
        .filter_map(|parent| fs::read_dir(parent).ok())
        .flat_map(|entries| entries.flatten().take(64).collect::<Vec<_>>())
        .filter_map(|entry| {
            let prefix = entry.path().canonicalize().ok()?;
            let bin = prefix.join("bin").canonicalize().ok()?;
            let library = prefix.join("lib").is_dir();
            let interpreter = interpreter_home(&bin);
            (library
                && interpreter
                && bin.parent() == Some(prefix.as_path())
                && managed_prefix(&prefix))
            .then_some((prefix, bin))
        })
        .next()
}

fn executable(path: &Path) {
    fs::write(path, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// `<root>/workspace` plus `<root>/venv` whose `bin/python3 -> python -> base`.
fn layout(root: &Path, base: &Path, home: &str) -> (PathBuf, PathBuf) {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("pyproject.toml"), "").unwrap();
    let venv = root.join("venv");
    fs::create_dir_all(venv.join("bin")).unwrap();
    fs::create_dir_all(venv.join("lib/python3/site-packages")).unwrap();
    fs::write(venv.join(".gitignore"), "*\n").unwrap();
    fs::write(
        venv.join("pyvenv.cfg"),
        format!("home = {home}\ninclude-system-site-packages = false\n"),
    )
    .unwrap();
    symlink(base, venv.join("bin/python")).unwrap();
    symlink("python", venv.join("bin/python3")).unwrap();
    (workspace, venv)
}

fn admit(
    command: &str,
    workspace: &Path,
    venv: &Path,
) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    let command = vec![command.to_owned(), "-m".to_owned(), "pytest".to_owned()];
    let search = venv.join("bin").to_string_lossy().into_owned();
    let (launch, executable) = resolve_pytest_executable(&command, workspace, workspace, &search)?;
    allowed_executables(
        &executable,
        &launch,
        &command,
        workspace,
        workspace,
        &search,
    )
}

#[test]
fn external_venv_of_a_trusted_interpreter_is_admitted_with_a_venv_only_grant() {
    let Some(base) = trusted_python() else { return };
    let fixture = fixture();
    let home = base.parent().unwrap().to_string_lossy().into_owned();
    let (workspace, venv) = layout(&fixture.0, &base, &home);
    let allowed = admit("python3", &workspace, &venv).unwrap();
    assert!(allowed.contains(&venv.join("bin/python3")), "{allowed:?}");
    assert!(allowed.contains(&base), "{allowed:?}");
    let roots = runtime_roots(&allowed, &workspace, None);
    assert!(roots.contains(&venv), "{roots:?}");
    assert!(
        roots.iter().all(|root| !path_is_within(&fixture.0, root)),
        "{roots:?}"
    );
    // A launcher that links straight to the base still grants its venv.
    let direct = admit("python", &workspace, &venv).unwrap();
    assert!(runtime_roots(&direct, &workspace, None).contains(&venv));
}

#[test]
fn venv_layouts_that_could_widen_reads_or_exec_are_rejected() {
    let Some(base) = trusted_python() else { return };
    let home = base.parent().unwrap().to_string_lossy().into_owned();
    type Mutate = fn(&Path, &Path, &Path);
    let cases: &[(&str, Mutate)] = &[
        ("real interpreter copy", |_, venv, _| {
            fs::remove_file(venv.join("bin/python")).unwrap();
            executable(&venv.join("bin/python"));
        }),
        ("untrusted pyvenv home", |root, venv, _| {
            fs::create_dir_all(root.join("base/bin")).unwrap();
            let cfg = format!("home = {}\n", root.join("base/bin").display());
            fs::write(venv.join("pyvenv.cfg"), cfg).unwrap();
        }),
        ("duplicate pyvenv home", |root, venv, _| {
            let cfg = format!("home = /usr/bin\nhome = {}\n", root.display());
            fs::write(venv.join("pyvenv.cfg"), cfg).unwrap();
        }),
        ("relative pyvenv home", |_, venv, _| {
            fs::write(venv.join("pyvenv.cfg"), "home = usr/bin\n").unwrap();
        }),
        ("missing pyvenv.cfg", |_, venv, _| {
            fs::remove_file(venv.join("pyvenv.cfg")).unwrap();
        }),
        ("linked pyvenv.cfg", |root, venv, _| {
            fs::rename(venv.join("pyvenv.cfg"), root.join("cfg")).unwrap();
            symlink(root.join("cfg"), venv.join("pyvenv.cfg")).unwrap();
        }),
        ("link into the workspace", |_, venv, workspace| {
            executable(&workspace.join("python3"));
            fs::remove_file(venv.join("bin/python")).unwrap();
            symlink(workspace.join("python3"), venv.join("bin/python")).unwrap();
        }),
        ("non-python link hop", |_, venv, _| {
            fs::remove_file(venv.join("bin/python3")).unwrap();
            fs::rename(venv.join("bin/python"), venv.join("bin/tool")).unwrap();
            symlink("tool", venv.join("bin/python3")).unwrap();
        }),
        ("unexpected venv entry", |_, venv, _| {
            fs::write(venv.join(".env"), "TOKEN=x\n").unwrap();
        }),
        ("linked venv entry", |root, venv, _| {
            fs::create_dir(root.join("elsewhere")).unwrap();
            symlink(root.join("elsewhere"), venv.join("share")).unwrap();
        }),
    ];
    for (name, mutate) in cases {
        let fixture = fixture();
        let (workspace, venv) = layout(&fixture.0, &base, &home);
        mutate(&fixture.0, &venv, &workspace);
        assert!(admit("python3", &workspace, &venv).is_err(), "{name}");
    }
}

#[test]
fn protected_or_workspace_holding_venvs_and_venv_pytest_scripts_are_rejected() {
    let Some(base) = trusted_python() else { return };
    let fixture = fixture();
    let home = base.parent().unwrap().to_string_lossy().into_owned();
    let (_, venv) = layout(&fixture.0, &base, &home);
    let hidden = fixture.0.join(".ssh");
    fs::create_dir(&hidden).unwrap();
    fs::rename(&venv, hidden.join("venv")).unwrap();
    let hidden = hidden.join("venv");
    assert!(launcher_root(&hidden.join("bin/python3")).is_none());
    fs::rename(hidden, &venv).unwrap();
    assert!(launcher_root(&venv.join("bin/python3")).is_some());
    let inner = venv.join("share/project");
    fs::create_dir_all(&inner).unwrap();
    assert!(external_root(&venv.join("bin/python3"), &base, &inner).is_none());
    assert!(admit("python3", &inner, &venv).is_err());
    let workspace = fixture.0.join("workspace");
    let script = venv.join("bin/pytest");
    fs::write(
        &script,
        format!("#!{}\n", venv.join("bin/python3").display()),
    )
    .unwrap();
    fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
    let search = venv.join("bin").to_string_lossy().into_owned();
    let command = vec!["pytest".to_owned()];
    assert!(resolve_pytest_executable(&command, &workspace, &workspace, &search).is_err());
}

#[test]
fn venv_admission_keeps_interpreter_environment_filtering() {
    let Some(base) = trusted_python() else { return };
    let fixture = fixture();
    let home = base.parent().unwrap().to_string_lossy().into_owned();
    let (workspace, venv) = layout(&fixture.0, &base, &home);
    let allowed = admit("python3", &workspace, &venv).unwrap();
    let private = fixture.0.join("private");
    let mut source = BTreeMap::from([
        ("PYTHONHOME".to_owned(), venv.display().to_string()),
        (
            "PYTHONSTARTUP".to_owned(),
            venv.join("x.py").display().to_string(),
        ),
        ("VIRTUAL_ENV".to_owned(), venv.display().to_string()),
    ]);
    let filter = |source: &BTreeMap<String, String>| {
        environment::filter(
            source, &workspace, &workspace, &private, &private, &allowed, false,
        )
    };
    let env = filter(&source).unwrap();
    for key in ["PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV"] {
        assert!(!env.contains_key(key), "{key}");
    }
    let site = venv.join("lib/python3/site-packages").display().to_string();
    source.insert("PYTHONPATH".to_owned(), site);
    assert_eq!(
        filter(&source).unwrap_err().reason_code,
        PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE
    );
}

#[test]
fn a_workspace_venv_grants_the_install_its_launchers_run() {
    let Some(base) = trusted_python() else { return };
    let Some((prefix, bin)) = trusted_prefix() else {
        eprintln!("skipping workspace venv test: no trusted prefix");
        return;
    };
    let fixture = fixture();
    let (workspace, outside) = layout(&fixture.0, &base, &bin.to_string_lossy());
    let venv = workspace.join(".venv");
    fs::rename(&outside, &venv).unwrap();
    let venv_bin = venv.join("bin");
    let home = |home: &Path| {
        fs::write(
            venv.join("pyvenv.cfg"),
            format!("home = {}\n", home.display()),
        )
        .unwrap();
    };
    // A trusted root names every program and configuration file installed
    // below it, so a `pyvenv.cfg` naming its `bin` grants the interpreter's
    // own directory and the standard library beside it, never the root.
    let granted = workspace_base_roots(&venv_bin, &workspace);
    assert_eq!(granted.first(), Some(&bin), "{granted:?}");
    assert!(!granted.contains(&prefix), "{granted:?}");
    assert!(
        granted.iter().skip(1).all(|library| {
            library.parent() == Some(prefix.join("lib").as_path())
                && library.to_string_lossy().contains("python")
        }),
        "{granted:?}"
    );
    // A managed install is one runtime's own, so it is granted whole.
    if let Some((managed, managed_bin)) = managed_prefix_install() {
        home(&managed_bin);
        assert_eq!(
            workspace_base_roots(&venv_bin, &workspace),
            vec![managed],
            "{managed_bin:?}"
        );
        home(&bin);
    }
    // Only a venv's `bin`, and only a venv the workspace holds.
    assert!(workspace_base_roots(&venv, &workspace).is_empty());
    assert!(workspace_base_roots(&venv_bin, &fixture.0.join("elsewhere")).is_empty());
    // A directory below a trusted root that no install starts Python from is
    // not a runtime, however the workspace's own `pyvenv.cfg` names it.
    for sibling in ["lib", "etc", "share"] {
        let candidate = prefix.join(sibling);
        if candidate.is_dir() {
            home(&candidate);
            assert!(
                workspace_base_roots(&venv_bin, &workspace).is_empty(),
                "{candidate:?}"
            );
        }
    }
    home(&bin);
    // A home that is not an approved runtime grants nothing.
    let plain = fixture.0.join("base/bin");
    fs::create_dir_all(&plain).unwrap();
    home(&plain);
    assert!(workspace_base_roots(&venv_bin, &workspace).is_empty());
    // A system interpreter grants `/usr/bin` and its standard library, not
    // `/usr`, which holds the whole system's libraries and configuration.
    home(Path::new("/usr/bin"));
    let system = workspace_base_roots(&venv_bin, &workspace);
    assert_eq!(
        system.first().map(PathBuf::as_path),
        Some(Path::new("/usr/bin"))
    );
    assert!(!system.contains(&PathBuf::from("/usr")), "{system:?}");
    // Nor does a venv that is no longer shaped like one.
    home(&bin);
    fs::write(venv.join("notes.txt"), "").unwrap();
    assert!(workspace_base_roots(&venv_bin, &workspace).is_empty());
}

#[test]
fn a_version_selector_reaches_the_run_only_as_a_version_name() {
    let Some(base) = trusted_python() else { return };
    let fixture = fixture();
    let home = base.parent().unwrap().to_string_lossy().into_owned();
    let (workspace, venv) = layout(&fixture.0, &base, &home);
    let allowed = admit("python3", &workspace, &venv).unwrap();
    let private = fixture.0.join("private");
    let filter = |source: &BTreeMap<String, String>| {
        environment::filter(
            source, &workspace, &workspace, &private, &private, &allowed, false,
        )
        .unwrap()
    };
    let kept = BTreeMap::from([
        ("PYENV_VERSION".to_owned(), "3.12.1:3.11".to_owned()),
        ("ASDF_NODEJS_VERSION".to_owned(), "20.11.0".to_owned()),
        ("RBENV_VERSION".to_owned(), "system".to_owned()),
    ]);
    let env = filter(&kept);
    for (key, value) in &kept {
        assert_eq!(env.get(key), Some(value), "{key}");
    }
    // A value that names anything but a version, and a setting that moves the
    // manager's root instead of choosing inside it, are both dropped.
    let dropped = BTreeMap::from([
        ("PYENV_VERSION".to_owned(), "../../etc".to_owned()),
        ("NODENV_VERSION".to_owned(), "-rf".to_owned()),
        ("GOENV_VERSION".to_owned(), String::new()),
        ("PYENV_ROOT".to_owned(), home.clone()),
        ("ASDF_DATA_DIR".to_owned(), home),
    ]);
    let env = filter(&dropped);
    for key in dropped.keys() {
        assert!(!env.contains_key(key), "{key}");
    }
}
