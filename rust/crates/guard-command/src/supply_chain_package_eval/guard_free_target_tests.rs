use super::*;

/// A virtual environment at `root` with an interpreter, `pyvenv.cfg` and an
/// unrelated installed package. Returns the interpreter path.
fn venv(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("python"), b"\x7fELF").unwrap();
    std::fs::write(root.join("pyvenv.cfg"), b"home = /usr/bin\n").unwrap();
    std::fs::create_dir_all(root.join("lib/python3.12/site-packages/rich-14.2.0.dist-info"))
        .unwrap();
    bin.join("python")
}

fn guard_free(command: &str, base: Option<&Path>) -> bool {
    installs_into_guard_free_environment(command, base, None)
}

#[test]
fn uv_pip_install_into_a_fresh_venv_is_guard_free() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("candidate/.venv");
    let python = venv(&root);
    let command = format!(
        "uv pip install --no-cache --python {} --no-deps /wheels/abc/hol_guard-3.61.0-py3-none-any.whl",
        python.display()
    );
    assert!(guard_free(&command, None));
    let inline = format!(
        "uv pip install --python={} ./hol_guard.whl",
        python.display()
    );
    assert!(guard_free(&inline, None));
    let venv_dir = format!("uv pip install -p {} ./hol_guard.whl", root.display());
    assert!(guard_free(&venv_dir, None));
    let sync = format!(
        "uv pip sync -q --python {} requirements.txt",
        python.display()
    );
    assert!(guard_free(&sync, None));
    // A relative interpreter resolves against the working directory, and
    // proves nothing without one.
    let relative = "uv pip install --python candidate/.venv/bin/python ./hol_guard.whl";
    assert!(guard_free(relative, Some(dir.path())));
    assert!(!guard_free(relative, None));
}

#[test]
fn a_target_directory_that_does_not_exist_yet_is_guard_free() {
    let dir = tempfile::tempdir().unwrap();
    let command = format!(
        "uv pip install --target {} ./hol_guard.whl",
        dir.path().join("fresh").display()
    );
    assert!(guard_free(&command, None));
}

#[test]
fn an_environment_that_already_holds_guard_keeps_its_review() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tool-venv");
    let python = venv(&root);
    std::fs::create_dir_all(root.join("lib/python3.12/site-packages/hol_guard-3.60.0.dist-info"))
        .unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        python.display()
    );
    assert!(!guard_free(&command, None));

    let scripts = dir.path().join("script-venv");
    let python = venv(&scripts);
    std::fs::write(scripts.join("bin/hol-guard"), b"").unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        python.display()
    );
    assert!(!guard_free(&command, None));

    let editable = dir.path().join("editable-venv");
    venv(&editable);
    std::fs::write(
        editable.join("lib/python3.12/site-packages/__editable___plugin_scanner_1_0_finder.py"),
        b"",
    )
    .unwrap();
    let command = format!("uv pip install -p {} ./hol_guard.whl", editable.display());
    assert!(!guard_free(&command, None));

    let target = dir.path().join("target");
    std::fs::create_dir_all(target.join("hol_guard-3.60.0.dist-info")).unwrap();
    let command = format!(
        "uv pip install --python {} --target {} ./hol_guard.whl",
        dir.path().join("candidate/.venv").display(),
        target.display()
    );
    venv(&dir.path().join("candidate/.venv"));
    assert!(!guard_free(&command, None));
}

#[test]
fn the_environment_running_guard_keeps_its_review() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("guard-venv");
    let python = venv(&root);
    let runtime = root.join("lib/python3.12/site-packages/runtime/hol-guard-runtime");
    std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
    std::fs::write(&runtime, b"").unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        python.display()
    );
    assert!(installs_into_guard_free_environment(&command, None, None));
    assert!(!installs_into_guard_free_environment(
        &command,
        None,
        Some(&runtime)
    ));
}

#[cfg(unix)]
#[test]
fn a_linked_environment_or_interpreter_keeps_its_review() {
    let dir = tempfile::tempdir().unwrap();
    let guard = dir.path().join("guard-venv");
    let guard_python = venv(&guard);
    std::fs::write(guard.join("bin/hol-guard"), b"").unwrap();

    // A directory link resolves to the Guard environment.
    let link = dir.path().join("innocent");
    std::os::unix::fs::symlink(&guard, &link).unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        link.join("bin/python").display()
    );
    assert!(!guard_free(&command, None));

    // An interpreter linked from a directory that is not a virtual
    // environment runs with the Guard environment's prefix.
    let bare = dir.path().join("bare/bin");
    std::fs::create_dir_all(&bare).unwrap();
    std::os::unix::fs::symlink(&guard_python, bare.join("python")).unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        bare.join("python").display()
    );
    assert!(!guard_free(&command, None));

    // A script standing in for the interpreter can start any Python.
    let wrapper = dir.path().join("wrapper");
    let wrapper_python = venv(&wrapper);
    std::fs::write(
        &wrapper_python,
        format!("#!/bin/sh\nexec {} \"$@\"\n", guard_python.display()),
    )
    .unwrap();
    let command = format!(
        "uv pip install --python {} ./hol_guard.whl",
        wrapper_python.display()
    );
    assert!(!guard_free(&command, None));
    // Naming the directory starts the same script.
    let command = format!("uv pip install -p {} ./hol_guard.whl", wrapper.display());
    assert!(!guard_free(&command, None));

    // A directory with `pyvenv.cfg` but no interpreter proves nothing.
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::write(empty.join("pyvenv.cfg"), b"home = /usr/bin\n").unwrap();
    let command = format!("uv pip install -p {} ./hol_guard.whl", empty.display());
    assert!(!guard_free(&command, None));
}

#[test]
fn shapes_that_do_not_name_the_environment_exactly_keep_their_review() {
    let dir = tempfile::tempdir().unwrap();
    let python = venv(&dir.path().join(".venv"));
    let python = python.display();
    let guard = dir.path().join("guard");
    for command in [
        // The environment comes from the shell, `PATH` or a version request.
        "uv pip install ./hol_guard.whl".to_string(),
        "uv pip install --python 3.12 ./hol_guard.whl".to_string(),
        "uv pip install --python python3 ./hol_guard.whl".to_string(),
        "uv tool install ./hol_guard.whl".to_string(),
        "pipx install ./hol_guard.whl".to_string(),
        // pip and python -m pip are not accepted at all.
        format!(
            "{}/.venv/bin/pip install ./hol_guard.whl",
            dir.path().display()
        ),
        format!("{python} -m pip install ./hol_guard.whl"),
        "pip install ./hol_guard.whl".to_string(),
        // Options that move the install or that this check does not know.
        format!("uv pip install --system --python {python} ./hol_guard.whl"),
        format!("uv pip install --break-system-packages --python {python} ./hol_guard.whl"),
        format!("uv pip install --python {python} --directory /other ./hol_guard.whl"),
        format!("uv pip install --python {python} --project /other ./hol_guard.whl"),
        format!("uv pip install --python {python} --config-file uv.toml ./hol_guard.whl"),
        format!(
            "uv pip install --python {python} -t{} ./hol_guard.whl",
            guard.display()
        ),
        format!("uv pip install -p{python} ./hol_guard.whl"),
        format!("uv pip install -p={python} ./hol_guard.whl"),
        format!(
            "uv pip install --python {python} --targ {} ./hol_guard.whl",
            guard.display()
        ),
        format!("uv pip install --python {python} -- ./hol_guard.whl"),
        // Values the shell could still expand.
        "uv pip install --python $GUARD_ENV/bin/python ./hol_guard.whl".to_string(),
        "uv pip install --python ${VIRTUAL_ENV}/bin/python ./hol_guard.whl".to_string(),
        format!("uv pip install --python {python} --target ~other/site ./hol_guard.whl"),
        format!("uv pip install --python {python} --target /opt/*/site ./hol_guard.whl"),
        format!("uv pip install --python {python} --target %APPDATA%\\site ./hol_guard.whl"),
        // Chained, redirected or incomplete commands.
        format!("uv pip install --python {python} ./a.whl && pip install ./hol_guard.whl"),
        format!("uv pip install --python {python} ./a.whl; uv tool install ./hol_guard.whl"),
        format!("uv pip install --python {python} --python"),
    ] {
        assert!(!guard_free(&command, Some(dir.path())), "{command}");
    }
}
