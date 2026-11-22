use super::*;

fn venv(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("python"), b"").unwrap();
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
    let python = venv(&dir.path().join("candidate/.venv"));
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
    let venv_dir = format!(
        "uv pip install -p {} ./hol_guard.whl",
        dir.path().join("candidate/.venv").display()
    );
    assert!(guard_free(&venv_dir, None));
}

#[test]
fn venv_pip_and_python_m_pip_are_guard_free() {
    let dir = tempfile::tempdir().unwrap();
    venv(&dir.path().join(".venv"));
    assert!(guard_free(
        ".venv/bin/pip install ./dist/hol_guard-3.61.0-py3-none-any.whl",
        Some(dir.path())
    ));
    assert!(guard_free(
        ".venv/bin/python -m pip install --no-deps ./hol_guard.whl",
        Some(dir.path())
    ));
    // A relative path with no known working directory proves nothing.
    assert!(!guard_free(".venv/bin/pip install ./hol_guard.whl", None));
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
    let python = venv(&editable);
    std::fs::write(
        editable.join("lib/python3.12/site-packages/__editable___plugin_scanner_1_0_finder.py"),
        b"",
    )
    .unwrap();
    let command = format!("{} -m pip install ./hol_guard.whl", python.display());
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

#[test]
fn a_symlink_into_a_guard_environment_keeps_its_review() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("guard-venv");
    venv(&root);
    std::fs::write(root.join("bin/hol-guard"), b"").unwrap();
    let link = dir.path().join("innocent");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&root, &link).unwrap();
    #[cfg(unix)]
    {
        let command = format!(
            "uv pip install --python {} ./hol_guard.whl",
            link.join("bin/python").display()
        );
        assert!(!guard_free(&command, None));
    }
}

#[test]
fn shapes_that_do_not_name_the_environment_keep_their_review() {
    let dir = tempfile::tempdir().unwrap();
    let python = venv(&dir.path().join(".venv"));
    let python = python.display();
    for command in [
        "uv pip install ./hol_guard.whl".to_string(),
        "uv pip install --python 3.12 ./hol_guard.whl".to_string(),
        "pip install ./hol_guard.whl".to_string(),
        "python -m pip install ./hol_guard.whl".to_string(),
        "uv tool install ./hol_guard.whl".to_string(),
        "pipx install ./hol_guard.whl".to_string(),
        format!("uv pip install --system --python {python} ./hol_guard.whl"),
        format!("{python} -m pip install --user ./hol_guard.whl"),
        format!("uv pip install --python {python} ./a.whl && pip install ./hol_guard.whl"),
        format!("uv pip install --python {python} ./a.whl; uv tool install ./hol_guard.whl"),
        format!("uv pip install --python {python} --python"),
    ] {
        assert!(!guard_free(&command, Some(dir.path())), "{command}");
    }
}
