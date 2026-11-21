use super::*;

/// An executable macOS ships inside one of its own frameworks, found the way
/// a shebang names one. `/System/Library/Frameworks/Ruby.framework/Versions/
/// 2.6/usr/bin/ruby` is the one `/usr/bin/rake` runs on.
fn framework_program() -> Option<PathBuf> {
    for directory in mac_framework_program_directories() {
        let Ok(programs) = fs::read_dir(&directory) else {
            continue;
        };
        for program in programs.filter_map(Result::ok) {
            let path = program.path();
            if path.is_file()
                && fs::metadata(&path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
            {
                return Some(path);
            }
        }
    }
    None
}

/// `/usr/bin/rake` is a short script whose shebang names the Ruby macOS ships
/// inside a framework. That interpreter sits on the signed system volume, so
/// the sandbox can run it, but it is not under any of the four `bin`
/// directories the roots used to name and the run was reviewed instead of
/// contained. The frameworks' own `usr/bin` directories join them - and only
/// those, because the trees beside them carry privileged helpers nothing
/// denies back out.
#[test]
fn a_script_run_by_a_framework_interpreter_stays_reachable() {
    let root = scratch();
    let workspace = root.join("workspace");
    let roots = executable_roots(&workspace, Vec::new());
    assert!(
        !roots
            .iter()
            .any(|entry| entry == Path::new(MAC_FRAMEWORK_ROOT)),
        "the frameworks tree is an executable root whole"
    );
    for entry in &roots {
        if entry.starts_with(MAC_FRAMEWORK_ROOT) {
            assert!(
                entry.ends_with("usr/bin"),
                "{} is not an interpreter directory",
                entry.display()
            );
        }
    }
    // Every macOS install ships at least one framework interpreter; without
    // one the assertions above would hold over an empty list and the roots
    // this test exists for would have gone missing unnoticed.
    let interpreter = framework_program().expect("macOS ships a framework interpreter");
    assert!(
        roots
            .iter()
            .any(|entry| interpreter.starts_with(entry) && entry.starts_with(MAC_FRAMEWORK_ROOT)),
        "{} is not under an executable root",
        interpreter.display()
    );
    tool(
        &workspace.join("build.rb"),
        &format!("#!{}\n", interpreter.display()),
    );
    assert!(
        !outside(&root, "./build.rb", "/usr/bin:/bin"),
        "{} is unreachable",
        interpreter.display()
    );
    let _ = fs::remove_dir_all(root);
}
