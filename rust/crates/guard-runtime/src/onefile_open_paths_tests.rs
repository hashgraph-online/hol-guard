use super::*;

fn names(found: &[&str]) -> Option<BTreeSet<String>> {
    Some(found.iter().map(|name| (*name).to_owned()).collect())
}

fn prefixes(root: &Path) -> BTreeSet<Vec<u8>> {
    root_prefixes(root)
}

#[test]
fn lsof_names_are_taken_from_paths_below_the_temp_root() {
    let root = Path::new("/var/tmp/guard-scan-root");
    let output = b"p123\nn/var/tmp/guard-scan-root/_MEIabc123/lib/libpython.so\n\
n/var/tmp/guard-scan-root/_MEIzzz999\n\
n/var/tmp/guard-scan-root/other/_MEInot\n\
n/var/tmp/guard-scan-root-sibling/_MEIsibling\n\
n/elsewhere/_MEIelse\n\
f12\n";

    assert_eq!(
        names_from_lsof(output, &prefixes(root)),
        names(&["_MEIabc123", "_MEIzzz999"])
    );
}

#[test]
fn empty_lsof_output_proves_nothing() {
    assert_eq!(names_from_lsof(b"", &prefixes(Path::new("/tmp/x"))), None);
}

#[test]
fn a_failed_lsof_run_is_unknown() {
    let root = Path::new("/tmp/guard-scan-root");
    assert_eq!(
        scan(root, Platform::MacOs, Path::new("/missing-proc"), || None),
        None
    );
    assert_eq!(
        scan(root, Platform::MacOs, Path::new("/missing-proc"), || Some(
            Vec::new()
        )),
        None
    );
}

#[test]
fn other_platforms_never_scan() {
    let root = Path::new("/tmp/guard-scan-root");
    let output = b"n/tmp/guard-scan-root/_MEIabc\n".to_vec();
    assert_eq!(
        scan(root, Platform::Other, Path::new("/missing-proc"), || Some(
            output
        )),
        None
    );
}

#[test]
fn trailing_separators_are_trimmed_from_the_root() {
    assert_eq!(trimmed(b"/tmp/"), b"/tmp".to_vec());
    assert_eq!(trimmed(b"C:\\Temp\\"), b"C:\\Temp".to_vec());
    assert_eq!(trimmed(b"/"), Vec::<u8>::new());
}

#[test]
fn the_answer_is_null_when_unknown_or_too_large() {
    assert_eq!(answer(None), json!({ "in_use": null }));
    assert_eq!(
        answer(names(&["_MEIb", "_MEIa"])),
        json!({ "in_use": ["_MEIa", "_MEIb"] })
    );
    let many = (0..=MAX_IN_USE_NAMES)
        .map(|index| format!("_MEI{index}"))
        .collect();
    assert_eq!(answer(Some(many)), json!({ "in_use": null }));
}

#[test]
fn requests_need_the_schema_and_an_absolute_root() {
    let request = |schema: &str, temp_root: &str| Request {
        schema: schema.to_owned(),
        temp_root: temp_root.to_owned(),
    };
    let absolute = std::env::temp_dir();
    let absolute = absolute.to_string_lossy();
    assert!(temp_root(&request(SCHEMA, &absolute)).is_ok());
    assert!(temp_root(&request("onefile-open-paths.v0", &absolute)).is_err());
    assert!(temp_root(&request(SCHEMA, "relative/tmp")).is_err());
    assert!(run_command(
        &br#"{"schema":"onefile-open-paths.v1","temp_root":"/tmp","extra":1}"#[..]
    )
    .is_err());
}

#[cfg(unix)]
mod proc_scan {
    use std::os::unix::fs::symlink;

    use super::*;

    struct FakeProc {
        _directory: tempfile::TempDir,
        proc_root: PathBuf,
        temp_root: PathBuf,
    }

    fn fake_proc() -> FakeProc {
        let directory = tempfile::tempdir().expect("tempdir");
        let proc_root = directory.path().join("proc");
        let temp_root = directory.path().join("tmp");
        fs::create_dir_all(&proc_root).expect("proc root");
        fs::create_dir_all(&temp_root).expect("temp root");
        FakeProc {
            _directory: directory,
            proc_root,
            temp_root,
        }
    }

    fn process(fake: &FakeProc, pid: &str, maps: &str) -> PathBuf {
        let entry = fake.proc_root.join(pid);
        fs::create_dir_all(entry.join("fd")).expect("fd dir");
        fs::write(entry.join("maps"), maps).expect("maps");
        entry
    }

    #[test]
    fn maps_links_and_descriptors_are_read() {
        let fake = fake_proc();
        let root = fake.temp_root.display().to_string();
        let entry = process(
            &fake,
            "101",
            &format!(
                "7f00-7f01 r-xp 00000000 08:01 1 {root}/_MEImapped/libpython.so (deleted)\n\
                 7f02-7f03 r--p 00000000 00:00 0 [heap]\n"
            ),
        );
        symlink(fake.temp_root.join("_MEIcwd"), entry.join("cwd")).expect("cwd");
        symlink("/usr/bin/true", entry.join("exe")).expect("exe");
        symlink(fake.temp_root.join("_MEIfd/data.bin"), entry.join("fd/3")).expect("fd");
        fs::create_dir_all(fake.proc_root.join("self")).expect("non-pid entry");

        assert_eq!(
            scan(&fake.temp_root, Platform::Linux, &fake.proc_root, || None),
            names(&["_MEIcwd", "_MEIfd", "_MEImapped"])
        );
    }

    #[test]
    fn a_process_that_exits_mid_scan_is_skipped() {
        let fake = fake_proc();
        let root = fake.temp_root.display().to_string();
        process(
            &fake,
            "101",
            &format!("0-1 r-xp 0 0 1 {root}/_MEIkept/lib.so\n"),
        );
        // A process directory without maps reads as one that already exited.
        fs::create_dir_all(fake.proc_root.join("202")).expect("exited process");

        assert_eq!(
            scan(&fake.temp_root, Platform::Linux, &fake.proc_root, || None),
            names(&["_MEIkept"])
        );
    }

    #[test]
    fn an_unreadable_proc_entry_falls_back_to_lsof() {
        let fake = fake_proc();
        let entry = process(&fake, "101", "");
        // A descriptor table that is a file, not a directory, is an
        // unexpected error, so the proc scan gives up and lsof answers.
        fs::remove_dir(entry.join("fd")).expect("remove fd dir");
        fs::write(entry.join("fd"), "").expect("fd file");
        let root = fake.temp_root.display().to_string();
        let output = format!("n{root}/_MEIfromlsof/x\n").into_bytes();

        assert_eq!(
            scan(&fake.temp_root, Platform::Linux, &fake.proc_root, || Some(
                output
            )),
            names(&["_MEIfromlsof"])
        );
    }

    #[test]
    fn an_empty_proc_falls_back_to_lsof() {
        let fake = fake_proc();
        assert_eq!(
            scan(&fake.temp_root, Platform::Linux, &fake.proc_root, || None),
            None
        );
    }

    #[test]
    fn output_past_the_limit_stops_the_child_at_once() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do echo xxxxxxxxxxxxxxxx; done"]);
        let started = Instant::now();

        assert_eq!(bounded_stdout(command, 4096, Duration::from_secs(60)), None);
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn bounded_output_needs_a_clean_exit() {
        let run = |script: &str| {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            bounded_stdout(command, 4096, Duration::from_secs(30))
        };

        assert_eq!(run("echo n/tmp/x"), Some(b"n/tmp/x\n".to_vec()));
        assert_eq!(run("echo n/tmp/x; exit 1"), None);
    }

    #[test]
    fn the_resolved_root_is_matched_too() {
        let fake = fake_proc();
        let alias = fake.proc_root.parent().expect("parent").join("tmp-alias");
        symlink(&fake.temp_root, &alias).expect("alias");
        let resolved = fs::canonicalize(&fake.temp_root).expect("resolved");
        let output = format!("n{}/_MEIresolved/x\n", resolved.display()).into_bytes();

        assert_eq!(
            scan(
                &alias,
                Platform::MacOs,
                Path::new("/missing-proc"),
                || Some(output)
            ),
            names(&["_MEIresolved"])
        );
    }
}
