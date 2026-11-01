use super::*;

fn request(op: &str, pid: Option<i64>) -> Request {
    Request {
        schema: SCHEMA.to_owned(),
        op: op.to_owned(),
        pid,
    }
}

fn host(ps: Option<PathBuf>, proc_root: Option<PathBuf>) -> Host {
    Host {
        ps,
        proc_root,
        timeout: Duration::from_secs(5),
        output_limit: OUTPUT_LIMIT_BYTES,
    }
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "posix-processes.v0", "op": "inventory" }),
        json!({ "schema": SCHEMA, "op": "inventory", "pid": 1 }),
        json!({ "schema": SCHEMA, "op": "elapsed", "pid": 1 }),
        json!({ "schema": SCHEMA, "op": "parent" }),
        json!({ "schema": SCHEMA, "op": "parent", "pid": 0 }),
        json!({ "schema": SCHEMA, "op": "command", "pid": -4 }),
        json!({ "schema": SCHEMA, "op": "unknown" }),
        json!({ "schema": SCHEMA, "op": "inventory", "extra": 1 }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "posix_processes_request_invalid",
            "{request}"
        );
    }
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("fits") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "posix_processes_request_too_large"
    );
}

#[test]
fn without_ps_or_procfs_nothing_is_proven() {
    let host = host(None, None);
    assert_eq!(
        answer(&request("inventory", None), &host),
        Ok(json!({ "listing": null, "entries": null }))
    );
    assert_eq!(
        answer(&request("elapsed", None), &host),
        Ok(json!({ "listing": null }))
    );
    assert_eq!(
        answer(&request("parent", Some(7)), &host),
        Ok(json!({ "parent_pid": null }))
    );
    assert_eq!(
        answer(&request("command", Some(7)), &host),
        Ok(json!({ "command": null }))
    );
}

fn write_cmdline(root: &Path, name: &str, bytes: &[u8]) {
    let directory = root.join(name);
    fs::create_dir_all(&directory).expect("process directory");
    fs::write(directory.join("cmdline"), bytes).expect("cmdline");
}

#[test]
fn procfs_inventory_reads_each_command_line_without_ps() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    write_cmdline(
        root,
        "4242",
        b"python\0-m\0codex_plugin_scanner.cli\0guard\0daemon\0--serve\0--port\x004781\0",
    );
    write_cmdline(root, "17", b"  \xffbroken\0arg  \0\0");
    write_cmdline(root, "18", b"");
    write_cmdline(root, "0", b"swapper");
    write_cmdline(root, "self", b"not a pid");
    fs::create_dir_all(root.join("19")).expect("exited process");
    let answer = answer(
        &request("inventory", None),
        &host(None, Some(root.to_path_buf())),
    )
    .expect("answer");
    assert_eq!(answer["listing"], Value::Null);
    let mut entries: Vec<(i64, String)> =
        serde_json::from_value(answer["entries"].clone()).expect("entries");
    entries.sort();
    assert_eq!(
        entries,
        [
            (17, "\u{fffd}broken arg".to_owned()),
            (
                4242,
                "python -m codex_plugin_scanner.cli guard daemon --serve --port 4781".to_owned()
            ),
        ]
    );
}

#[test]
fn procfs_inventory_fails_closed_past_its_budget() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_cmdline(directory.path(), "4242", &[b'x'; 17]);
    assert_eq!(proc_entries(directory.path(), 16), None);
    assert_eq!(
        proc_entries(directory.path(), 17),
        Some(vec![(4242, "x".repeat(17))])
    );
    write_cmdline(directory.path(), "4243", b"y");
    assert_eq!(
        proc_entries(directory.path(), 17),
        None,
        "the budget is shared across every process"
    );
    assert_eq!(proc_entries(&directory.path().join("missing"), 16), None);
}

#[cfg(unix)]
mod with_ps {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    /// A stand-in `ps` that runs `body` as a shell script.
    fn fake_ps(directory: &Path, body: &str) -> PathBuf {
        let path = directory.join("ps");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("mode");
        path
    }

    fn answer_with(body: &str, op: &str, pid: Option<i64>) -> Value {
        let directory = tempfile::tempdir().expect("tempdir");
        let ps = fake_ps(directory.path(), body);
        answer(&request(op, pid), &host(Some(ps), None)).expect("answer")
    }

    #[test]
    fn ps_runs_with_a_clean_c_locale_and_the_query_arguments() {
        let listing = answer_with(
            r#"printf '%s|%s|%s|%s\n' "$*" "$LANG" "$LC_ALL" "${HOME:-unset}""#,
            "inventory",
            None,
        );
        assert_eq!(
            listing,
            json!({ "listing": "-axo pid=,command=|C|C|unset\n", "entries": null })
        );
        let elapsed = answer_with(r#"printf '%s' "$*""#, "elapsed", None);
        assert_eq!(elapsed, json!({ "listing": "-axo pid=,etime=,command=" }));
    }

    #[test]
    fn ps_is_preferred_over_procfs() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_cmdline(directory.path(), "4242", b"daemon");
        let ps = fake_ps(directory.path(), "echo listed");
        let answer = answer(
            &request("inventory", None),
            &host(Some(ps), Some(directory.path().to_path_buf())),
        );
        assert_eq!(
            answer,
            Ok(json!({ "listing": "listed\n", "entries": null }))
        );
    }

    #[test]
    fn parent_and_command_read_one_process() {
        assert_eq!(
            answer_with(
                r#"[ "$*" = "-p 42 -o ppid=" ] && echo '  7 '"#,
                "parent",
                Some(42)
            ),
            json!({ "parent_pid": 7 })
        );
        for output in ["0", "-3", "seven", ""] {
            assert_eq!(
                answer_with(&format!("echo '{output}'"), "parent", Some(42)),
                json!({ "parent_pid": null }),
                "{output:?}"
            );
        }
        assert_eq!(
            answer_with(
                r#"[ "$*" = "-p 42 -o command=" ] && echo '  hol-guard daemon --serve  '"#,
                "command",
                Some(42)
            ),
            json!({ "command": "hol-guard daemon --serve" })
        );
        assert_eq!(
            answer_with("echo '   '", "command", Some(42)),
            json!({ "command": null })
        );
    }

    #[test]
    fn failed_oversized_slow_or_undecodable_queries_answer_null() {
        assert_eq!(
            answer_with("echo partial; exit 1", "elapsed", None),
            json!({ "listing": null })
        );
        assert_eq!(
            answer_with(r"printf '\377\n'", "elapsed", None),
            json!({ "listing": null })
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let oversized = Host {
            output_limit: 8,
            ..host(Some(fake_ps(directory.path(), "echo 123456789")), None)
        };
        assert_eq!(
            answer(&request("elapsed", None), &oversized),
            Ok(json!({ "listing": null }))
        );
        let exact = Host {
            output_limit: 10,
            ..host(Some(fake_ps(directory.path(), "echo 123456789")), None)
        };
        assert_eq!(
            answer(&request("elapsed", None), &exact),
            Ok(json!({ "listing": "123456789\n" }))
        );
        let slow = Host {
            timeout: Duration::from_millis(200),
            ..host(Some(fake_ps(directory.path(), "exec /bin/sleep 5")), None)
        };
        let started = std::time::Instant::now();
        assert_eq!(
            answer(&request("elapsed", None), &slow),
            Ok(json!({ "listing": null }))
        );
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn only_a_resolved_executable_ps_is_trusted() {
        if let Some(path) = trusted_ps_path() {
            assert!(path.is_absolute());
            assert!(fs::metadata(&path).expect("metadata").is_file());
        }
    }
}
