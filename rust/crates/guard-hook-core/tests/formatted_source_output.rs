use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut attempt = 0;
        let root = loop {
            let root = std::env::temp_dir().join(format!(
                "guard-formatted-source-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
                Err(error) => panic!("failed to create test root: {error}"),
            }
        };
        Self(host_spelling(root.canonicalize().unwrap()))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `canonicalize` spells Windows paths in the verbatim `\\?\C:\` form, which
/// source review refuses as a glob. Hosts send the ordinary drive form, so the
/// fixture root uses that. A root on a share canonicalizes to `\\?\UNC\server\
/// share\...`, whose ordinary spelling is `\\server\share\...`; without that
/// arm the `?` survives and source classification refuses the request before
/// the behavior under test runs.
fn host_spelling(path: std::path::PathBuf) -> std::path::PathBuf {
    let Some(stripped) = path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) else {
        return path;
    };
    if let Some(share) = stripped.strip_prefix(r"UNC\") {
        return format!(r"\\{share}").into();
    }
    if stripped.as_bytes().get(1) == Some(&b':') {
        return stripped.into();
    }
    path
}

fn request(root: &std::path::Path, output: &str) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("formatted-read".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": "example.py"},
            "tool_response": output,
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": "example.py", "tool_input_path": "example.py",
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "output_chars": output.chars().count()}
        }),
        cwd: Some(root.to_string_lossy().into()),
        home_dir: root.to_string_lossy().into(),
        guard_home: root.join("guard").to_string_lossy().into(),
        source_ref_external_allowed: true,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

#[cfg(any(unix, windows))]
#[test]
fn formatted_reads_require_complete_scanned_output_and_clean_source() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    std::fs::write(&source, "print(1 + 1)\n").unwrap();
    let output = "[example.py#ABCD]\n1: print(1 + 1)";
    let base = request(root.path(), output);
    let allowed = review_post_tool(&base);
    assert_eq!(allowed.reason_code, "output_scan_allow");
    assert_eq!(allowed.model_output_action, "allow_original");

    let mut mismatch = base.clone();
    mismatch.payload["guard_source_ref"]["output_chars"] = json!(output.len() + 1);
    assert_ne!(
        review_post_tool(&mismatch).model_output_action,
        "allow_original"
    );

    let mut truncated = base.clone();
    truncated.payload["tool_response_summary"] = json!({"excerpt_truncated": true});
    assert_ne!(
        review_post_tool(&truncated).model_output_action,
        "allow_original"
    );

    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let unsafe_output = request(root.path(), &format!("1: {token}"));
    assert_eq!(
        review_post_tool(&unsafe_output).reason_code,
        "output_secret_match"
    );

    std::fs::write(&source, format!("token = '{token}'\n")).unwrap();
    assert_eq!(review_post_tool(&base).reason_code, "source_secret_match");
}

#[cfg(not(any(unix, windows)))]
#[test]
fn formatted_reads_fail_closed_without_descriptor_verified_source_reads() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    std::fs::write(&source, "print(1 + 1)\n").unwrap();
    let result = review_post_tool(&request(root.path(), "[example.py#ABCD]\n1: print(1 + 1)"));
    assert_eq!(result.reason_code, "no_output_to_review");
    assert_eq!(result.model_output_action, "block");
}

#[cfg(unix)]
#[test]
fn external_and_linked_plaintext_is_scanned_without_checkout_location_allowlists() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let outside = root.path().join("ordinary.txt");
    std::fs::write(&outside, "ordinary fixture\n").unwrap();
    let link = workspace.join("guide.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    for target in [
        outside.to_string_lossy().as_ref(),
        "guide.txt",
        "../ordinary.txt",
    ] {
        let mut input = request(&workspace, "ordinary fixture");
        input.payload["tool_input"]["path"] = json!(target);
        input.payload["guard_source_ref"]["path"] = json!(target);
        input.payload["guard_source_ref"]["tool_input_path"] = json!(target);
        let result = review_post_tool(&input);
        assert_eq!(
            result.model_output_action, "allow_original",
            "{target}: {result:?}"
        );
        input.source_ref_external_allowed = false;
        assert_ne!(
            review_post_tool(&input).model_output_action,
            "allow_original",
            "{target}"
        );
    }
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    std::fs::write(&outside, format!("{token}\n")).unwrap();
    let mut secret = request(&workspace, "ordinary fixture");
    for field in ["path", "tool_input_path"] {
        secret.payload["guard_source_ref"][field] = json!("guide.txt");
    }
    secret.payload["tool_input"]["path"] = json!("guide.txt");
    assert_eq!(review_post_tool(&secret).reason_code, "source_secret_match");
    let dotenv = root.path().join(".env");
    std::fs::write(&dotenv, "synthetic fixture only\n").unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&dotenv, &link).unwrap();
    assert_ne!(
        review_post_tool(&secret).model_output_action,
        "allow_original"
    );
}

#[cfg(unix)]
#[test]
fn resolved_directory_target_is_rechecked_before_inline_output_allow() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    let ordinary = root.path().join("ordinary");
    let credentials = root.path().join(".ssh");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&ordinary).unwrap();
    std::fs::create_dir_all(&credentials).unwrap();

    let mut ordinary_request = request(&workspace, "ordinary/\n");
    ordinary_request
        .payload
        .as_object_mut()
        .unwrap()
        .remove("guard_source_ref");
    ordinary_request.payload["tool_input"]["path"] = json!(ordinary.to_string_lossy());
    let ordinary_result = review_post_tool(&ordinary_request);
    assert_eq!(ordinary_result.model_output_action, "allow_original");

    let mut redirected_request = request(&workspace, "id_ed25519\n");
    redirected_request
        .payload
        .as_object_mut()
        .unwrap()
        .remove("guard_source_ref");
    redirected_request.payload["tool_input"]["path"] = json!(credentials.to_string_lossy());
    let redirected_result = review_post_tool(&redirected_request);
    assert_eq!(redirected_result.reason_code, "sensitive_path");
    assert_ne!(redirected_result.model_output_action, "allow_original");

    let mut selector_redirected_request = request(&workspace, "ordinary/\n");
    selector_redirected_request
        .payload
        .as_object_mut()
        .unwrap()
        .remove("guard_source_ref");
    selector_redirected_request.payload["tool_input"]["path"] =
        json!(format!("{}:1-5", ordinary.display()));
    selector_redirected_request.payload["resolved_directory_target"] =
        json!(credentials.to_string_lossy());
    let selector_redirected_result = review_post_tool(&selector_redirected_request);
    assert_eq!(selector_redirected_result.reason_code, "sensitive_path");
    assert_ne!(
        selector_redirected_result.model_output_action,
        "allow_original"
    );
}

#[cfg(unix)]
#[test]
fn agent_plan_reads_outside_the_workspace_keep_their_original_output() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let plan = root.path().join(".codex/plans/rollout-todo.md");
    std::fs::create_dir_all(plan.parent().unwrap()).unwrap();
    std::fs::write(&plan, "# TODO\n\n- [ ] Ship the reviewed fix\n").unwrap();
    // OMP's read tool drops the file's final newline.
    let output = "# TODO\n\n- [ ] Ship the reviewed fix";
    let mut input = request(&workspace, output);
    input.home_dir = root.path().to_string_lossy().into();
    let target = plan.to_string_lossy().into_owned();
    input.payload["tool_input"]["path"] = json!(target);
    input.payload["guard_source_ref"]["path"] = json!(target);
    input.payload["guard_source_ref"]["tool_input_path"] = json!(target);
    let result = review_post_tool(&input);
    assert_eq!(result.reason_code, "source_full_scan_allow", "{result:?}");
    assert_eq!(result.model_output_action, "allow_original");

    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    std::fs::write(&plan, format!("# TODO\n\n{token}\n")).unwrap();
    assert_eq!(review_post_tool(&input).reason_code, "source_secret_match");
}

#[cfg(any(unix, windows))]
#[test]
fn slices_that_show_no_secret_are_reviewed_on_their_own() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let begin = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    let end = ["-----END ", "PRIVATE KEY-----"].concat();
    let mut lines: Vec<String> = (1..=30).map(|number| format!("step({number})")).collect();
    lines[1] = format!("token = '{token}'");
    lines[19] = begin;
    lines[20] = "c2xpY2Ugb2YgYSBrZXk=".into();
    lines[21] = end;
    std::fs::write(&source, lines.join("\n") + "\n").unwrap();
    let slice = |rows: &[usize]| {
        let body: Vec<String> = rows
            .iter()
            .map(|number| format!("{number}:{}", lines[number - 1]))
            .collect();
        format!("[example.py#ABCD]\n{}", body.join("\n"))
    };

    let clean = review_post_tool(&request(root.path(), &slice(&[10, 11, 12])));
    assert_eq!(clean.reason_code, "output_scan_allow", "{clean:?}");
    assert_eq!(clean.model_output_action, "allow_original");
    let collapsed = format!("{}\n13-18:  … }}", slice(&[10, 11, 12]));
    let clean = review_post_tool(&request(root.path(), &collapsed));
    assert_eq!(clean.reason_code, "output_scan_allow", "{clean:?}");
    // A range anchored by its enclosing block's first and last lines leaves
    // the omitted lines between them, the secret included, unshown.
    let anchored_rows = |runs: &[&[usize]]| {
        let rows: Vec<String> = runs
            .iter()
            .map(|run| {
                run.iter()
                    .map(|number| format!("{number}:{}", lines[number - 1]))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect();
        format!(
            "[example.py#ABCD]\n{}\n\n[Showing lines 10-12 of 30]",
            rows.join("\n…\n")
        )
    };
    let clean = review_post_tool(&request(
        root.path(),
        &anchored_rows(&[&[1], &[10, 11, 12], &[30]]),
    ));
    assert_eq!(clean.reason_code, "output_scan_allow", "{clean:?}");

    for blocked in [
        // The secret itself, the lines just below it, and a key body.
        slice(&[2]),
        slice(&[5, 6]),
        slice(&[21]),
        format!("{}\n19-24:  …", slice(&[12])),
        // An anchor row is a shown line like any other.
        anchored_rows(&[&[2], &[10, 11, 12], &[30]]),
        anchored_rows(&[&[1], &[10, 11, 12], &[21]]),
        // Rows that are not the file's lines keep the whole-file decision.
        "[example.py#ABCD]\n10:step(9)".into(),
        "[example.py#ABCD]\nstep(10)".into(),
    ] {
        let result = review_post_tool(&request(root.path(), &blocked));
        assert_eq!(result.reason_code, "source_secret_match", "{blocked:?}");
    }
}

#[cfg(any(unix, windows))]
#[test]
fn slices_of_a_value_far_below_its_credential_name_stay_blocked() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    let value = ["s3cr3t", "Value", "1234"].concat();
    let quoted = format!("\"{value}\"");
    let layouts: [&[&str]; 2] = [
        &["api_key =", "", "", "", ""],
        &["api_key", "", "", "", "=", "", "", ""],
    ];
    for layout in layouts {
        let mut lines: Vec<String> = (1..=6).map(|number| format!("step({number})")).collect();
        lines.extend(layout.iter().map(|line| line.to_string()));
        lines.push(quoted.clone());
        lines.extend((1..=6).map(|number| format!("done({number})")));
        std::fs::write(&source, lines.join("\n") + "\n").unwrap();
        let value_line = lines.len() - 6;
        let row = |number: usize| format!("{number}:{}", lines[number - 1]);
        let slice = |rows: &[usize]| {
            let body: Vec<String> = rows.iter().map(|number| row(*number)).collect();
            format!("[example.py#ABCD]\n{}", body.join("\n"))
        };

        for blocked in [
            slice(&[value_line]),
            slice(&[value_line, value_line + 1]),
            format!("{}\n{}-{}:  …", slice(&[3]), 4, value_line),
        ] {
            let result = review_post_tool(&request(root.path(), &blocked));
            assert_eq!(result.reason_code, "source_secret_match", "{blocked:?}");
        }
        // Lines the match does not reach are still reviewed on their own.
        let clean = review_post_tool(&request(root.path(), &slice(&[value_line + 2])));
        assert_eq!(clean.reason_code, "output_scan_allow", "{clean:?}");
        let clean = review_post_tool(&request(root.path(), &slice(&[1, 2, 3])));
        assert_eq!(clean.reason_code, "output_scan_allow", "{clean:?}");
    }
}

#[cfg(unix)]
#[test]
fn search_path_lists_are_rechecked_entry_by_entry() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    let auth = workspace.join("src/components/auth");
    let queries = workspace.join("scripts/queries.json");
    std::fs::create_dir_all(&auth).unwrap();
    std::fs::create_dir_all(queries.parent().unwrap()).unwrap();
    std::fs::write(auth.join("email-auth.tsx"), "export {}\n").unwrap();
    std::fs::write(&queries, "{}\n").unwrap();

    let search = |path: String| {
        let mut input = request(&workspace, "match\n");
        let payload = input.payload.as_object_mut().unwrap();
        payload.remove("guard_source_ref");
        payload.insert("tool_name".into(), json!("grep"));
        input.payload["tool_input"] = json!({"pattern": "attempt_id", "path": path});
        review_post_tool(&input)
    };

    // Joined, the source file's `auth` directory and the JSON file name read
    // as one credential path; OMP searches them as two ordinary files.
    let list = format!(
        "{};{}",
        auth.join("email-auth.tsx").display(),
        queries.display()
    );
    assert_eq!(search(list).model_output_action, "allow_original");
    let relative = search("src/components/auth/email-auth.tsx; scripts/queries.json".into());
    assert_eq!(relative.model_output_action, "allow_original");

    let dotenv = format!("{};{}", queries.display(), workspace.join(".env").display());
    assert_eq!(search(dotenv).reason_code, "sensitive_path");
    let credentials = format!("{};{}", workspace.join(".ssh").display(), queries.display());
    assert_eq!(search(credentials).reason_code, "sensitive_path");

    // A literal path containing `;` is what OMP opens, so it is judged whole.
    let literal = workspace.join("secrets;notes");
    std::fs::create_dir_all(&literal).unwrap();
    std::fs::write(literal.join("data.json"), "{}\n").unwrap();
    let whole = search(literal.join("data.json").to_string_lossy().into_owned());
    assert_eq!(whole.reason_code, "sensitive_path");
}

#[cfg(unix)]
#[test]
fn external_source_named_for_a_credential_feature_is_scanned() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    let sibling = root.path().join("sibling");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir_all(sibling.join(".git")).unwrap();
    std::fs::create_dir_all(sibling.join("src/credentials")).unwrap();
    let read = |file: &std::path::Path, body: &str| {
        std::fs::write(file, body).unwrap();
        let target = file.to_string_lossy().into_owned();
        let output = format!("[{target}#ABCD]\n1:{}", body.trim_end());
        let mut input = request(&workspace, &output);
        input.payload["tool_input"]["path"] = json!(target);
        input.payload["guard_source_ref"]["path"] = json!(target);
        input.payload["guard_source_ref"]["tool_input_path"] = json!(target);
        review_post_tool(&input)
    };

    let source = sibling.join("src/auth-session.ts");
    let allowed = read(&source, "export const step = 1;\n");
    assert_eq!(allowed.model_output_action, "allow_original", "{allowed:?}");

    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let secret = read(&source, &format!("export const value = '{token}';\n"));
    assert_ne!(secret.model_output_action, "allow_original");

    for file in [
        sibling.join("auth.json"),
        sibling.join("api-token.txt"),
        sibling.join("src/credentials/session.ts"),
    ] {
        let result = read(&file, "inert fixture\n");
        assert_eq!(result.reason_code, "no_output_to_review", "{file:?}");
    }
}
