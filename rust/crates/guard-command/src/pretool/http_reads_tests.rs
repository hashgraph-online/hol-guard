use super::safe_http_segment;

/// A context whose home holds no configuration for either program, which is
/// what an ordinary machine looks like.
fn proven(command: &str) -> bool {
    let home = tempfile::tempdir().expect("temp home");
    proven_in(command, home.path().to_str().expect("utf-8 home"))
}

/// The same reading against a home a test has written files into.
fn proven_in(command: &str, home: &str) -> bool {
    proven_with(
        command,
        crate::pretool::PathContext {
            home_dir: Some(home),
            shell_home_matches: true,
            http_config_absent: true,
            ..Default::default()
        },
    )
}

fn proven_with(command: &str, context: crate::pretool::PathContext<'_>) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    model.confidence == "exact"
        && model.segments.first().is_some_and(|segment| {
            matches!(segment.executable.as_deref(), Some("http" | "xh"))
                && safe_http_segment(
                    segment.executable.as_deref().expect("executable"),
                    &model,
                    segment,
                    context,
                )
        })
}

/// Write `text` as the configuration at `relative` below `home`.
fn write_configuration(
    home: &std::path::Path,
    relative: &[&str],
    text: &str,
) -> std::path::PathBuf {
    let path = relative
        .iter()
        .fold(home.to_path_buf(), |path, part| path.join(part));
    std::fs::create_dir_all(path.parent().expect("configuration directory"))
        .expect("configuration directory");
    std::fs::write(&path, text).expect("configuration");
    path
}

#[test]
fn a_configuration_that_prepends_an_option_keeps_the_review() {
    for (program, relative) in [
        ("http", &[".config", "httpie"][..]),
        ("http", &[".httpie"][..]),
        ("xh", &[".config", "xh"][..]),
        ("xh", &["Library", "Application Support", "xh"][..]),
    ] {
        let home = tempfile::tempdir().expect("temp home");
        let relative: Vec<&str> = relative
            .iter()
            .copied()
            .chain(std::iter::once("config.json"))
            .collect();
        let command = format!("{program} :3000/health");
        let home_text = home.path().to_str().expect("utf-8 home");
        assert!(proven_in(&command, home_text), "{command}");

        let path = write_configuration(home.path(), &relative, "{\"default_options\": []}");
        assert!(proven_in(&command, home_text), "{command} empty");
        for text in [
            "{\"default_options\": [\"--follow\"]}",
            "{\"default_options\": [\"--download\"]}",
            "{\"default_options\": [\"--session=work\"]}",
            "{\"default_options\": \"--follow\"}",
            "{\"default_options\": null}",
            "[]",
            "not json",
            "",
        ] {
            std::fs::write(&path, text).expect("configuration");
            assert!(!proven_in(&command, home_text), "{command} {text}");
        }
        // A file carrying only HTTPie's own bookkeeping prepends nothing.
        std::fs::write(&path, "{\"__meta__\": {\"httpie\": \"3.2.2\"}}").expect("configuration");
        assert!(proven_in(&command, home_text), "{command} meta");
    }
}

#[test]
fn a_home_the_proof_cannot_place_keeps_the_review() {
    let home = tempfile::tempdir().expect("temp home");
    let home_text = home.path().to_str().expect("utf-8 home");
    assert!(proven_in("http :3000/health", home_text));
    for context in [
        crate::pretool::PathContext {
            home_dir: Some(home_text),
            shell_home_matches: true,
            // An inherited HTTPIE_CONFIG_DIR reads the file from somewhere
            // this proof never looked.
            http_config_absent: false,
            ..Default::default()
        },
        crate::pretool::PathContext {
            home_dir: Some(home_text),
            shell_home_matches: false,
            http_config_absent: true,
            ..Default::default()
        },
        crate::pretool::PathContext {
            home_dir: Some("relative/home"),
            shell_home_matches: true,
            http_config_absent: true,
            ..Default::default()
        },
        crate::pretool::PathContext {
            home_dir: None,
            shell_home_matches: true,
            http_config_absent: true,
            ..Default::default()
        },
    ] {
        assert!(!proven_with("http :3000/health", context));
    }
}

#[test]
fn a_read_of_a_local_or_public_service_is_proven() {
    for command in [
        "http http://127.0.0.1:8080/health",
        "http GET http://127.0.0.1:8080/health",
        "http HEAD http://localhost:3000/api/status",
        "http --json GET http://localhost:3000/api/status",
        "xh http://127.0.0.1:8080/health",
        "xh GET http://127.0.0.1:8080/health",
        "http :3000/health",
        "http GET :3000/api/status",
        "http :/health",
        "http -v http://127.0.0.1:8080/health",
        "http -bq http://127.0.0.1:8080/health",
        "http --headers http://127.0.0.1:8080/health",
        "http --print=HhBb http://127.0.0.1:8080/health",
        "http --print HhBb http://127.0.0.1:8080/health",
        "http -p b http://127.0.0.1:8080/health",
        "http -pb http://127.0.0.1:8080/health",
        "http --pretty=none --style=monokai http://127.0.0.1:8080/health",
        "http --timeout 5 --check-status http://127.0.0.1:8080/health",
        "http --ignore-stdin http://127.0.0.1:8080/health",
        "http --ignore-stdin https://example.com/api/health",
        "http --ignore-stdin -- https://example.com/api/health",
        "http --ignore-stdin https://api.example.com/v1/status Accept:application/json",
    ] {
        assert!(proven(command), "{command}");
    }
}

#[test]
fn a_body_a_file_a_credential_or_another_destination_stays_reviewed() {
    for command in [
        // A verb whose answer is not a read, or one this proof does not name.
        "http POST http://127.0.0.1:8080/health",
        "http DELETE http://127.0.0.1:8080/items/1",
        "http get http://127.0.0.1:8080/health",
        // Request items that build a body, a query string or an upload.
        "http http://127.0.0.1:8080/items name=value",
        "http http://127.0.0.1:8080/items count:=3",
        "http http://127.0.0.1:8080/items search==term",
        "http http://127.0.0.1:8080/items file@notes.txt",
        "http http://127.0.0.1:8080/items body=@notes.txt",
        "http http://127.0.0.1:8080/items fields=a:b",
        // Headers that carry a credential.
        "http http://127.0.0.1:8080/health Authorization:Bearer-x",
        "http http://127.0.0.1:8080/health X-Api-Key:x",
        "http http://127.0.0.1:8080/health Cookie:session=x",
        // Options that write a file, send credentials or move the request.
        "http --download http://127.0.0.1:8080/health",
        "http -d http://127.0.0.1:8080/health",
        "http --output out.json http://127.0.0.1:8080/health",
        "http -o out.json http://127.0.0.1:8080/health",
        "http --follow http://127.0.0.1:8080/health",
        "http -F http://127.0.0.1:8080/health",
        "http --auth user:pass http://127.0.0.1:8080/health",
        "http -a user:pass http://127.0.0.1:8080/health",
        "http --session=work http://127.0.0.1:8080/health",
        "http --proxy http:http://127.0.0.1:9000 http://127.0.0.1:8080/health",
        "http --verify=no https://example.com/",
        "http --cert client.pem https://example.com/",
        "http --form http://127.0.0.1:8080/items name=value",
        "http -f http://127.0.0.1:8080/items name=value",
        "http --default-scheme https example.com",
        "http --print ../../etc/passwd http://127.0.0.1:8080/health",
        // A public host with no word about what stdin carries.
        "http https://example.com/api/health",
        "http -- https://example.com/api/health",
        "xh https://example.com/api/health",
        // Destinations the curl reading already refuses.
        "http http://127.0.0.1:9222/json",
        "http http://169.254.169.254/latest/meta-data/",
        "http https://example.com/api?token=abc",
        "http $URL",
        // Nothing to read.
        "http",
        "http GET",
        "http --json",
    ] {
        assert!(!proven(command), "{command}");
    }
}

#[test]
fn the_local_shorthand_names_the_local_host_only() {
    assert!(super::header_item("Accept:application/json"));
    assert!(!super::header_item("Accept"));
    assert!(!super::header_item("name=value"));
    assert!(!super::header_item("count:=3"));
    assert!(!super::header_item("file@notes.txt"));

    let context = crate::pretool::PathContext::default();
    assert!(super::readable(":3000/health", context, false));
    assert!(super::readable(":/health", context, false));
    // The shorthand writes the host in; it never reaches another one.
    assert!(!super::readable(":9222/json", context, false));
    assert!(!super::readable("::3000/health", context, false));
}

/// Both programs take a redirected stdin as the request body, so a read whose
/// answer could leave this machine says on the line that it carries none.
#[test]
fn a_public_read_says_what_it_carries_and_a_local_one_need_not() {
    let context = crate::pretool::PathContext::default();
    assert!(!super::readable(
        "https://example.com/api/health",
        context,
        false
    ));
    assert!(super::readable(
        "https://example.com/api/health",
        context,
        true
    ));
    assert!(super::readable(
        "http://127.0.0.1:8080/health",
        context,
        false
    ));
    // The flag is read as an option, not as a word the request names.
    assert!(proven("http --ignore-stdin https://example.com/api/health"));
    assert!(!proven(
        "http -- --ignore-stdin https://example.com/api/health"
    ));
}
