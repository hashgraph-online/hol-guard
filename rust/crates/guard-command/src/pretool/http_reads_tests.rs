use super::safe_http_segment;

fn proven(command: &str) -> bool {
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
                && safe_http_segment(&model, segment, crate::pretool::PathContext::default())
        })
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
        "http https://example.com/api/health",
        "http -- https://example.com/api/health",
        "http https://api.example.com/v1/status Accept:application/json",
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
    assert!(super::readable(":3000/health", context));
    assert!(super::readable(":/health", context));
    // The shorthand writes the host in; it never reaches another one.
    assert!(!super::readable(":9222/json", context));
    assert!(!super::readable("::3000/health", context));
}
