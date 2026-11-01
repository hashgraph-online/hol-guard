use super::*;
use crate::grok_executable_paths::{chain_secure, lenient};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Inside the checkout rather than the shared temp directory, whose
        // world-writable ancestors no launcher could be trusted under.
        let directory = tempfile::Builder::new()
            .prefix("grok-executable-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("tempdir");
        let root = strict(directory.path()).expect("canonical root");
        for part in ["home/.hol-guard", "workspace", "elsewhere"] {
            fs::create_dir_all(root.join(part)).expect("layout");
        }
        Self {
            _directory: directory,
            root,
        }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    /// Whether a launcher under this fixture can pass the ownership checks.
    fn secure(&self) -> bool {
        let secure = chain_secure(&self.root);
        if !secure {
            eprintln!("skipping: the checkout path is writable by another account");
        }
        secure
    }

    fn request(&self, op: &str, fields: Value) -> Result<Value, String> {
        let mut request = json!({
            "schema": SCHEMA,
            "op": op,
            "guard_home": self.home().join(".hol-guard"),
            "home_dir": self.home(),
            "workspace_dir": self.workspace(),
            "cwd": self.root.join("elsewhere"),
        });
        for (key, value) in fields.as_object().expect("fields").clone() {
            request[key] = value;
        }
        let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
        answer(&request)
    }

    fn resolve(&self, fields: Value) -> Value {
        self.request("resolve", fields).expect("resolve answer")
    }
}

fn write_executable(path: &Path, body: &str) -> PathBuf {
    let parent = path.parent().expect("parent");
    fs::create_dir_all(parent).expect("parent dir");
    // A permissive umask must not make the fixture's own directories unsafe.
    let checkout = strict(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("checkout");
    for directory in parent
        .ancestors()
        .take_while(|directory| *directory != checkout)
    {
        set_mode(directory, 0o755);
    }
    fs::write(path, body).expect("write");
    set_mode(path, 0o755);
    path.to_path_buf()
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn error(answer: &Value) -> String {
    assert!(answer["executable"].is_null(), "{answer}");
    answer["error"].as_str().expect("error").to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn requests_are_validated() {
    let fixture = Fixture::new();
    for (op, fields) in [
        ("resolve", json!({ "schema": "grok-executable.v0" })),
        ("resolve", json!({ "home_dir": "relative/home" })),
        ("resolve", json!({ "path": "/usr/bin/grok" })),
        ("resolve", json!({ "env_keys": ["PATH"] })),
        ("register", json!({})),
        (
            "register",
            json!({ "path": "/usr/bin/grok", "explicit": "/usr/bin/grok" }),
        ),
        ("launch-env", json!({ "candidate": "/usr/bin/grok" })),
        (
            "launch-env",
            json!({ "windows_roots": ["a", "b", "c", "d"] }),
        ),
        ("delete", json!({})),
        ("resolve", json!({ "unknown": true })),
    ] {
        assert!(
            fixture.request(op, fields.clone()).is_err(),
            "{op} {fields}"
        );
    }
}

#[test]
fn a_missing_candidate_is_reported_as_not_found() {
    let fixture = Fixture::new();
    assert_eq!(error(&fixture.resolve(json!({}))), NOT_FOUND);
}

#[test]
fn standard_user_install_roots_are_automatic() {
    let fixture = Fixture::new();
    if !fixture.secure() {
        return;
    }
    for relative in [
        ".local/bin/grok",
        ".grok/bin/grok",
        ".nvm/versions/node/v22.1.0/bin/grok",
    ] {
        let body = format!("#!/bin/sh\n# {relative}\nexit 0\n");
        let candidate = write_executable(&fixture.home().join(relative), &body);
        let answer = fixture.resolve(json!({ "candidate": candidate }));
        let executable = &answer["executable"];
        assert_eq!(executable["path"], json!(candidate), "{answer}");
        assert_eq!(executable["source"], "automatic");
        assert_eq!(executable["content_sha256"], sha256_hex(body.as_bytes()));
    }
}

#[test]
fn a_custom_path_root_requires_one_explicit_selection() {
    let fixture = Fixture::new();
    let candidate = write_executable(&fixture.root.join("custom-tools/grok"), "#!/bin/sh\n");
    let answer = fixture.resolve(json!({ "candidate": candidate }));
    assert!(error(&answer).contains("--grok-executable"), "{answer}");
    let unmanaged = fixture.home().join(".nvm/versions/node/v22.1.0/lib/grok");
    let answer = fixture.resolve(json!({ "candidate": write_executable(&unmanaged, "x") }));
    assert!(error(&answer).contains("--grok-executable"), "{answer}");
}

#[test]
fn workspace_guard_home_and_cwd_launchers_are_refused() {
    let fixture = Fixture::new();
    for directory in [
        fixture.workspace().join("bin"),
        fixture.home().join(".hol-guard/bin"),
        fixture.root.join("elsewhere/bin"),
    ] {
        let candidate = write_executable(&directory.join("grok"), "#!/bin/sh\n");
        for fields in [
            json!({ "candidate": candidate }),
            json!({ "explicit": candidate }),
        ] {
            let answer = fixture.resolve(fields);
            assert!(error(&answer).contains("workspace"), "{answer}");
        }
    }
}

#[test]
fn the_cwd_is_not_refused_when_it_holds_the_home_directory() {
    let fixture = Fixture::new();
    if !fixture.secure() {
        return;
    }
    let candidate = write_executable(&fixture.home().join(".local/bin/grok"), "#!/bin/sh\n");
    let answer = fixture.resolve(json!({ "candidate": candidate, "cwd": fixture.home() }));
    assert_eq!(answer["executable"]["source"], "automatic", "{answer}");
}

#[test]
fn a_relative_candidate_is_never_promoted_to_absolute() {
    let fixture = Fixture::new();
    let answer = fixture.resolve(json!({ "candidate": "relative-bin/grok" }));
    assert!(error(&answer).contains("absolute"), "{answer}");
}

#[test]
fn a_file_that_is_not_named_grok_is_refused() {
    let fixture = Fixture::new();
    let other = write_executable(&fixture.root.join("custom-tools/node"), "#!/bin/sh\n");
    let answer = fixture.resolve(json!({ "explicit": other }));
    assert_eq!(
        error(&answer),
        "The selected file is not a Grok executable."
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_into_the_workspace_is_refused() {
    let fixture = Fixture::new();
    let target = write_executable(&fixture.workspace().join("tools/grok"), "#!/bin/sh\n");
    let candidate = fixture.root.join("trusted-bin/grok");
    fs::create_dir_all(candidate.parent().expect("parent")).expect("dir");
    std::os::unix::fs::symlink(&target, &candidate).expect("symlink");
    let answer = fixture.resolve(json!({ "explicit": candidate }));
    assert!(error(&answer).contains("symlink targets"), "{answer}");
}

#[cfg(unix)]
#[test]
fn writable_or_non_executable_launchers_are_refused() {
    let fixture = Fixture::new();
    let candidate = write_executable(&fixture.root.join("custom-tools/grok"), "#!/bin/sh\n");
    set_mode(&candidate, 0o775);
    let answer = fixture.resolve(json!({ "explicit": candidate }));
    assert!(error(&answer).contains("writable"), "{answer}");
    set_mode(&candidate, 0o644);
    let answer = fixture.resolve(json!({ "explicit": candidate }));
    assert!(error(&answer).contains("not executable"), "{answer}");
}

#[test]
fn an_explicit_selection_is_registered_and_bound_to_its_hash() {
    let fixture = Fixture::new();
    if !fixture.secure() {
        return;
    }
    let custom = write_executable(
        &fixture.root.join("custom-tools/grok"),
        "#!/bin/sh\nexit 0\n",
    );
    let explicit = fixture.resolve(json!({ "explicit": custom }));
    assert_eq!(explicit["executable"]["source"], "explicit", "{explicit}");

    let registered = fixture
        .request("register", json!({ "path": custom }))
        .expect("register answer");
    assert_eq!(registered["trusted"], true, "{registered}");
    assert_eq!(registered["executable"]["source"], "registration");
    let file = fixture
        .home()
        .join(".hol-guard/managed/grok/trusted-executable.json");
    let text = fs::read_to_string(&file).expect("registration");
    assert!(text.starts_with("{\"path\":"), "{text}");
    assert!(
        text.contains(",\"schemaVersion\":1,\"sha256\":\""),
        "{text}"
    );
    assert!(text.ends_with("\"}\n"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(file.parent().expect("state dir")), 0o700);
    }

    let subsequent = fixture.resolve(json!({}));
    assert_eq!(
        subsequent["executable"]["source"], "registration",
        "{subsequent}"
    );
    assert_eq!(
        subsequent["executable"]["content_sha256"],
        registered["executable"]["content_sha256"]
    );

    write_executable(&custom, "#!/bin/sh\nexit 1\n");
    assert!(error(&fixture.resolve(json!({}))).contains("changed"));
    // An explicit selection still wins over the stale registration.
    let reselected = fixture.resolve(json!({ "explicit": custom }));
    assert_eq!(
        reselected["executable"]["source"], "explicit",
        "{reselected}"
    );
}

#[test]
fn registering_an_untrusted_path_saves_nothing() {
    let fixture = Fixture::new();
    let candidate = write_executable(&fixture.workspace().join("bin/grok"), "#!/bin/sh\n");
    let answer = fixture
        .request("register", json!({ "path": candidate }))
        .expect("register answer");
    assert_eq!(answer["trusted"], false, "{answer}");
    assert!(error(&answer).contains("workspace"));
    assert!(!fixture.home().join(".hol-guard/managed/grok").exists());
}

#[cfg(unix)]
#[test]
fn an_unsafe_or_malformed_registration_is_refused() {
    let fixture = Fixture::new();
    let state = fixture.home().join(".hol-guard/managed/grok");
    fs::create_dir_all(&state).expect("state dir");
    let file = state.join(REGISTRATION_FILE);
    let cases = [
        (
            "{\"schemaVersion\":2,\"path\":\"/usr/bin/grok\",\"sha256\":\"x\"}",
            0o600,
            "unsupported format",
        ),
        ("[1]", 0o600, "unsupported format"),
        (
            "{\"schemaVersion\":1,\"path\":7,\"sha256\":\"x\"}",
            0o600,
            "incomplete",
        ),
        ("not json", 0o600, "unreadable"),
        (
            "{\"schemaVersion\":1,\"path\":\"/usr/bin/grok\",\"sha256\":\"x\"}",
            0o666,
            "unsafe ownership",
        ),
    ];
    for (body, mode, expected) in cases {
        fs::write(&file, body).expect("write registration");
        set_mode(&file, mode);
        let answer = fixture.resolve(json!({}));
        assert!(error(&answer).contains(expected), "{body}: {answer}");
    }
    fs::remove_file(&file).expect("remove");
    fs::create_dir(&file).expect("directory in its place");
    assert!(error(&fixture.resolve(json!({}))).contains("not a regular file"));
}

#[test]
fn the_launch_environment_drops_loaders_and_unsafe_path_entries() {
    let fixture = Fixture::new();
    let workspace_bin = fixture.workspace().join("bin");
    fs::create_dir_all(&workspace_bin).expect("workspace bin");
    let separator = if cfg!(windows) { ";" } else { ":" };
    let path_value = [
        workspace_bin.to_str().expect("utf-8"),
        "relative-bin",
        "/usr/bin",
    ]
    .join(separator);
    let answer = fixture
        .request(
            "launch-env",
            json!({
                "path_value": path_value,
                "grok_home": fixture.workspace().join(".grok"),
                "env_keys": ["DYLD_INSERT_LIBRARIES", "GROK_HOME", "HOME", "NODE_OPTIONS", "PATH", "PYTHONPATH", "SAFE_SETTING"],
            }),
        )
        .expect("launch answer");
    assert_eq!(
        answer["drop"],
        json!([
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "GROK_HOME"
        ])
    );
    let path = answer["path"].as_str().expect("path");
    assert!(
        !path.contains(workspace_bin.to_str().expect("utf-8")),
        "{path}"
    );
    assert!(
        !path.split(separator).any(|entry| entry == "relative-bin"),
        "{path}"
    );
}

#[test]
fn a_grok_home_outside_the_refused_locations_is_kept() {
    let fixture = Fixture::new();
    let answer = fixture
        .request(
            "launch-env",
            json!({ "grok_home": "~/.grok", "env_keys": ["GROK_HOME"] }),
        )
        .expect("launch answer");
    assert_eq!(answer["drop"], json!([]));
}

#[test]
fn an_empty_safe_path_falls_back_to_the_default() {
    let fixture = Fixture::new();
    let answer = fixture
        .request("launch-env", json!({ "path_value": "relative-only" }))
        .expect("launch answer");
    let default = if cfg!(windows) {
        ".;C:\\bin"
    } else {
        "/bin:/usr/bin"
    };
    assert_eq!(answer["path"], default);
}

#[test]
fn lenient_resolution_appends_what_does_not_exist() {
    let fixture = Fixture::new();
    let root = &fixture.root;
    assert_eq!(
        lenient(&root.join("missing/../workspace/new"), root),
        Some(root.join("workspace/new"))
    );
    assert_eq!(
        lenient(Path::new("workspace"), root),
        Some(root.join("workspace"))
    );
    #[cfg(unix)]
    {
        let link = root.join("link");
        std::os::unix::fs::symlink(fixture.workspace(), &link).expect("symlink");
        assert_eq!(
            lenient(&link.join("later"), root),
            Some(fixture.workspace().join("later"))
        );
    }
}

#[test]
fn tilde_paths_expand_to_the_home_directory() {
    let home = Path::new("/home/someone");
    assert_eq!(expand("~", home), home);
    assert_eq!(expand("~/", home), home);
    assert_eq!(expand("~/.local/bin", home), home.join(".local/bin"));
    assert_eq!(expand("/usr/bin", home), Path::new("/usr/bin"));
    assert_eq!(expand("~other/bin", home), Path::new("~other/bin"));
}
