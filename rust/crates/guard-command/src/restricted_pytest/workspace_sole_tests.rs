use super::*;

#[test]
fn one_plain_invocation_names_its_program() {
    for text in ["lanectl status", "lanectl status --name 'a b'", "lanectl"] {
        assert_eq!(sole_program(text).as_deref(), Some("lanectl"), "{text}");
    }
}

#[test]
fn another_program_in_the_same_shell_names_no_sole_program() {
    for text in [
        "lanectl status && git init",
        "lanectl status ; git init",
        "lanectl status || git init",
        "lanectl status | tee out",
        "git init && lanectl status",
        "FOO=1 lanectl status",
        "env lanectl status",
        "",
    ] {
        assert_eq!(sole_program(text), None, "{text}");
    }
}

/// A multi-module repository keeps every `go.mod` in a subdirectory and only
/// `go.work` at its root, and `make test` there drives `go` without naming
/// it. Reading `go.mod` alone would leave that build without its
/// dependencies.
#[test]
fn a_go_work_root_reaches_the_module_cache_without_naming_the_toolchain() {
    let root = std::env::temp_dir().join(format!("go-work-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("services/api")).unwrap();
    assert!(!reaches_go_modules("make test", &root));
    std::fs::write(root.join("go.work"), "go 1.23\n\nuse ./services/api\n").unwrap();
    assert!(reaches_go_modules("make test", &root));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn only_a_text_that_names_the_toolchain_reaches_the_go_module_cache() {
    // The cache below the real HOME holds whatever `go mod download` fetched,
    // a private module included, and the plan grants it as an executable
    // root. A workspace run that never names `go` has no reason to reach it.
    for text in [
        "go build ./...",
        "go test ./... && go vet ./...",
        "/usr/local/go/bin/go build ./...",
        "cd services/api && go test ./...",
        "GOFLAGS=-mod=mod go build ./...",
        "sudo go install ./cmd/api",
    ] {
        assert!(runs_toolchain(text, "go"), "{text}");
    }
    // The name as an argument compiles nothing, and the grant is read and
    // executable access to whatever `go mod download` has fetched.
    for text in [
        "pnpm test",
        "cargo build",
        "pytest -q",
        "pytest -k go",
        "rg -n go",
        "npm run golden",
        "./scripts/gogo.sh",
    ] {
        assert!(!runs_toolchain(text, "go"), "{text}");
    }
}

#[test]
fn only_a_cargo_workspace_or_a_cargo_text_reaches_the_cargo_caches() {
    // The registry and the git checkouts below the real HOME hold whatever
    // the host fetched, a private registry included, and the plan grants each
    // as an executable root. A Node or Python workspace that never names the
    // toolchain has no reason to reach them.
    let root = std::env::temp_dir().join(format!("guard-cargo-reach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for text in [
        "cargo build --locked",
        "cargo test -q && cargo clippy",
        "rustup run stable cargo build",
        "rustc --version",
        "CARGO_TERM_COLOR=always cargo check",
    ] {
        assert!(reaches_cargo_caches(text, &root), "{text}");
    }
    for text in [
        "pnpm test",
        "pytest -q",
        "go build ./...",
        "rg -n cargo",
        "./scripts/cargocult.sh",
    ] {
        assert!(!reaches_cargo_caches(text, &root), "{text}");
    }
    // A package the root holds is driven by `make` and by its own scripts
    // without either naming cargo, so the manifest grants the caches too.
    std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    assert!(reaches_cargo_caches("make test", &root));
    let _ = std::fs::remove_dir_all(&root);
}
