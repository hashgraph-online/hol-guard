use super::{env_requires_approval_even_when_contained, go_env_inert, go_toolchain_selector, read_only_query, safe_go_probe};
use std::path::{Path, PathBuf};

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-go-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos(),
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn the_printing_queries_are_read_and_the_writing_ones_are_not() {
    for arguments in [
        "version",
        "env GOPATH",
        "env GOROOT GOMODCACHE",
        "env -json GOVERSION",
    ] {
        assert!(read_only_query(&words(arguments)), "go {arguments}");
    }
    for arguments in [
        // A full environment dump can invoke the configured C compiler.
        "env",
        "env -json",
        // Go 1.23.2 invokes CC while computing these values, including in
        // JSON mode. No setting below may receive a direct read proof.
        "env CGO_CFLAGS",
        "env CGO_CPPFLAGS",
        "env CGO_CXXFLAGS",
        "env CGO_FFLAGS",
        "env CGO_LDFLAGS",
        "env PKG_CONFIG",
        "env GOGCCFLAGS",
        "env -json CGO_CFLAGS",
        // These write the stored environment file.
        "env -w GOTOOLCHAIN=local",
        "env -u GOFLAGS",
        // These open the named executables and print what is built into
        // them, so they are file reads rather than a banner.
        "version -m ./bin/server",
        "version ./bin/server",
        // Every other verb compiles, fetches or runs the workspace's code.
        "build ./...",
        "run .",
        "test ./...",
        "list ./...",
        "generate ./...",
        "install example.test/cmd/tool@latest",
        "help",
        "help env",
        "",
        // An option this proof has not read is still an option.
        "env -changed",
        "env --json",
        "env GO-PATH",
        "env GOPATH=/tmp",
    ] {
        assert!(!read_only_query(&words(arguments)), "go {arguments}");
    }
}

#[test]
fn compiler_derived_go_environment_reads_keep_approval_even_in_a_sandbox() {
    for arguments in [
        "env",
        "env -json",
        "env CGO_CFLAGS",
        "env CGO_CPPFLAGS",
        "env CGO_CXXFLAGS",
        "env CGO_FFLAGS",
        "env CGO_LDFLAGS",
        "env PKG_CONFIG",
        "env GOGCCFLAGS",
        "env -json CGO_CFLAGS",
    ] {
        assert!(
            env_requires_approval_even_when_contained(&words(arguments)),
            "go {arguments}"
        );
    }
    for arguments in ["version", "env GOPATH", "env GOROOT", "env -json GOVERSION"] {
        assert!(
            !env_requires_approval_even_when_contained(&words(arguments)),
            "go {arguments}"
        );
    }
}

#[test]
fn the_settings_that_choose_a_toolchain_are_screened() {
    for name in [
        "GOTOOLCHAIN",
        "gotoolchain",
        "GOROOT",
        "GOTOOLDIR",
        "GOENV",
        "GOFLAGS",
        "GOPROXY",
        "GOSUMDB",
        "GONOSUMDB",
        "GONOSUMCHECK",
        "GOPRIVATE",
        "GOINSECURE",
        "GOPATH",
        "GOMODCACHE",
        "GOCACHEPROG",
        "GOAUTH",
        "goauth",
        "GONOPROXY",
        "GOVCS",
        "GOWORK",
        "XDG_CONFIG_HOME",
    ] {
        assert!(go_toolchain_selector(name), "{name}");
    }
    // These name where output lands or how the build caches, not which
    // toolchain answers the question.
    for name in ["GOBIN", "GOCACHE", "GODEBUG", "GOOS", "GOARCH", "HOME"] {
        assert!(!go_toolchain_selector(name), "{name}");
    }
}

#[test]
fn a_stored_setting_decides_whether_the_banner_is_read() {
    let root = temp_root("env-file");
    let directory = root.join(".config").join("go");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("env");

    // Nothing stored: the toolchain is whichever `go` the session found, or
    // a release the command downloads and verifies itself.
    assert!(go_env_inert(&path));

    for contents in [
        "",
        "GOTOOLCHAIN=local\n",
        "GOBIN=/opt/bin\nGOCACHE=/tmp/cache\n",
        // An empty value is the same as an unset one.
        "GOFLAGS=\n",
        // A line that is not a setting is not a setting.
        "a comment without an equals sign\n",
    ] {
        std::fs::write(&path, contents).unwrap();
        assert!(go_env_inert(&path), "{contents:?}");
    }

    for contents in [
        // `path` runs a `go1.N` found on PATH, which is a local binary.
        "GOTOOLCHAIN=path\n",
        "GOTOOLCHAIN=go1.25.3\n",
        "GOROOT=/opt/go\n",
        "GOTOOLDIR=/opt/go/pkg/tool\n",
        "GOPROXY=https://proxy.example.test\n",
        "GOSUMDB=off\n",
        "GOPRIVATE=example.test/*\n",
        "GOPATH=/opt/gopath\n",
        "GOMODCACHE=/opt/modcache\n",
        "GOFLAGS=-toolexec=/opt/wrap\n",
        "GOCACHEPROG=/opt/cacheprog\n",
        "GOAUTH=command /opt/sign\n",
        "GOWORK=/opt/go.work\n",
        "GOVCS=*:all\n",
        "GONOPROXY=example.test/*\n",
        "GOBIN=/opt/bin\nGOTOOLCHAIN=path\n",
    ] {
        std::fs::write(&path, contents).unwrap();
        assert!(!go_env_inert(&path), "{contents:?}");
    }

    // A file that cannot be read for what it sets is not a file that sets
    // nothing.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(!go_env_inert(&path));
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, "GOTOOLCHAIN=local\n").unwrap();
    let link = directory.join("env-link");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(!go_env_inert(&link));
    }
    #[cfg(not(unix))]
    let _ = link;

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_oversized_stored_file_keeps_the_review() {
    let root = temp_root("env-size");
    let directory = root.join(".config").join("go");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("env");
    std::fs::write(&path, "#".repeat(64 * 1024)).unwrap();
    assert!(!go_env_inert(&path));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_go_workspace_keeps_review_even_with_inert_environment() {
    let root = temp_root("workspace-toolchain");
    let repo = root.join("project");
    let nested = repo.join("src");
    std::fs::create_dir_all(&nested).unwrap();
    let home = root.to_str().unwrap().to_owned();
    let cwd = nested.to_str().unwrap().to_owned();
    let context = || super::super::PathContext {
        home_dir: Some(&home),
        cwd: Some(&cwd),
        go_toolchain_inert: true,
        shell_home_matches: true,
        ..Default::default()
    };

    // Without a workspace selector, Go has no module directive to choose
    // another program on PATH.
    assert!(safe_go_probe(&words("version"), context()));
    assert!(safe_go_probe(&words("env GOPATH"), context()));

    // Go 1.23.2 demonstrably runs an inert locally planted go1.24.0 program
    // from PATH when this directive is present, even though GOTOOLCHAIN is
    // unset and the command only asks for a version or a named setting.
    let module = repo.join("go.mod");
    std::fs::write(
        &module,
        "module example.test/guard\ngo 1.23.0\ntoolchain go1.24.0\n",
    )
    .unwrap();
    assert!(!safe_go_probe(&words("version"), context()));
    assert!(!safe_go_probe(&words("env GOPATH"), context()));
    std::fs::remove_file(&module).unwrap();

    let workspace = root.join("go.work");
    std::fs::write(&workspace, "go 1.23.0\ntoolchain go1.24.0\n").unwrap();
    assert!(!safe_go_probe(&words("version"), context()));
    std::fs::remove_file(&workspace).unwrap();

    // A file whose contents cannot be trusted is treated as a potential
    // selector too; no attempt is made to infer safety from a filename.
    std::fs::write(&module, "module example.test/guard\n").unwrap();
    assert!(!safe_go_probe(&words("version"), context()));
    std::fs::remove_file(&module).unwrap();
    assert!(safe_go_probe(&words("version"), context()));

    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn logical_go_workspace_ancestors_cannot_select_an_unreviewed_toolchain() {
    let root = temp_root("logical-go-workspace");
    let physical = root.join("physical").join("nested");
    let logical = root.join("logical");
    std::fs::create_dir_all(&physical).unwrap();
    std::fs::create_dir_all(&logical).unwrap();
    let link = logical.join("link");
    std::os::unix::fs::symlink(&physical, &link).unwrap();
    let home = root.to_str().unwrap().to_owned();
    let cwd = link.to_str().unwrap().to_owned();
    let context = || super::super::PathContext {
        home_dir: Some(&home),
        cwd: Some(&cwd),
        go_toolchain_inert: true,
        shell_home_matches: true,
        ..Default::default()
    };

    assert!(safe_go_probe(&words("version"), context()));
    // Go 1.23.2 uses a valid logical PWD to find this go.mod, even
    // though the symlink target's physical ancestors have no module.
    std::fs::write(
        logical.join("go.mod"),
        "module example.test/guard\ngo 1.23.0\ntoolchain go1.26.0\n",
    )
    .unwrap();
    assert!(!safe_go_probe(&words("version"), context()));
    assert!(!safe_go_probe(&words("env GOPATH"), context()));

    // A relative cwd must never be resolved against Guard's own cwd.
    let relative_context = super::super::PathContext {
        home_dir: Some(&home),
        cwd: Some("logical/link"),
        go_toolchain_inert: true,
        shell_home_matches: true,
        ..Default::default()
    };
    assert!(!safe_go_probe(&words("version"), relative_context));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_probe_reads_the_queries_only_where_nothing_selects_a_toolchain() {
    let root = temp_root("probe");
    let cwd = root.join("workspace");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = root.to_str().unwrap().to_owned();
    let cwd = cwd.to_str().unwrap().to_owned();
    let context = |inert: bool| super::super::PathContext {
        home_dir: Some(&home),
        cwd: Some(&cwd),
        go_toolchain_inert: inert,
        shell_home_matches: true,
        ..Default::default()
    };

    assert!(safe_go_probe(&words("version"), context(true)));
    assert!(safe_go_probe(&words("env GOPATH"), context(true)));
    // Even with a fixed official Go toolchain, the full env dump and
    // compiler-related keys can execute CC. They are not inert reads.
    for arguments in ["env", "env -json", "env CGO_CFLAGS", "env -json PKG_CONFIG"] {
        assert!(
            !safe_go_probe(&words(arguments), context(true)),
            "go {arguments}"
        );
    }
    // An inherited selector is read before anything stored, so it settles
    // the question on its own.
    assert!(!safe_go_probe(&words("version"), context(false)));
    // A writing query is not a read however the toolchain was chosen.
    assert!(!safe_go_probe(
        &words("env -w GOTOOLCHAIN=local"),
        context(true)
    ));

    // Either Unix location is a file the go command on that host would read.
    for directory in [
        Path::new(&home).join(".config").join("go"),
        Path::new(&home)
            .join("Library")
            .join("Application Support")
            .join("go"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("env");
        std::fs::write(&path, "GOTOOLCHAIN=path\n").unwrap();
        assert!(!safe_go_probe(&words("version"), context(true)));
        std::fs::remove_file(&path).unwrap();
        assert!(safe_go_probe(&words("version"), context(true)));
    }

    // The stored file is read under the home the hook reported, so a shell
    // whose own `HOME` names somewhere else is not proved by reading it.
    assert!(!safe_go_probe(
        &words("version"),
        super::super::PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            go_toolchain_inert: true,
            ..Default::default()
        }
    ));

    // A relative home is not a home this proof can read.
    assert!(!safe_go_probe(
        &words("version"),
        super::super::PathContext {
            home_dir: Some("relative/home"),
            cwd: Some(&cwd),
            go_toolchain_inert: true,
            shell_home_matches: true,
            ..Default::default()
        }
    ));
    assert!(!safe_go_probe(
        &words("version"),
        super::super::PathContext {
            cwd: Some(&cwd),
            go_toolchain_inert: true,
            shell_home_matches: true,
            ..Default::default()
        }
    ));

    std::fs::remove_dir_all(&root).unwrap();
}
