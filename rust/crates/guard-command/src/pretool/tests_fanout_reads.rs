#![cfg(unix)]

use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

struct Fixture {
    home: String,
    workspace: String,
}

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn fixture() -> Fixture {
    // Keep the fixture outside $TMPDIR, which canonicalizes under /private/var.
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-fanout-reads")
        .join(format!(
            "run-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
    let _ = std::fs::remove_dir_all(&base);
    let (home, ws) = (base.join("home"), base.join("home/ws"));
    for file in [
        "ws/src/main.ts",
        "ws/src/util.ts",
        "ws/test/a.test.ts",
        ".ssh/id_rsa",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic\n").unwrap();
    }
    std::fs::write(ws.join("src/.env"), "synthetic\n").unwrap();
    // A workspace symlink aimed at a credential directory.
    std::os::unix::fs::symlink(home.join(".ssh"), ws.join("linked")).unwrap();
    let canonical =
        |path: &std::path::Path| path.canonicalize().unwrap().to_str().unwrap().to_owned();
    Fixture {
        home: canonical(&home),
        workspace: canonical(&ws),
    }
}

fn action(fixture: &Fixture, cwd: &str, command: &str) -> String {
    evaluate_pre_tool_with_context(&request(command), Some(&fixture.home), Some(cwd))
        .map(|decision| decision.minimum_action)
        .unwrap_or_else(|error| error)
}

#[test]
fn read_only_find_fanout_runs_silently() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "find src test -type f -name '*.ts' -exec cat {} +",
        "find . -type f -name '*.ts' -exec cat {} +",
        "find src -type f -name '*.ts' -exec head -n 5 {} +",
        "find src -maxdepth 2 -type f -name '*.ts' -exec wc -l {} +",
        "find src test -type f -name '*.ts' -print0 | xargs -0 cat",
        "find src -type f -name '*.ts' -print0 | xargs -0 -r -n 10 head -n 3",
        "find src -type f -name '*.ts' -print0 | xargs -0 wc -l | tail -1",
        "find src -type f -print0 | xargs -0 stat",
        "find src -type f -name '*.ts' -print0 | xargs -0 cat 2>&1 | tail -30",
    ] {
        assert_eq!(action(&fixture, ws, command), "allow", "{command}");
    }
}

#[test]
fn search_children_run_silently() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "find src -type f -name '*.ts' -exec grep -n main {} \\;",
        "find src -type f -name '*.ts' -print0 | xargs -0 grep -n main",
    ] {
        assert_eq!(action(&fixture, ws, command), "allow", "{command}");
    }
}

#[test]
fn a_root_spelled_with_the_workspace_path_fans_out_like_the_relative_root() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        format!("find {ws}/src -type f -name '*.ts' -exec grep -l main {{}} \\;"),
        format!("find {ws}/src -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {ws}/src {ws}/test -type f -name '*.ts' -print0 | xargs -0 grep -l main"),
        format!("find {ws} -type f -name '*.ts' -exec head -n 5 {{}} +"),
    ] {
        assert_eq!(action(&fixture, ws, &command), "allow", "{command}");
    }
    let home = fixture.home.as_str();
    for command in [
        // Resolves outside the workspace, or through a link or a parent.
        format!("find {home} -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {home}/.ssh -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {ws}/linked -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {ws}/src/../linked -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {ws}/.. -type f -name '*.ts' -exec cat {{}} +"),
        format!("find {ws}/missing -type f -name '*.ts' -exec cat {{}} +"),
        // The type test and the extension test still apply.
        format!("find {ws}/src -name '*.ts' -exec grep -l main {{}} \\;"),
        format!("find {ws}/src -type f -exec cat {{}} +"),
    ] {
        assert_ne!(action(&fixture, ws, &command), "allow", "{command}");
    }
}

#[test]
fn unproven_fanout_stays_reviewed() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        // Filename injection through a replacement string or a shell.
        "find src -type f | xargs -I{} sh -c 'echo {}; cat {}'",
        "find src -type f -print0 | xargs -0 -I{} cat {}",
        "find src -type f -print0 | xargs -0 sh -c 'cat \"$@\"' _",
        "find src -type f -exec sh -c 'cat {}' \\;",
        // Whitespace splitting can add paths.
        "find src -type f -name '*.ts' | xargs cat",
        // Other producers.
        "echo ~/.ssh/id_rsa | xargs cat",
        "ls src | xargs cat",
        "printf 'src/main.ts\\0' | xargs -0 cat",
        "xargs cat",
        "xargs -0",
        // Writes, execution and network children.
        "find src -type f -name '*.ts' -print0 | xargs -0 rm",
        "find src -type f -name '*.ts' -print0 | xargs -0 curl",
        "find src -type f -name '*.ts' -exec rm {} +",
        "find src -type f -name '*.ts' -exec curl {} +",
        "find src -type f -name '*.ts' -delete",
        "find src -type f -name '*.ts' -fprint out.txt",
        "find src -type f -name '*.ts' -ok cat {} \\;",
        "find src -type f -name '*.ts' -execdir cat {} +",
        "find src -type f -name '*.ts' -exec sed -i s/a/b/ {} +",
        // Extensions outside the source list, which `*` also matches after a dot.
        "find . -type f -name '*.local' -exec cat {} +",
        "find . -type f -name '*.envrc' -exec cat {} +",
        "find . -type f -name '*.json' -print0 | xargs -0 cat",
        // Empty input without `-r` runs the child with no operand.
        "find src -type f -name '*.ts' -print0 | xargs -0 rg main",
        "find src -type f -name '*.ts' -print0 | xargs -0 grep -rn main",
        // A `;` inside the child ends the body early and exposes more expression.
        "find src -type f -name '*.ts' -exec grep -e x -e ';' -o -delete -fprintf {} ';'",
        "find src -type f -name '*.ts' -exec grep -e x -e ';' -o -exec touch {} ';'",
        "find src -type f -name '*.ts' -exec grep -e x -e ';' -fprint src/main.ts -fprintf {} ';'",
        // Roots outside the workspace or through links.
        "find .. -type f -name '*.ts' -exec cat {} +",
        "find ../home -type f -name '*.ts' -exec cat {} +",
        "find /etc -type f -name '*.conf' -exec cat {} +",
        "find ~/.ssh -type f -name '*.ts' -exec cat {} +",
        "find ~ -type f -name '*.ts' -print0 | xargs -0 cat",
        "find linked -type f -name '*.ts' -exec cat {} +",
        "find src/../linked -type f -name '*.ts' -exec cat {} +",
        // Symlinks and other node types are not regular files.
        "find src -name '*.ts' -exec cat {} +",
        "find src -type l -name '*.ts' -exec cat {} +",
        "find -L src -type f -name '*.ts' -exec cat {} +",
        "find src -follow -type f -name '*.ts' -exec cat {} +",
        "find src -type f -name '*.ts' -o -name '*.js' -exec cat {} +",
        // Content readers need a plain, non-credential extension.
        "find src -type f -exec cat {} +",
        "find src -type f -name '.env*' -exec cat {} +",
        "find src -type f -name '*.env' -exec cat {} +",
        "find src -type f -name '*.pem' -print0 | xargs -0 cat",
        "find src -type f -name '*' -exec cat {} +",
    ] {
        assert_ne!(action(&fixture, ws, command), "allow", "{command}");
    }
}

#[test]
fn home_workspace_has_no_fanout_boundary() {
    let fixture = fixture();
    let command = "find ws -type f -name '*.ts' -exec cat {} +";
    assert_ne!(action(&fixture, &fixture.home, command), "allow");
}

#[test]
fn whitespace_split_xargs_names_the_safe_form() {
    let fixture = fixture();
    let decision = evaluate_pre_tool_with_context(
        &request("find src -type f -name '*.ts' | xargs cat"),
        Some(&fixture.home),
        Some(&fixture.workspace),
    )
    .unwrap();
    assert_eq!(decision.minimum_action, "review");
    assert!(decision.reason.contains("-print0 | xargs -0"));
}
