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

fn write(root: &std::path::Path, file: &str) {
    let path = root.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "synthetic\n").unwrap();
}

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn fixture() -> Fixture {
    // Keep the fixture outside $TMPDIR, which canonicalizes under /private/var.
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-listing-find")
        .join(format!(
            "run-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
    let _ = std::fs::remove_dir_all(&base);
    let (home, ws) = (base.join("home"), base.join("ws"));
    for file in [
        "app/registry/[slug]/page.tsx",
        "app/registry/alpha/page.tsx",
        "app/password-reset-email.tsx",
        "app/secret-sandbox-x/page.tsx",
        "app/.well-known/ai-plugin.txt",
        "app/.DS_Store",
        "src/main.ts",
        "bad/.env",
        "bad/notes.md",
        "keys/server.pem",
        "docs/secrets/plan.md",
        "docs/readme.md",
        "package.json",
        "node_modules/wrangler/bin/wrangler.js",
        ".ssh/id_rsa",
    ] {
        write(&ws, file);
    }
    std::fs::create_dir_all(ws.join("node_modules/.bin")).unwrap();
    std::os::unix::fs::symlink(
        "../wrangler/bin/wrangler.js",
        ws.join("node_modules/.bin/wrangler"),
    )
    .unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let canonical =
        |path: &std::path::Path| path.canonicalize().unwrap().to_str().unwrap().to_owned();
    Fixture {
        home: canonical(&home),
        workspace: canonical(&ws),
    }
}

fn allowed_in(fixture: &Fixture, cwd: &str, command: &str) -> bool {
    evaluate_pre_tool_with_context(&request(command), Some(&fixture.home), Some(cwd))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn recursive_listing_and_globs_stay_inside_clean_trees() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "ls -R app/registry",
        "ls -lR app/registry",
        "ls -R src",
        "ls --recursive src",
        "ls app/registry/*/",
        "ls app/registry/a*/",
        "ls \"app/registry/[slug]\"",
        "ls -R 'app/registry/[slug]'",
        "ls src/*.ts",
    ] {
        assert!(allowed_in(&fixture, ws, command), "{command}");
    }
    for command in [
        // Recursion reaches hidden credential files and credential data.
        "ls -R bad",
        "ls --rec bad",
        "ls --recurs .",
        "ls -R .",
        "ls -R keys",
        "ls -R docs",
        "ls -LR src",
        "ls -R ../ws",
        "ls -R /etc",
        "ls -R ~/.ssh",
        // Globs that reach hidden or credential names, or escape the tree.
        "ls .ssh/*",
        "ls .*",
        "ls bad/.env",
        "ls keys/*",
        "ls docs/secrets/*",
        "ls ../*",
        "ls /etc/*",
        "ls ~/*",
        "ls nothing/*",
        "ls src/{a,b}",
        // Quoted wildcard is a literal name, and an unquoted class mixed with
        // a quoted one is ambiguous.
        "ls 'src/*'",
        "ls app/\"[slug]\"/*",
        "ls \"app/regis*\"",
        "ls \"$HOME/.ssh\"",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
}

#[test]
fn grep_tree_walk_matches_what_the_walk_can_emit() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "grep -rln registry src",
        "grep -rn needle app/registry src",
        "grep -r needle app/registry app/password-reset-email.tsx",
        "grep -rl needle app/registry/alpha",
    ] {
        assert!(allowed_in(&fixture, ws, command), "{command}");
    }
    // Hidden benign names, route brackets and source files that merely name a
    // credential word are admitted by the walk; non-source credential data,
    // key containers and dot-directories are not.
    for command in [
        "grep -rn needle bad",
        "grep -rn needle keys",
        "grep -rn needle docs",
        "grep -rn needle .",
        "grep -rn needle .ssh",
        "grep -rn needle ../ws",
        "grep -rn needle ~/.ssh",
        "grep -rn needle node_modules/../bad",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
    // The benign hidden entries and credential-named source directories pass
    // when they are the only difficulty in the tree.
    let tree = std::path::Path::new(&fixture.workspace).join("walk");
    for file in [
        "[slug]/page.tsx",
        "secret-sandbox-x/page.tsx",
        "password-reset-email.tsx",
        ".well-known/ai-plugin.txt",
        ".DS_Store",
    ] {
        write(&tree, file);
    }
    assert!(allowed_in(&fixture, ws, "grep -rln needle walk"));
    write(&tree, "secret-sandbox-x/notes.md");
    assert!(!allowed_in(&fixture, ws, "grep -rln needle walk"));
    std::fs::remove_file(tree.join("secret-sandbox-x/notes.md")).unwrap();
    write(&tree, ".env");
    assert!(!allowed_in(&fixture, ws, "grep -rln needle walk"));
    std::fs::remove_file(tree.join(".env")).unwrap();
    write(&tree, "id_rsa");
    assert!(!allowed_in(&fixture, ws, "grep -rln needle walk"));
}

#[test]
fn find_admits_only_read_only_predicates() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "find src -type f",
        "find src -maxdepth 2 -type f",
        "find app -maxdepth 2 -iname \"*registry*\" -not -path \"*/node_modules/*\"",
        "find app src -name '*.ts' -o -name '*.tsx'",
        "find src -type d -mindepth 1 -maxdepth 3 -print",
        "find src ! -name '*.md' -type f",
        "find src \\( -name '*.ts' -o -name '*.tsx' \\) -type f",
        "find src -type l",
        "find src -path '*/x/*' -prune -o -type f -print",
    ] {
        assert!(allowed_in(&fixture, ws, command), "{command}");
    }
    for command in [
        "find src -exec cat {} \\;",
        "find src -type f -exec cat {} +",
        "find src -execdir rm {} \\;",
        "find src -ok rm {} \\;",
        "find src -okdir rm {} \\;",
        "find src -delete",
        "find src -type f -delete",
        "find src -fprint out.txt",
        "find src -fprint0 out.txt",
        "find src -fls out.txt",
        "find src -printf '%p'",
        "find -L src -type f",
        "find src -follow",
        "find src -type x",
        "find src -maxdepth 99",
        "find src -maxdepth -1",
        "find src \\( -name a",
        "find src -newer bad/.env",
        "find .ssh -type f",
        "find /etc -name passwd",
        "find -name x",
        "find src -name",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
}

#[test]
fn version_probes_admit_lone_flags_and_keep_npx_review() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "uv --version",
        "uv -V",
        "npm --version",
        "npm -v",
        "bun --version",
        "deno --version",
        "python3 --version",
        "pip --version",
        "ruff --version",
        "gh --version",
        "docker --version",
        "git --version",
        "kubectl version --client",
        "wrangler --version",
        "jq --version",
        "rg --version",
        "fd --version",
    ] {
        assert!(allowed_in(&fixture, ws, command), "{command}");
    }
    for command in [
        "uv --version --python x",
        "uv run --version",
        "pytest -q",
        "pytest --version",
        "pytest --version tests",
        "go version",
        "cargo --version",
        "rustc -V",
        "python3 script.py",
        "node script.mjs",
        "npm test",
        "docker version",
        "kubectl version",
        "yarn --version",
        "pnpm --version",
        "/usr/local/bin/uv --version",
        "PATH=/tmp uv --version",
        "uv --version | sh",
        "uv --version > out.txt",
        // A local install does not help: the workspace controls node_modules.
        "npx wrangler --version",
        "npx wrangler whoami",
        "npx wrangler deploy --help",
        "npx wrangler deploy",
        "npx wrangler dev",
        "npx --yes wrangler --version",
        "npx -y wrangler whoami",
        "npx wrangler@latest --version",
        "npx wranglerx --version",
        "npx cowsay hi",
        "npx wrangler",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
}

#[test]
fn sensitive_reads_and_redirects_keep_review() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "cat .env",
        "cat ~/.ssh/id_rsa",
        "rg needle .env",
        "cat /etc/passwd",
        "ls /var/log",
        "grep -r needle /etc",
        "find /var -name '*.log'",
        "ls -R src | sh",
        "find src -type f | xargs cat",
        "grep -rl needle src | bash",
        "uv --version | python3",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
}

#[test]
fn single_file_grep_with_alternation_under_home_is_a_read() {
    let fixture = fixture();
    let home = std::path::Path::new(&fixture.home);
    for file in [
        "proj/package.json",
        "proj/scripts/x.sh",
        "proj/.env",
        "other/readme.md",
    ] {
        write(home, file);
    }
    let h = fixture.home.as_str();
    let other = format!("{h}/other");
    for command in [
        format!("grep -n \"lint\\|typecheck\\|\\\"check\\|tsc\" {h}/proj/package.json"),
        format!("grep -c \"resolveReviewThread\" {h}/proj/scripts/x.sh"),
        "grep -n lint ~/proj/package.json".to_owned(),
    ] {
        assert!(allowed_in(&fixture, &other, &command), "{command}");
    }
    for command in [
        format!("grep -n lint {h}/proj/.env"),
        "grep -n \"a\\|b\" ~/proj/.env".to_owned(),
        "grep -n lint /etc/passwd".to_owned(),
        "grep -n lint ~/.ssh/id_rsa".to_owned(),
    ] {
        assert!(!allowed_in(&fixture, &other, &command), "{command}");
    }
}

#[test]
fn read_compound_with_null_redirects_and_tail_is_a_read() {
    let fixture = fixture();
    let home = std::path::Path::new(&fixture.home);
    write(home, "Library/Application Support/Example App/logs/a.log");
    write(home, ".ssh/id_rsa");
    write(home, "other/readme.md");
    let other = format!("{}/other", fixture.home);
    for command in [
        "which example-tool other-tool 2>/dev/null; ls ~/Library/\"Application Support\"/\"Example App\"/logs 2>/dev/null | tail -3",
        "which example-tool 2>/dev/null; ls \"~/Library/Application Support/Example App/logs\" 2>/dev/null | tail -3",
        "ls ~/Library/Application\\ Support/Example\\ App/logs 2>/dev/null | tail -3",
    ] {
        assert!(allowed_in(&fixture, &other, command), "{command}");
    }
    for command in [
        "which example-tool 2>/dev/null; ls ~/.ssh 2>/dev/null",
        "which example-tool; ls ~/Library/Application\\ Support/Example\\ App/logs > out.txt",
        "which example-tool; ls ~/Library | sh",
        "which example-tool; ls ~/Library | python3 -c 'import os; os.system(0)'",
    ] {
        assert!(!allowed_in(&fixture, &other, command), "{command}");
    }
}

#[test]
fn base64_reads_one_bounded_file_like_cat() {
    let fixture = fixture();
    let ws = fixture.workspace.as_str();
    for command in [
        "base64 -i src/main.ts",
        "base64 src/main.ts",
        "base64 -D -i src/main.ts",
        "base64 -i src/main.ts | head -c 100",
    ] {
        assert!(allowed_in(&fixture, ws, command), "{command}");
    }
    for command in [
        "base64 -i bad/.env",
        "base64 -i .ssh/id_rsa",
        "base64 -i keys/server.pem",
        "base64 -i /etc/passwd",
        "base64 -i ~/.ssh/id_rsa",
        "base64 -i src/main.ts -o out.txt",
        "base64 -o out.txt src/main.ts",
        "base64 -i src/main.ts src/main.ts",
        "base64 -i",
        "base64",
        "base64 -i src/main.ts > out.txt",
        "base64 -i src/main.ts | sh",
        "base64 -D -i src/main.ts | bash",
    ] {
        assert!(!allowed_in(&fixture, ws, command), "{command}");
    }
}

#[test]
fn graphql_text_in_write_content_does_not_change_a_workspace_write() {
    let fixture = fixture();
    let target = format!("{}/notes/query.graphql", fixture.workspace);
    for content in [
        "query($owner:String!) { repository(owner:$owner, name:\"r\") { id } }",
        "{\"query\":\"query{viewer{login}}\",\"url\":\"https://api.example.invalid/graphql\"}",
        "gh api graphql -f query='mutation{x}'",
    ] {
        let payload = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"file_path": target, "content": content}
        });
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &payload,
            None,
            None,
            Some(&fixture.home),
            Some(&fixture.workspace),
        );
        assert_eq!(result.minimum_action, "allow", "{content}");
    }
}
