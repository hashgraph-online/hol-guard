use super::{contained_shape, project};
use std::path::PathBuf;

fn fresh_workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-wr-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn literal_path_redirects_are_projected_away() {
    for (raw, projected) in [
        ("python3 app.py > out.txt", "python3 app.py"),
        ("python3 app.py > out.txt 2>&1", "python3 app.py"),
        ("python3 app.py >> log.txt", "python3 app.py"),
        ("python3 app.py >| log.txt", "python3 app.py"),
        ("python3 app.py < input.txt", "python3 app.py"),
        ("python3 app.py 2>/dev/null", "python3 app.py"),
        ("python3 app.py >&2", "python3 app.py"),
        ("python3 app.py>out.txt", "python3 app.py"),
        ("echo a > a.txt  &&  echo b", "echo a &&  echo b"),
        ("echo a\\ > a.txt\nrm -rf x", "echo a\\ \nrm -rf x"),
    ] {
        assert_eq!(project(raw).as_deref(), Some(projected), "{raw}");
    }
    let compound = project("printf 'node_modules\\n' > .gitignore && git add -A").unwrap();
    assert!(!compound.contains(".gitignore"), "{compound}");
    assert!(compound.ends_with("&& git add -A"), "{compound}");
}

#[test]
fn quoted_heredocs_are_projected_only_when_they_feed_cat() {
    let raw = "cat > todo.py <<'EOF'\nprint('>')\nEOF\npython3 todo.py list";
    let projected = project(raw).unwrap();
    assert!(!projected.contains("print"), "{projected}");
    assert!(projected.starts_with("cat"), "{projected}");
    assert!(projected.ends_with("\npython3 todo.py list"), "{projected}");
    for raw in [
        "python3 <<'EOF'\nprint(1)\nEOF",
        "sh <<'EOF'\ngit push\nEOF",
        "cat > f <<EOF\n$(cat ~/.ssh/id_rsa)\nEOF",
        "cat > f <<'EOF'\nunterminated",
        "cat <<< text > f",
    ] {
        assert_eq!(project(raw), None, "{raw:?}");
    }
}

#[test]
fn a_quoted_heredoc_feeds_python_only_a_builtin_only_program() {
    let raw = "python3 - <<'EOF'\ns=open('a').read()\nopen('a','w').write(s.replace('if (a && import.meta.url) {', 'if (a) {'))\nEOF\nls";
    assert_eq!(project(raw).as_deref(), Some("python3 -\nls"));
    // Bodies are matched to their heredocs in order.
    let raw = "cat > a <<'A'; python3 - <<'B'\nimport os\nA\nprint(1)\nB\nls";
    assert!(project(raw).is_some(), "{raw:?}");
    for raw in [
        "cat > a <<'A'; python3 - <<'B'\nprint(1)\nA\nimport os\nB\nls",
        "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['gh','pr','list'])\nEOF",
        "python3 - <<'EOF'\nx = 'import.meta'; import os\nEOF",
        "python3 - <<'EOF'\nexec('print(1)')\nEOF",
        "python3 - <<'EOF'\n# coding: utf-7\nprint(1)\nEOF",
        "python3 - <<'EOF'\nprint(1)\n  EOF\nimport os\nEOF",
        "python3 - <<'EOF'\nprint(1)",
        "python3 - <<EOF\nprint(1)\nEOF",
        "python3 <<'EOF'\nprint(1)\nEOF",
        "PYTHONPATH=. python3 - <<'EOF'\nprint(1)\nEOF",
        "python3 -I - <<'EOF'\nprint(1)\nEOF",
        "node - <<'EOF'\nconsole.log(1)\nEOF",
        "sh - <<'EOF'\necho 1\nEOF",
        "bash <<'EOF'\necho 1\nEOF",
    ] {
        assert_eq!(project(raw), None, "{raw:?}");
    }
}

#[test]
fn other_redirect_forms_are_not_projected() {
    for raw in [
        "python3 app.py",
        "echo '>' x",
        "echo \">\" x",
        "python3 app.py > ~/out.txt",
        "python3 app.py > $OUT",
        "python3 app.py > \"out.txt\"",
        "python3 app.py > out\\ file",
        "python3 app.py > -f",
        "python3 app.py > >(tee out.txt)",
        "diff <(ls a) <(ls b)",
        "python3 app.py <> data",
        "python3 app.py 3> out.txt",
        "python3 app.py 2>&3",
        "python3 app.py <&0",
        "python3 app.py &> out.txt",
        "python3 app.py > ",
    ] {
        assert_eq!(project(raw), None, "{raw:?}");
    }
}

#[test]
fn a_bootstrapped_init_keeps_the_raw_remainder() {
    let ws = fresh_workspace("bootstrap");
    let raw = "git init && printf 'x\\n' > .gitignore && git add -A";
    let shape = contained_shape(raw, &project(raw).unwrap(), &ws).unwrap();
    assert!(shape.bootstrap.is_some());
    assert_eq!(
        shape.remainder.as_deref(),
        Some("printf 'x\\n' > .gitignore && git add -A")
    );
    // A redirect on the init itself cannot be split from the raw bytes.
    let raw = "git init > /dev/null && git add -A";
    assert!(contained_shape(raw, &project(raw).unwrap(), &ws).is_none());
    let raw = "mkdir src && git init 2> err.txt && git add -A";
    assert!(contained_shape(raw, &project(raw).unwrap(), &ws).is_none());
}

#[test]
fn work_before_a_bootstrapped_init_is_sliced_from_the_raw_bytes() {
    let ws = fresh_workspace("bootstrap-prefix");
    let raw = "printf '.todo.json\\n__pycache__/\\n' > .gitignore && git init -b main -q && git add -A && git commit -qm 'Initial commit'";
    let shape = contained_shape(raw, &project(raw).unwrap(), &ws).unwrap();
    assert_eq!(
        shape.bootstrap.as_deref(),
        Some(&["-b".to_owned(), "main".to_owned(), "-q".to_owned()][..])
    );
    assert_eq!(
        shape.prefix.as_deref(),
        Some("printf '.todo.json\\n__pycache__/\\n' > .gitignore")
    );
    assert_eq!(
        shape.remainder.as_deref(),
        Some("git add -A && git commit -qm 'Initial commit'")
    );
    // Offsets count characters, not bytes, on both sides of the split.
    let raw = "printf 'caf\u{e9}' > a.txt  &&  echo \u{e9}t\u{e9} > b.txt && git init && cat a.txt > c.txt";
    let shape = contained_shape(raw, &project(raw).unwrap(), &ws).unwrap();
    assert_eq!(
        shape.prefix.as_deref(),
        Some("printf 'caf\u{e9}' > a.txt  &&  echo \u{e9}t\u{e9} > b.txt")
    );
    assert_eq!(shape.remainder.as_deref(), Some("cat a.txt > c.txt"));
    let raw = "cat <<'EOF' > notes.txt\nhello && git init\nEOF\ngit init";
    assert!(contained_shape(raw, &project(raw).unwrap(), &ws).is_none());
}

/// The execution sink plans the exact text the edge classified, pipes,
/// stderr folding and status reads included, so every such call the edge
/// sends to the workspace sandbox is one the plan accepts as issued.
#[cfg(unix)]
#[test]
fn the_sink_plans_every_wrapped_call_the_edge_contains() {
    use crate::pretool::workspace_contained_tests::{reason, workspace, CONTAINED};
    let ws = workspace("redirect-wrapped", true);
    for command in ["npm run build 2>&1", "npm run build 2>&1 | tail -20"] {
        assert!(
            crate::restricted_pytest::workspace_exact_shape(command, &ws).is_some(),
            "{command}"
        );
    }
    for command in [
        "npm run build 2>&1",
        "npm run build 2>&1 | tail -20",
        "npm run lint | head -50",
        "python3 app.py | tee log.txt",
        "npm run build; echo \"EXIT:$?\"",
        "python3 app.py 2>&1 | head -40; echo $?",
    ] {
        if reason("claude-code", command, &ws, true) == CONTAINED {
            assert!(
                crate::restricted_pytest::workspace_exact_shape(command, &ws).is_some(),
                "{command}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn the_sink_plans_package_directory_calls_whole_from_the_root() {
    use crate::pretool::workspace_contained_tests::workspace;
    let ws = workspace("package-directory", true);
    std::fs::create_dir_all(ws.join("web")).unwrap();
    std::fs::write(ws.join("web/package.json"), "{}").unwrap();
    for command in [
        "bun --cwd web run build",
        "yarn --cwd web test",
        "npm --prefix web run lint",
        "pnpm --dir=web run build 2>&1 | tail -20",
        "pnpm -C web run build",
        "npm -C web test",
    ] {
        // Planned whatever the host's containment, so the check never
        // depends on the edge classifying the call as contained first.
        assert!(
            crate::restricted_pytest::workspace_exact_shape(command, &ws).is_some(),
            "{command}"
        );
    }
}

/// The narrower sink refuses a relative `cd` inside the workspace, so the
/// edge neither peels it nor keeps the narrower profile for its redirect:
/// the workspace sandbox runs the text whole.
#[cfg(unix)]
#[test]
fn relative_in_workspace_cd_keeps_the_workspace_sandbox() {
    use crate::pretool::PathContext;
    // Below the build tree, as the temporary directory is a protected root
    // on macOS unless the workspace itself is proved private.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/narrower-sink-fixtures")
        .join(format!("relative-cd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project/web")).unwrap();
    let root = root.canonicalize().unwrap();
    let home = root.to_str().unwrap();
    let ws = root.join("project");
    let cwd = ws.to_str().unwrap();
    let context = PathContext {
        home_dir: Some(home),
        cwd: Some(cwd),
        cdpath_unset: true,
        ..PathContext::default()
    };
    let core = |raw: &str| {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: raw.to_owned(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        crate::pretool::contained_wrapper::contained_core(&model, context).is_some()
    };
    for raw in [
        "cd web && npm run build 2>&1 | tail -15",
        "cd ./web && npm run build 2>&1 | tail -15",
        "cd web && ./node_modules/.bin/vite build | tail -15",
    ] {
        assert!(!core(raw), "{raw}");
        assert!(!super::narrower_sink_runs(raw, context), "{raw}");
    }
    let absolute = format!("cd {cwd}/web && npm run build 2>&1 | tail -15");
    for raw in [absolute.as_str(), "npm run build 2>&1 | tail -15"] {
        assert!(core(raw), "{raw}");
        assert!(super::narrower_sink_runs(raw, context), "{raw}");
    }
}
