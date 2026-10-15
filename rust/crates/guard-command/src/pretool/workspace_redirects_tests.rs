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
