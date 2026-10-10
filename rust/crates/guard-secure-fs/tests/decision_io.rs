use guard_secure_fs::{read_bounded, SecureReadError};
use std::fs::{self, OpenOptions};
use std::io::Write;

fn fixture_root(name: &str) -> std::path::PathBuf {
    let temporary_root =
        fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
}

#[test]
fn bounded_read_rejects_truncation_limit_before_materializing_more_bytes() {
    let dir = fixture_root("truncation");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"0123456789").unwrap();

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bounded_read_rejects_source_growth_beyond_limit() {
    let dir = fixture_root("growth");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b" growth").unwrap();
    drop(file);

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn omp_skill_sources_keep_sensitive_and_hidden_path_floors() {
    use guard_secure_fs::classify_scannable_source_path;
    let dir = fixture_root("omp-skill");
    let home = dir.join("home");
    let cwd = dir.join("workspace");
    let skill = home.join(".agent/skills/example/SKILL.md");
    fs::create_dir_all(skill.parent().unwrap()).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&skill, "inert reference").unwrap();
    assert!(
        classify_scannable_source_path(skill.to_str().unwrap(), &cwd, Some(&home), true).allowed
    );
    for relative in [
        ".agent/auth.json",
        ".agent/skills/example/.env",
        ".agent/skills/example/../secret.txt",
    ] {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "synthetic sensitive fixture").unwrap();
        assert!(
            !classify_scannable_source_path(path.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed
        );
    }
    #[cfg(unix)]
    {
        let link = home.join(".agent/skills/example/linked.md");
        std::os::unix::fs::symlink(&skill, &link).unwrap();
        assert!(
            !classify_scannable_source_path(link.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
