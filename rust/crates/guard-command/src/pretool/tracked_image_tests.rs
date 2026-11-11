//! Committed screenshots named for the screen they show, such as
//! `auth-login.png`, pass a recursive search's walk only as plain PNGs whose
//! text chunks the secret detector clears.
use super::tests::{fixture, write_index};
use super::*;
use std::path::PathBuf;

const SHOT: &str = "docs/guard/artifacts/auth-desktop-login.png";

/// A PNG of `chunks`, closed by `IEND`. Readers here skip the CRCs.
fn png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let iend: (&[u8; 4], &[u8]) = (b"IEND", b"");
    for (kind, data) in chunks.iter().chain([&iend]) {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(*kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&[0; 4]);
    }
    bytes
}

/// What macOS writes for a screenshot: pixels, a density and XMP metadata.
fn screenshot() -> Vec<u8> {
    png(&[
        (b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
        (b"pHYs", &[0, 0, 22, 37, 0, 0, 22, 37, 1]),
        (
            b"iTXt",
            b"XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta><exif:UserComment>Screenshot</exif:UserComment></x:xmpmeta>",
        ),
        (b"IDAT", &[0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 5, 0xfe, 2, 0xfe]),
    ])
}

fn tracked(project: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = project.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_tracked_screenshot_named_for_a_login_screen_is_proven() {
    let (_, project) = fixture();
    let shot = tracked(&project, SHOT, &screenshot());
    write_index(&project.join(".git"), &[SHOT]);
    assert!(guard_secure_fs::credential_named_path(&shot));
    assert!(committed_image(&shot));
}

#[test]
fn untracked_disguised_or_stored_images_keep_review() {
    let (_, project) = fixture();
    let untracked = tracked(&project, SHOT, &screenshot());
    write_index(&project.join(".git"), &[]);
    assert!(!committed_image(&untracked));

    let (_, project) = fixture();
    let text = "docs/auth-token.png";
    let jpeg = "docs/auth-login.jpg";
    let stored = "docs/secrets/auth-login.png";
    tracked(&project, text, b"token = example\n");
    tracked(&project, jpeg, &[0xff, 0xd8, 0xff, 0xe0, 0, 0]);
    tracked(&project, stored, &screenshot());
    write_index(&project.join(".git"), &[text, jpeg, stored]);
    for name in [text, jpeg, stored] {
        assert!(!committed_image(&project.join(name)), "{name}");
    }
}

/// `grep -a` prints whatever text an image carries, so every chunk must be
/// one the format defines and every text chunk must be readable and clean.
#[test]
fn images_carrying_text_the_walk_cannot_clear_keep_review() {
    let header: (&[u8; 4], &[u8]) = (b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
    let key = concat!(
        "-----BEGIN RSA PRIVATE",
        " KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n"
    );
    let mut secret = b"Comment\0".to_vec();
    secret.extend_from_slice(key.as_bytes());
    let mut trailing = screenshot();
    trailing.extend_from_slice(key.as_bytes());
    let cases: [(&str, Vec<u8>); 4] = [
        ("private chunk", png(&[header, (b"prVt", key.as_bytes())])),
        (
            "compressed text",
            png(&[header, (b"iTXt", b"Comment\0\x01\0\0\0x\x9c")]),
        ),
        ("key in a text chunk", png(&[header, (b"tEXt", &secret)])),
        ("bytes after IEND", trailing),
    ];
    for (label, bytes) in cases {
        let (_, project) = fixture();
        let shot = tracked(&project, SHOT, &bytes);
        write_index(&project.join(".git"), &[SHOT]);
        assert!(!committed_image(&shot), "{label}");
    }
}

/// A recursive grep over a docs tree holding a committed screenshot is
/// decided as it is without one, in text mode too. An untracked capture of the
/// same name keeps the review.
#[cfg(unix)]
#[test]
fn a_recursive_grep_walks_past_a_tracked_screenshot() {
    use super::tests::{bash, hook};
    let decide = |image: Option<bool>, command: &str| {
        let (home, project) = fixture();
        tracked(&project, "docs/phase-e-schema.md", b"# Phase E schema\n");
        let mut names = vec!["docs/phase-e-schema.md"];
        if let Some(listed) = image {
            tracked(&project, SHOT, &screenshot());
            if listed {
                names.push(SHOT);
            }
        }
        write_index(&project.join(".git"), &names);
        let result = hook(bash(command), &home, &project);
        (result.reason_code, result.minimum_action)
    };
    for command in ["grep -rln Phase docs", "grep -a -rn Phase docs"] {
        let plain = decide(None, command);
        assert_eq!(decide(Some(true), command), plain, "{command}");
        assert_ne!(decide(Some(false), command), plain, "{command}");
    }
}
