//! What a process marker inside a repository's own hidden tree is allowed
//! to be: a file named for a marker, holding one short number. Both halves
//! are load-bearing, so the cases that fail either one sit here beside the
//! ones that pass.

use super::*;

/// A marker a running process left behind carries no document extension, so
/// that screen refuses it. Asking who holds a lock is ordinary work.
#[test]
fn a_repositorys_own_process_markers_read_from_hidden_directories() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    for (marker, body) in [
        (".deploy-production.lock.d/pid", "48213\n"),
        (".cache/dev-server/port", "3017"),
        (".turbo/generation", " 12 \n"),
        // The name may say what the marker belongs to instead of standing
        // alone, which is how a server writes its own.
        (".cache/dev-server/vite.port", "5173\n"),
        (".state/web.pid", "48213"),
    ] {
        plant(&repo.join(marker), body);
        assert!(read(&repo.join(marker), &home, &repo), "{marker}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// The name and the number are both the proof, and a file that fails either
/// one keeps the review it already had.
#[test]
fn a_hidden_file_that_is_not_a_process_marker_keeps_its_review() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    // A line of digits is a marker; a page of them is something else.
    let long = "7".repeat(65);
    // A 128-bit key written in decimal is 39 digits, and a PIN, a TOTP or a
    // recovery code is shorter still. Digits alone prove nothing, so the
    // name has to say a process wrote the file.
    let decimal_key = "3".repeat(39);
    for (name, body) in [
        // Named for nothing a process leaves behind, so the digits inside
        // stay unread however plain they look.
        (".cache/otp", "483921\n"),
        (".private/recovery", "8172635401\n"),
        (".state/account", "4024007182693012\n"),
        // Named for a marker, holding something no marker holds: a word
        // beside the number, a word instead of one, nothing at all, a number
        // no process counts to, and a page of digits.
        (".state/holder.pid", "pid 48213\n"),
        (".state/owner.pid", "deploy\n"),
        (".state/boot.pid", ""),
        (".state/service.pid", decimal_key.as_str()),
        (".state/dump.pid", long.as_str()),
    ] {
        plant(&repo.join(name), body);
        assert!(!read(&repo.join(name), &home, &repo), "{name}");
    }
    // Every other screen still runs: a marker inside a credential store, and
    // one in a sibling checkout the session is not working in, keep their
    // review.
    plant(&repo.join(".aws/sso/cache/pid"), "48213\n");
    assert!(!read(&repo.join(".aws/sso/cache/pid"), &home, &repo));
    let other = home.join("other");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    plant(&other.join(".deploy.lock.d/pid"), "48213\n");
    assert!(!read(&other.join(".deploy.lock.d/pid"), &home, &repo));
    std::fs::remove_dir_all(root).unwrap();
}
