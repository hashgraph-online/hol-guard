//! Absolute paths that name a real file even where their top directory is
//! missing on this host. `/root` does not exist on macOS, yet a command aimed
//! at `/root/.ssh/authorized_keys` names another account's home on the host it
//! was written for, so it is never read as a URL-like pattern such as
//! `/api/v1`.

use std::path::Path;

/// Top directories that hold account homes on some supported platform.
const HOME_ROOTS: &[&str] = &["root", "home", "Users"];

/// Files a login or interactive shell runs on its own, wherever they sit.
const SHELL_STARTUP_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".bash_aliases",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".zshenv",
    ".kshrc",
    ".cshrc",
    ".tcshrc",
];

/// Whether an absolute path names an account home or a shell startup file,
/// which makes it a file system path whether or not its top directory exists.
pub(super) fn names_a_home_file(path: &Path) -> bool {
    let top = path.components().nth(1);
    top.is_some_and(|top| HOME_ROOTS.iter().any(|root| top.as_os_str() == *root))
        || path
            .file_name()
            .is_some_and(|file| SHELL_STARTUP_FILES.iter().any(|name| file == *name))
}

#[cfg(test)]
mod tests {
    use super::names_a_home_file;
    use std::path::Path;

    #[test]
    fn home_roots_and_startup_files_name_the_file_system() {
        for path in [
            "/root/.bashrc",
            "/root/.ssh/authorized_keys",
            "/root/.config/fish/config.fish",
            "/home/someone/.bash_aliases",
            "/Users/someone/notes.txt",
            "/missing-home/user/.zshrc",
        ] {
            assert!(names_a_home_file(Path::new(path)), "{path}");
        }
        for path in [
            "/api/v1",
            "/v2/users",
            "/rooted/file",
            "/homepage/index.html",
        ] {
            assert!(!names_a_home_file(Path::new(path)), "{path}");
        }
    }
}
