//! Which allowed steps may change the files a later step reads.
//!
//! A path proof reads the filesystem as it is before the command runs. An
//! earlier step can make that proof stale: `git checkout` can replace a
//! tracked file with a symlink to a credential, and `ln -sf` or `mv` can do
//! the same. A later read is judged on its own only when no earlier step it
//! follows can do that.

use super::executable_basename;

/// Programs that create, move, link, unpack or rewrite files, or that run
/// arbitrary code which can. A service CLI an extension names -- a model
/// runner or a client acting on remote state -- is not here.
const TREE_WRITERS: &[&str] = &[
    // File tools.
    "cp",
    "mv",
    "ln",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "install",
    "tee",
    "dd",
    "rsync",
    "scp",
    "sed",
    "perl",
    "awk",
    "gawk",
    "patch",
    "truncate",
    "chmod",
    "chown",
    "chgrp",
    "unlink",
    "link",
    "mktemp",
    "shred",
    // Archives.
    "tar",
    "unzip",
    "gunzip",
    "gzip",
    "bunzip2",
    "bzip2",
    "xz",
    "unxz",
    "zstd",
    "7z",
    "cpio",
    "ar",
    "jar",
    // Downloads that can write a file.
    "curl",
    "wget",
    "http",
    "xh",
    // Version control and hosting clients that check out trees.
    "hg",
    "svn",
    "jj",
    "gh",
    "glab",
    "repo",
    // Package managers, builds and runners.
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bun",
    "bunx",
    "deno",
    "pip",
    "pipx",
    "uv",
    "uvx",
    "poetry",
    "pdm",
    "conda",
    "mamba",
    "cargo",
    "rustup",
    "go",
    "gem",
    "bundle",
    "make",
    "cmake",
    "ninja",
    "gradle",
    "mvn",
    "ant",
    "composer",
    "dotnet",
    "nix",
    "brew",
    "terraform",
    "tofu",
    "pulumi",
    "ansible",
    "ansible-playbook",
    // Shells and interpreters.
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "env",
    "xargs",
    "eval",
    "exec",
    "source",
    ".",
    "python",
    "node",
    "nodejs",
    "ruby",
    "php",
    "lua",
    "osascript",
    // Containers that can bind-mount or copy into the work tree.
    "docker",
    "podman",
    "nerdctl",
    "docker-compose",
    "kubectl",
];

/// Whether `segment` may change files a later step reads. A Git step is safe
/// only when its verb rewrites nothing; a step with no executable is not.
pub(crate) fn may_rewrite_tree(segment: &crate::CommandSegmentV1) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return true;
    };
    let basename = executable_basename(executable);
    if basename == "git" {
        return !super::step_preserves_later_programs(segment);
    }
    // A case-insensitive file system runs `CHMOD` as `chmod`, and the
    // command matchers fold case too, so the name is folded before lookup.
    let folded = basename.to_ascii_lowercase();
    if folded == "git" {
        return true;
    }
    // Versioned names (`python3.12`, `pip3`) belong to the same program.
    let stem = folded.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    TREE_WRITERS.contains(&folded.as_str()) || TREE_WRITERS.contains(&stem)
}

#[cfg(test)]
mod tests {
    /// A case-insensitive file system runs `CHMOD` as `chmod`, so the folded
    /// name decides whether a step may rewrite the tree.
    #[test]
    fn a_tree_writer_is_recognized_in_any_letter_case() {
        for source in [
            "chmod -R 777 docs",
            "CHMOD -R 777 docs",
            "Rm -rf docs",
            "GIT checkout .",
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: source.to_owned(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .unwrap();
            assert!(super::may_rewrite_tree(&model.segments[0]), "{source}");
        }
    }
}
