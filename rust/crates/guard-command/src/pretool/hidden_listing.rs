//! `ls` of a hidden directory or file inside a repository work tree, such as a deploy
//! lock directory or the `.git` marker an agent probes for. Listing returns
//! names, not file content. Credential stores and agent state keep their
//! guard, and the repository root must clear every sensitive-path screen.

use std::path::{Component, Path};

#[path = "home_hidden_listing.rs"]
mod home;
pub(in crate::pretool) use home::{
    home_hidden_content_read, home_hidden_directory, home_hidden_tool_directory,
    home_hidden_walk_clears_stores, resolved_home_hidden_content_read,
    resolved_home_hidden_listing,
};

/// Agent state and tool trees whose entry names reveal agent state inside a
/// repository. Credential stores and harness homes come from the shared home
/// lists.
const AGENT_STATE_NAMES: [&str; 5] = [".agent", ".agents", ".config", ".local", ".npm"];

fn guarded_hidden_name(name: &str) -> bool {
    AGENT_STATE_NAMES.contains(&name)
        || home::CREDENTIAL_STORE_NAMES.contains(&name)
        || home::HARNESS_HOME_NAMES.contains(&name)
        || name.starts_with(".env")
}

/// Whether `value` names an existing directory below a hidden component that
/// sits inside a repository work tree the session may already read.
pub(in crate::pretool) fn repository_hidden_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let path = value.trim();
    if path.is_empty()
        || path.len() > 4096
        || path.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '{', '}', '[', ']',
        ])
        || path.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    let expanded = super::expand_home_read_path(path, home_dir).unwrap_or_else(|| path.to_owned());
    let expanded = Path::new(&expanded);
    let candidate = if expanded.is_absolute() {
        expanded.to_path_buf()
    } else if let Some(root) = cwd.filter(|root| Path::new(root).is_absolute()) {
        Path::new(root).join(expanded)
    } else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(candidate) else {
        return false;
    };
    // A listing prints names and metadata only, so an existing regular file
    // is as safe as a directory under the same screens.
    if !canonical.is_dir() && !canonical.is_file() {
        return false;
    }
    repository_hidden_below(&canonical, home_dir, cwd, false)
}

/// Whether `canonical` names an existing document of the repository's own
/// content that happens to sit below a hidden directory.
///
/// A checkout keeps real content in hidden directories: `.codex-plugin` and
/// `.claude-plugin` hold the manifest a plugin is read from, `.well-known`
/// holds an agent card, `.github` holds the workflows. Reading one is
/// ordinary work, and the screens that make a hidden *listing* safe make the
/// read safe too, with two additions. The repository's own `.git` tree is
/// administrative, not content — it holds remote URLs, rebase author scripts
/// and hook bodies — so a content read never reaches it. And the name has to
/// carry a document extension, which keeps the rule off the compiled
/// programs, archives and key material that also live under hidden
/// directories.
///
/// This is deliberately a property of the path rather than a list of
/// directory names: the next harness to invent a dot-directory for its
/// manifest needs no change here.
pub(in crate::pretool) fn repository_hidden_source_document(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    canonical.is_file()
        && guard_secure_fs::source_document_extension(canonical)
        && repository_hidden_below(canonical, home_dir, cwd, true)
}

/// Directories a repository publishes a plugin manifest from. Neither is a
/// harness directory: a harness loads a plugin the user installed, never the
/// manifest of the checkout it is working in.
const PLUGIN_MANIFEST_DIRECTORIES: [&str; 2] = [".claude-plugin", ".codex-plugin"];

/// Whether an edit to `canonical` changes a plugin manifest the repository
/// publishes, such as `.claude-plugin/plugin.json`. Every screen of the hidden
/// content read applies, and a plugin directory is the only hidden component
/// allowed below the repository, so a file a tool runs from, such as
/// `.vscode/tasks.json` or `.cargo/config.toml`, keeps its review.
pub(in crate::pretool) fn repository_plugin_manifest(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    repository_hidden_source_document(canonical, home_dir, cwd)
        && enclosing_work_tree(canonical, home_dir)
            .and_then(|repository| names_below(repository, canonical))
            .and_then(|names| {
                let (leaf, parents) = names.split_last()?;
                Some(plugin_manifest_names(leaf, parents))
            })
            .unwrap_or(false)
}

/// The files a plugin directory holds as its manifest: the plugin's own and
/// the marketplace listing that names it.
const PLUGIN_MANIFEST_NAMES: [&str; 2] = ["plugin.json", "marketplace.json"];

/// Whether the names below a repository spell a plugin manifest, directly
/// inside a plugin directory with no other hidden component above it. A
/// script or another JSON file beside the manifest is not one.
fn plugin_manifest_names(leaf: &str, parents: &[String]) -> bool {
    PLUGIN_MANIFEST_NAMES.contains(&leaf)
        && parents.split_last().is_some_and(|(directory, above)| {
            PLUGIN_MANIFEST_DIRECTORIES.contains(&directory.as_str())
                && !above.iter().any(|name| name.starts_with('.'))
        })
}

/// The lowercased names of `canonical` below `repository`, when every one is
/// a plain component.
fn names_below(repository: &Path, canonical: &Path) -> Option<Vec<String>> {
    canonical
        .strip_prefix(repository)
        .ok()?
        .components()
        .map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// The screens shared by the hidden listing and the hidden content read: the
/// path sits below a hidden component inside a repository work tree, and no
/// component below that repository names agent state, a credential store, a
/// harness home or an environment file.
///
/// `content_read` adds what naming a file rather than a directory needs: the
/// repository's own administrative tree stays out, the hidden component has to
/// be a directory above the file, and the names a tool keeps its logins under
/// keep their review.
fn repository_hidden_below(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    content_read: bool,
) -> bool {
    // The work tree is searched from the path itself rather than from the
    // outermost hidden component above it: a checkout may sit below a hidden
    // directory of its own, as `~/.workspace/app` does, and the repository is
    // then the one nearest the path, never whatever encloses `.workspace`.
    let Some(repository) = enclosing_work_tree(canonical, home_dir) else {
        return false;
    };
    // A repository at or above the home directory is a dotfiles checkout, and
    // reading it as "the repository's own content" would hand over every
    // dotfile in the home directory. The rule is about a checkout an agent
    // works in, which always sits below home.
    let Some(home) = home_dir.and_then(|value| std::fs::canonicalize(value).ok()) else {
        return false;
    };
    if home.starts_with(repository) {
        return false;
    }
    // A work tree keeps its administrative directory in `.git`, but a `.git`
    // file names that directory somewhere else, and `--separate-git-dir` is
    // free to put it inside the work tree under a name of its own. The hook
    // bodies, author scripts and remote URLs in it are then reachable by a
    // path that never spells `.git`, so the pointer is read rather than the
    // name trusted.
    if content_read && administrative_tree_holds(repository, canonical) {
        return false;
    }
    let Some(names) = names_below(repository, canonical) else {
        return false;
    };
    let Some((leaf, parents)) = names.split_last() else {
        return false;
    };
    let manifest = plugin_manifest_names(leaf, parents);
    if content_read && !working_in(repository, &home, home_dir, cwd, manifest) {
        return false;
    }
    if names
        .iter()
        .any(|name| guarded_hidden_name(name) || (content_read && name.as_str() == ".git"))
    {
        return false;
    }
    // A listing names the entries of a directory, so the hidden component may
    // be the entry itself. A content read is the repository's own document
    // *under* a hidden directory: a hidden file at the leaf of a work tree is
    // `hidden_project_document`'s territory, which applies the full screens
    // over its name, so `.mcp.json` keeps its review here.
    let hidden_parent = parents.iter().any(|name| name.starts_with('.'));
    let hidden_component = hidden_parent || leaf.starts_with('.');
    let hidden_below = if content_read {
        hidden_parent
    } else {
        hidden_component
    };
    if !hidden_below {
        return false;
    }
    if content_read && !content_names_allowed(canonical, leaf, parents) {
        return false;
    }
    guard_secure_fs::sensitive_path_family(canonical).is_none()
        && !guard_secure_fs::credential_named_path(canonical)
        && repository_location_allowed(repository, &home, home_dir, cwd)
}

/// Whether the session is working inside `repository`.
///
/// A content read opens the checkout the session is in. A sibling checkout's
/// hidden tree keeps its review: a developer's own `.private` notes sit beside
/// code exactly as a published manifest does, and nothing in the path tells
/// the two apart. A listing is not held to this — it prints names, and reading
/// the entries of a sibling's `node_modules/.bin` is ordinary work.
///
/// The test is the checkout the working directory itself belongs to, not mere
/// containment. Containment answers the wrong question at both ends: a
/// submodule or a vendored checkout inside the session's own tree would be
/// refused, although the document sits in the tree the session opened, and a
/// session working in a nested checkout would reach the enclosing repository's
/// hidden notes — exactly the sibling content this screen holds back. So the
/// work tree nearest the working directory has to be the file's repository, or
/// an ancestor of it.
///
/// A plugin manifest in a linked worktree of that same repository, which
/// `git worktree add` often puts in a temporary directory, belongs to the
/// repository checked out elsewhere rather than a sibling. Other hidden
/// documents there, such as `.private/notes.md`, keep the sibling review.
/// Git's common directory and the worktree's registered backlink have to
/// agree, so a stray `.git` file cannot nominate a directory.
fn working_in(
    repository: &Path,
    home: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    manifest: bool,
) -> bool {
    let Some(cwd) = cwd.and_then(|value| std::fs::canonicalize(value).ok()) else {
        return false;
    };
    let Some(tree) = work_tree_from(&cwd, home_dir) else {
        return false;
    };
    // A dotfiles checkout at or above the home directory is not a checkout an
    // agent works in. Reading it as one would make every repository below home
    // the session's own tree.
    if home.starts_with(tree) {
        return false;
    }
    repository.starts_with(tree)
        || (manifest && crate::pretool::worktree_writes::same_repository_worktree(tree, repository))
}

/// What the repository's own path has to clear.
///
/// Not the hidden-component screen: a checkout may sit below a hidden
/// directory of the developer's own, as `~/.workspace/app` does, and that
/// screen refuses such a path on sight. What matters is where the checkout is
/// — a system root, another user's home, a sensitive family, a
/// credential-named path — and that no component of it below the home
/// directory names agent state, a credential store, a harness home or an
/// environment file.
fn repository_location_allowed(
    repository: &Path,
    home: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if let Ok(below) = repository.strip_prefix(home) {
        let guarded = below.components().any(|component| match component {
            Component::Normal(name) => {
                guarded_hidden_name(&name.to_string_lossy().to_ascii_lowercase())
            }
            _ => true,
        });
        if guarded {
            return false;
        }
    }
    // A checkout in the user's private temporary directory sits below
    // `/private/var`, which is the user's own work rather than system state.
    let temporary = super::inside_private_temporary_directory(repository, home_dir);
    super::resolved_location_allowed(repository, home_dir, cwd, temporary)
}

/// The name screens a content read adds over the components below the
/// repository.
///
/// A directory spelled like an ordinary config file opens no tree, which is
/// the rule `BENIGN_PROJECT_DOTFILES` already states; a directory spelled
/// exactly as a tool's name is that tool's own tree rather than the
/// repository's content; and the leaf keeps the secret screen, plus as much
/// of the login screen as a file in the checkout's own content can carry. `credential_named_path` stands
/// aside for source-code extensions, so the directory half of that screen is
/// applied here in its own right.
fn content_names_allowed(canonical: &Path, leaf: &str, parents: &[String]) -> bool {
    !parents.iter().any(|parent| {
        guard_secure_fs::project_config_file_name(parent)
            || guard_secure_fs::tool_login_name(parent)
    }) && !leaf_names_a_tools_login(leaf)
        && !guard_secure_fs::credential_store_names::secret_bearing_file_name(
            leaf.trim_start_matches('.'),
        )
        && !guard_secure_fs::credential_directory_path(canonical)
}

/// A hidden leaf keeps the whole tool-login screen: `.config/.claude.json`
/// is that tool's own file wherever it sits. A plain leaf keeps the login-file
/// half only, because a repository names its own documents after the tools it
/// uses -- `.github/workflows/docker.yml`, `.well-known/agent.json` -- and
/// reading a vendor's name in those as a login puts back the very reviews this
/// screen exists to lift. The login names that are a file's whole name, `mcp`
/// and `npmrc` among them, still reject `.next/mcp.json`.
fn leaf_names_a_tools_login(leaf: &str) -> bool {
    if leaf.starts_with('.') {
        return guard_secure_fs::tool_login_name(leaf);
    }
    guard_secure_fs::tool_login_file_name(leaf)
}

fn enclosing_work_tree<'a>(path: &'a Path, home_dir: Option<&str>) -> Option<&'a Path> {
    work_tree_from(path.parent()?, home_dir)
}

/// The work tree nearest `directory`, `directory` itself included. The search
/// stays below the home directory or below a temporary root, where
/// `git worktree add` puts many checkouts, and never reaches either root.
fn work_tree_from<'a>(directory: &'a Path, home_dir: Option<&str>) -> Option<&'a Path> {
    if work_tree_marker(directory) {
        return Some(directory);
    }
    let home = std::fs::canonicalize(home_dir?).ok()?;
    directory
        .ancestors()
        .skip(1)
        .take_while(|ancestor| {
            (ancestor.starts_with(&home) && *ancestor != home.as_path())
                || below_temporary_root(ancestor, home_dir)
        })
        .find(|ancestor| work_tree_marker(ancestor))
}

fn below_temporary_root(directory: &Path, home_dir: Option<&str>) -> bool {
    super::inside_private_temporary_directory(directory, home_dir)
        || ["/tmp", "/private/tmp"]
            .iter()
            .any(|root| directory.starts_with(root) && directory != Path::new(root))
}

fn work_tree_marker(directory: &Path) -> bool {
    std::fs::symlink_metadata(directory.join(".git")).is_ok()
}

/// Whether `canonical` sits inside the administrative directory a `.git`
/// *file* or symlink at the root of `repository` points at.
///
/// A work tree whose `.git` is a directory is answered by the component screen
/// above and never reaches here. A pointer this rule cannot read in full, or
/// cannot parse, holds the read: the administrative directory is then unknown,
/// and an unknown one cannot be shown to be elsewhere.
fn administrative_tree_holds(repository: &Path, canonical: &Path) -> bool {
    use std::io::Read;

    let pointer = repository.join(".git");
    let Ok(metadata) = std::fs::symlink_metadata(&pointer) else {
        return false;
    };
    // Git also accepts `.git` as a *symlink* to the administrative directory;
    // `repo` and `git-new-workdir` both lay a checkout out that way. The
    // canonical read path then spells the target's name rather than `.git`, so
    // the component screen above never sees it and this rule resolves the link
    // itself. A link to anything but a directory, or one that cannot be
    // resolved, leaves the administrative directory unknown, and an unknown
    // one cannot be shown to be elsewhere.
    if metadata.file_type().is_symlink() {
        return match std::fs::canonicalize(&pointer) {
            Ok(target) if target.is_dir() => canonical.starts_with(target),
            _ => true,
        };
    }
    if !metadata.is_file() {
        return false;
    }
    if metadata.len() > 1024 {
        return true;
    }
    let mut content = String::new();
    if std::fs::File::open(&pointer)
        .and_then(|file| file.take(1025).read_to_string(&mut content))
        .is_err()
    {
        return true;
    }
    let line = content.strip_suffix('\n').unwrap_or(&content);
    let Some(target) = line.strip_prefix("gitdir: ") else {
        return true;
    };
    if target.is_empty() || target.contains(['\n', '\r', '\0']) {
        return true;
    }
    let target = Path::new(target);
    let resolved = if target.is_absolute() {
        std::fs::canonicalize(target)
    } else {
        std::fs::canonicalize(repository.join(target))
    };
    // A pointer at a directory that does not exist names nothing this read can
    // reach, so it holds nothing back.
    resolved.is_ok_and(|resolved| canonical.starts_with(resolved))
}

#[cfg(test)]
#[cfg(unix)]
#[path = "hidden_listing_temp_tests.rs"]
mod temp_tests;
