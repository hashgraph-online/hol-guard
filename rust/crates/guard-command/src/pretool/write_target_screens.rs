//! Path screens shared by the bounded write proofs: autostart locations,
//! loader-visible libraries, the home-spelling check and plain dot-named
//! scratch paths outside the home root.

use std::path::{Component, Path, PathBuf};

pub(in crate::pretool) fn autostart_write_target(path: &std::path::Path) -> bool {
    let rendered = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = rendered
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    parts.windows(2).any(|pair| {
        matches!(
            pair,
            ["library", "launchagents"]
                | ["library", "launchdaemons"]
                | [".config", "autostart"]
                | [".config", "systemd"]
        )
    }) || parts
        .windows(3)
        .any(|parts| parts == ["start menu", "programs", "startup"])
}

/// A shared library or framework bundle the dynamic loader can pick up from
/// an exported search path such as `LD_LIBRARY_PATH` or `DYLD_LIBRARY_PATH`:
/// `libz.so`, `libz.so.1.3`, `libz.dylib`, `z.dll` or a `.framework` bundle.
/// The caller applies this to the written filename. A parent directory named
/// `project.so` does not make an ordinary child a library. A file inside a
/// `.framework` bundle stays a bundle member because the loader reads the bundle.
pub(super) fn shared_library_part(part: &str) -> bool {
    part.ends_with(".dylib")
        || part.ends_with(".dll")
        || part.ends_with(".framework")
        || part.rsplit_once(".so").is_some_and(|(stem, version)| {
            !stem.is_empty()
                && version
                    .split('.')
                    .all(|piece| piece.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

pub(in crate::pretool) fn home_spelling_matches_target(
    target: &std::path::Path,
    canonical: &std::path::Path,
    supplied_home: Option<&str>,
    canonical_home: &std::path::Path,
) -> bool {
    let relative = target.strip_prefix(canonical_home).ok().or_else(|| {
        supplied_home.and_then(|home| target.strip_prefix(std::path::Path::new(home)).ok())
    });
    relative.is_some_and(|relative| canonical_home.join(relative) == canonical)
}

/// Hidden names a write must not create or change even outside the home
/// root. Each one runs or redirects tooling without an explicit command:
/// git internals and hooks, CI and editor tasks, package-manager and
/// interpreter selection, environment loaders, agent harness configuration
/// and credential stores. Harness directories are prefixes so variants such
/// as `.zcode-plugin`, `.clinerules` or `.vscode-insiders` stay guarded; some
/// harnesses load code from them on start (`.opencode/plugins/*.ts`).
const GUARDED_DOT_NAMES: &[&str] = &[
    ".agent",
    ".agents",
    ".aws",
    ".bin",
    ".buildkite",
    ".cargo",
    ".circleci",
    ".config",
    ".continue",
    ".devcontainer",
    ".direnv",
    ".docker",
    ".fleet",
    ".forgejo",
    ".gnupg",
    ".hg",
    ".hol-guard",
    ".hol-support",
    ".hooks",
    ".husky",
    ".idea",
    ".jj",
    ".kube",
    ".local",
    ".netrc",
    ".node-version",
    ".npm",
    ".nvmrc",
    ".omp",
    ".pi",
    ".python-version",
    ".ruby-version",
    ".ssh",
    ".svn",
    ".tool-versions",
    ".venv",
    ".yarn",
    ".zed",
];
const GUARDED_DOT_PREFIXES: &[&str] = &[
    ".aider",
    ".amazonq",
    ".antigravity",
    ".augment",
    ".bunfig",
    ".claude",
    ".cline",
    ".codex",
    ".copilot",
    ".crush",
    ".cursor",
    ".devin",
    ".env",
    ".gemini",
    ".git",
    ".goose",
    ".grok",
    ".hermes",
    ".junie",
    ".kimi",
    ".kiro",
    ".lefthook",
    ".mcp",
    ".mise",
    ".npmrc",
    ".openclaw",
    ".opencode",
    ".openhands",
    ".overcommit",
    ".paseo",
    ".pnp",
    ".pre-commit",
    ".pypirc",
    ".qwen",
    ".roo",
    ".trae",
    ".vscode",
    ".windsurf",
    ".yarnrc",
    ".zcode",
];

/// Hidden directories a write may pass through. Any other dot directory can
/// be configuration some tool loads on its own, such as a new agent's rules
/// folder, so it stays reviewed.
const SCRATCH_DOT_DIRECTORIES: &[&str] = &[".scratch", ".temp", ".tmp"];

/// Build and cache output a framework regenerates and a repository ignores.
/// None of these directories is read as configuration, so writing a build
/// result into one is the same work as writing into `dist`.
const BUILD_OUTPUT_DOT_DIRECTORIES: &[&str] = &[
    ".angular",
    ".astro",
    ".docusaurus",
    ".next",
    ".nuxt",
    ".output",
    ".parcel-cache",
    ".svelte-kit",
    ".turbo",
];

/// Tool caches installed packages keep inside `node_modules`. Only that
/// parent makes them cache directories; the same name elsewhere stays reviewed.
const NODE_MODULES_DOT_DIRECTORIES: &[&str] = &[".cache", ".vite", ".vite-temp"];

/// Whether a hidden directory holds scratch or regenerated build output.
fn regenerated_dot_directory(lowered: &str, in_node_modules: bool) -> bool {
    SCRATCH_DOT_DIRECTORIES.contains(&lowered)
        || BUILD_OUTPUT_DOT_DIRECTORIES.contains(&lowered)
        || (in_node_modules && NODE_MODULES_DOT_DIRECTORIES.contains(&lowered))
}

/// A write whose hidden components are plain scratch names, such as
/// `.tmp/check.mjs` or `.write-test` in a sibling checkout. No hidden
/// component may sit directly in the home directory, where dot names are
/// shell, tool and agent configuration, nor at or above the home, and none
/// may be a guarded name. The caller has already bounded the path to the
/// workspace, a linked worktree or the home.
pub(super) fn plain_dot_scratch_target(path: &Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|home| std::fs::canonicalize(home).ok()) else {
        return false;
    };
    let mut parent = PathBuf::new();
    let mut hidden = false;
    let components: Vec<Component<'_>> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        if let Component::Normal(name) = component {
            let Some(name) = name.to_str() else {
                return false;
            };
            if name.starts_with('.') {
                hidden = true;
                let lowered = name.to_ascii_lowercase();
                let directory = index + 1 < components.len();
                let in_node_modules = parent
                    .file_name()
                    .is_some_and(|last| last == "node_modules");
                if home.starts_with(&parent)
                    || (directory && !regenerated_dot_directory(&lowered, in_node_modules))
                    || GUARDED_DOT_NAMES.contains(&lowered.as_str())
                    || GUARDED_DOT_PREFIXES
                        .iter()
                        .any(|prefix| lowered.starts_with(prefix))
                {
                    return false;
                }
            }
        }
        parent.push(component.as_os_str());
    }
    hidden
}

pub(super) fn home_execution_control_target(
    path: &std::path::Path,
    home: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    if path.starts_with(workspace) {
        return false;
    }
    let parts: Vec<String> = path
        .strip_prefix(home)
        .ok()
        .into_iter()
        .flat_map(std::path::Path::components)
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    let shared_library = parts.last().is_some_and(|part| shared_library_part(part))
        || parts.iter().any(|part| part.ends_with(".framework"));
    parts.iter().any(|part| {
        matches!(part.as_str(), "bin" | "appdata" | "site-packages" | "dist-packages")
            || part.ends_with(".pth")
            || matches!(part.as_str(), "sitecustomize.py" | "usercustomize.py")
    }) || shared_library
        || parts.windows(2).any(|pair| {
        matches!(
            pair,
            [first, second]
                if first == "library"
                    && matches!(second.as_str(), "application support" | "application scripts" | "python")
                    || (first == ".local" && second == "bin")
                    || (first == ".github" && second == "workflows")
        )
    })
}
