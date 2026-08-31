use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{contains_symlink_component, resolve_candidate, SourcePathDecision};

const SOURCE_INSPECTION_PARTS: &[&str] = &[
    "__tests__",
    "app",
    "constants",
    "dashboard",
    "docs",
    "lib",
    "packages",
    "scripts",
    "src",
    "test",
    "tests",
    "workers",
];
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "css", "go", "h", "hpp", "html", "java", "js", "jsx", "json", "md", "mjs",
    "py", "rs", "sh", "toml", "ts", "tsx", "yaml", "yml",
];
const BENIGN_SOURCE_DOTFILES: &[&str] = &[".nvmrc", ".worktrees"];
const SENSITIVE_SEARCH_BASENAMES: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "credentials",
    "id_rsa",
];
const EXTERNAL_SENSITIVE_PARTS: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
];
const KNOWN_SKILL_DOC_ROOTS: &[&str] = &[
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
];

fn lowered_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn hidden_parts_allowed(parts: &[String]) -> bool {
    let hidden: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| part.starts_with('.'))
        .collect();
    if hidden.is_empty()
        || hidden
            .iter()
            .all(|part| BENIGN_SOURCE_DOTFILES.contains(part))
    {
        return true;
    }
    let workflow_prefix = parts
        .windows(2)
        .any(|window| window[0] == ".github" && window[1] == "workflows");
    workflow_prefix && hidden == [".github"]
}

fn sensitive_external_filename(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if EXTERNAL_SENSITIVE_PARTS.contains(&filename.as_str())
        || EXTERNAL_SENSITIVE_PARTS.contains(&stem.as_str())
    {
        return true;
    }
    stem.replace(['-', '.'], "_")
        .split('_')
        .any(|token| !token.is_empty() && EXTERNAL_SENSITIVE_PARTS.contains(&token))
}

fn source_shape_allowed(path: &Path, parts: &[String]) -> bool {
    parts
        .iter()
        .any(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
        || path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| {
                let lowered = name.to_ascii_lowercase();
                BENIGN_SOURCE_DOTFILES.contains(&lowered.as_str())
            })
        || path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .is_some_and(|suffix| SOURCE_EXTENSIONS.contains(&suffix.as_str()))
}

fn canonical_dir(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path)
        .ok()
        .and_then(|canonical| canonical.is_dir().then_some(canonical))
}

fn immediate_sibling_git_checkout(path: &Path, workspace: &Path) -> bool {
    let parent = match workspace.parent() {
        Some(parent) => parent,
        None => return false,
    };
    let relative = match path.strip_prefix(parent) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    let Component::Normal(first) = first else {
        return false;
    };
    let checkout = parent.join(first);
    if checkout == workspace {
        return false;
    }
    fs::symlink_metadata(checkout.join(".git")).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir())
    })
}

fn known_skill_doc_path(target: &str, home: &Path) -> Option<PathBuf> {
    if target
        .chars()
        .any(|character| matches!(character, '$' | '`' | '<' | '>' | '|' | ';' | '&'))
    {
        return None;
    }
    if let Some(skill_name) = target.strip_prefix("skill://") {
        let skill_name = skill_name.trim().trim_matches(['\'', '"']);
        let candidate = Path::new(skill_name);
        if skill_name.is_empty()
            || candidate.is_absolute()
            || candidate
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return None;
        }
        for root in KNOWN_SKILL_DOC_ROOTS {
            let skill_dir = home.join(root).join(candidate);
            let skill_file = skill_dir.join("SKILL.md");
            let Ok(real_dir) = fs::canonicalize(&skill_dir) else {
                continue;
            };
            let Ok(real_file) = fs::canonicalize(&skill_file) else {
                continue;
            };
            if real_file.is_file() && real_file.starts_with(&real_dir) {
                return Some(real_file);
            }
        }
        return None;
    }

    let lexical = resolve_candidate(target, None, home).ok()?;
    for root in KNOWN_SKILL_DOC_ROOTS {
        let lexical_root = home.join(root);
        if !lexical.starts_with(&lexical_root) || contains_symlink_component(&lexical) {
            continue;
        }
        if let Ok(real) = fs::canonicalize(&lexical) {
            return Some(real);
        }
    }
    None
}

pub fn classify_source_path(
    target: &str,
    cwd: &Path,
    home: Option<&Path>,
    allow_external: bool,
) -> SourcePathDecision {
    let stripped = target.trim().trim_matches(['\'', '"']);
    if stripped.is_empty() {
        return SourcePathDecision::deny("empty_path");
    }
    let lexical_path = Path::new(stripped);
    if lexical_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return SourcePathDecision::deny("path_traversal");
    }
    if stripped
        .chars()
        .any(|character| matches!(character, '*' | '?' | '{' | '}'))
    {
        return SourcePathDecision::deny("glob_pattern");
    }
    let lexical_parts = lowered_parts(lexical_path);
    if sensitive_path_family(lexical_path).is_some()
        || lexical_parts
            .iter()
            .any(|part| SENSITIVE_SEARCH_BASENAMES.contains(&part.as_str()))
    {
        return SourcePathDecision::deny("sensitive_basename");
    }
    if let Some(home) = home {
        if let Some(skill_path) = known_skill_doc_path(stripped, home) {
            return SourcePathDecision::allow("known_skill_doc_path", skill_path);
        }
        let safety = home.join(".hol-support").join("SAFETY.md");
        if (stripped == "~/.hol-support/SAFETY.md" || Path::new(stripped) == safety)
            && fs::symlink_metadata(&safety)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            if let Ok(real) = fs::canonicalize(safety) {
                return SourcePathDecision::allow("guard_safety_doc_path", real);
            }
        }
    }
    let Ok(workspace) = fs::canonicalize(cwd) else {
        return SourcePathDecision::deny("unresolved_path");
    };
    let external_requested = Path::new(stripped).is_absolute() || stripped.starts_with("~/");
    let home_for_resolution = home.unwrap_or_else(|| Path::new(""));
    let Ok(lexical) = resolve_candidate(stripped, Some(&workspace), home_for_resolution) else {
        return SourcePathDecision::deny("unresolved_path");
    };

    if contains_symlink_component(&lexical) {
        return SourcePathDecision::deny("symlink_in_path");
    }
    let Ok(candidate) = fs::canonicalize(&lexical) else {
        return SourcePathDecision::deny("external_target_not_readable");
    };

    let inside_workspace = candidate.starts_with(&workspace);
    if !inside_workspace {
        if !allow_external || !external_requested {
            return SourcePathDecision::deny("absolute_path_outside_workspace");
        }
        let Some(home) = home.and_then(canonical_dir) else {
            return SourcePathDecision::deny("external_home_unavailable");
        };
        if !candidate.starts_with(&home) {
            return SourcePathDecision::deny("external_target_outside_home");
        }
        if !immediate_sibling_git_checkout(&candidate, &workspace) {
            return SourcePathDecision::deny("external_target_not_sibling_git_checkout");
        }
        let parts = lowered_parts(&candidate);
        if parts
            .iter()
            .any(|part| EXTERNAL_SENSITIVE_PARTS.contains(&part.as_str()))
            || sensitive_external_filename(&candidate)
        {
            return SourcePathDecision::deny("sensitive_basename");
        }
        if !hidden_parts_allowed(&parts) {
            return SourcePathDecision::deny("unsafe_hidden_dir");
        }
        if !source_shape_allowed(Path::new(stripped), &parts) {
            return SourcePathDecision::deny("not_source_like");
        }
        return SourcePathDecision::allow("external_source_path", candidate);
    }

    let relative = match candidate.strip_prefix(&workspace) {
        Ok(relative) => relative,
        Err(_) => return SourcePathDecision::deny("resolved_outside_workspace"),
    };
    let parts = lowered_parts(relative);
    if parts.is_empty() {
        return SourcePathDecision::deny("empty_resolved_path");
    }
    if parts
        .iter()
        .any(|part| SENSITIVE_SEARCH_BASENAMES.contains(&part.as_str()))
    {
        return SourcePathDecision::deny("sensitive_basename");
    }
    if !hidden_parts_allowed(&parts) {
        return SourcePathDecision::deny("unsafe_hidden_dir");
    }
    if !source_shape_allowed(relative, &parts) {
        return SourcePathDecision::deny("not_source_like");
    }
    let reason = if parts
        .first()
        .is_some_and(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        "source_prefix"
    } else if parts
        .iter()
        .any(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        "source_inspection_part"
    } else if relative
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            let lowered = name.to_ascii_lowercase();
            BENIGN_SOURCE_DOTFILES.contains(&lowered.as_str())
        })
    {
        "benign_source_dotfile"
    } else {
        "source_extension"
    };
    SourcePathDecision::allow(reason, candidate)
}

pub fn sensitive_path_family(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let basename = parts.last().copied().unwrap_or_default();
    if basename == ".env" || basename.starts_with(".env.") {
        return Some(("local .env file", "critical"));
    }
    let direct = [
        (".npmrc", "npm registry credentials", "high"),
        (".pypirc", "Python package credentials", "high"),
        (".netrc", "netrc credentials", "high"),
        (".git-credentials", "Git credential store", "high"),
        ("terraform.tfvars", "Terraform variable secrets", "high"),
        ("private-key.pem", "wallet/private-key file", "critical"),
        ("private.key", "wallet/private-key file", "critical"),
        ("wallet.key", "wallet/private-key file", "critical"),
    ];
    if let Some((_, family, sensitivity)) = direct.iter().find(|(name, _, _)| *name == basename) {
        return Some((*family, *sensitivity));
    }
    if basename.contains("private-key")
        || basename.contains("private_key")
        || basename.contains("wallet-key")
        || basename.contains("wallet_key")
    {
        return Some(("wallet/private-key file", "critical"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".aws", "credentials"])
    {
        return Some(("AWS shared credentials file", "high"));
    }
    if parts.windows(2).any(|window| window == [".aws", "config"]) {
        return Some(("AWS shared config file", "high"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".docker", "config.json"])
    {
        return Some(("Docker client config", "high"));
    }
    if parts.windows(2).any(|window| window == [".kube", "config"]) {
        return Some(("Kubernetes config", "high"));
    }
    if parts.contains(&".gnupg") {
        return Some(("GnuPG key material", "high"));
    }
    if let Some(index) = parts.iter().position(|part| *part == ".ssh") {
        if parts
            .get(index + 1)
            .is_some_and(|name| matches!(*name, "id_rsa" | "id_ed25519" | "id_ecdsa"))
        {
            return Some(("SSH private key", "critical"));
        }
        if parts.get(index + 1).is_some_and(|name| *name == "config") {
            return Some(("SSH client config", "high"));
        }
    }
    None
}

pub fn source_like(path: &Path) -> bool {
    let parts = lowered_parts(path);
    if parts
        .iter()
        .any(|part| SENSITIVE_SEARCH_BASENAMES.contains(&part.as_str()))
        || !hidden_parts_allowed(&parts)
    {
        return false;
    }
    source_shape_allowed(path, &parts)
}
