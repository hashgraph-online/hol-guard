//! A Vite config's literal `outDir`, accepted only when the build sink would.

use std::path::{Path, PathBuf};

fn out_dir_patterns() -> (&'static regex::Regex, &'static regex::Regex) {
    static MENTIONS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\boutDir\b").expect("outDir mention"));
    static LITERAL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(?x)
            \boutDir\s*:\s*(?:
                (?:path\.)?(?:resolve|join)\(\s*__dirname\s*,\s*['"]([^'"\\$`]+)['"]\s*\)
                | ['"]([^'"\\$`]+)['"]
            )
            "#,
        )
        .expect("vite outDir literal")
    });
    (&MENTIONS, &LITERAL)
}

/// One Vite config may name a literal output the sink accepts. Several
/// configs, or none, keep the default `dist`. A single config that mentions
/// `outDir` without exactly one admissible literal makes the sink refuse the
/// build.
pub(super) fn vite_config_output_is_verifiable(directory: &Path, workspace: &Path) -> bool {
    const NAMES: [&str; 6] = [
        "vite.config.ts",
        "vite.config.mts",
        "vite.config.cts",
        "vite.config.js",
        "vite.config.mjs",
        "vite.config.cjs",
    ];
    let configs: Vec<PathBuf> = NAMES
        .iter()
        .map(|name| directory.join(name))
        .filter(|path| path.is_file())
        .collect();
    if configs.len() != 1 {
        return true;
    }
    let path = &configs[0];
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return true;
    }
    let Ok(raw) = std::fs::read(path) else {
        return true;
    };
    let text = String::from_utf8_lossy(&raw);
    let (mentions, literal) = out_dir_patterns();
    let mention_count = mentions.find_iter(&text).count();
    if mention_count == 0 {
        return true;
    }
    let captures: Vec<_> = literal.captures_iter(&text).collect();
    if raw.len() > 256 * 1024 || mention_count != 1 || captures.len() != 1 {
        return false;
    }
    let Some(spelled) = captures[0]
        .get(1)
        .or_else(|| captures[0].get(2))
        .map(|value| value.as_str())
    else {
        return false;
    };
    declared_output_is_admissible(
        &config_output_path(directory, spelled),
        directory,
        workspace,
    )
}

fn config_output_path(directory: &Path, spelled: &str) -> PathBuf {
    let spelled = Path::new(spelled);
    if spelled.is_absolute() {
        return spelled.to_path_buf();
    }
    let mut output = directory.to_path_buf();
    for part in spelled.components() {
        match part {
            std::path::Component::ParentDir => {
                output.pop();
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => output.push(name),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return spelled.to_path_buf();
            }
        }
    }
    output
}

/// `declared_vite_output`'s admissibility: inside the workspace, not the
/// workspace or the run directory, no hidden or `node_modules` part, no link
/// or package manifest along the path, and an existing directory holds only
/// built assets.
fn declared_output_is_admissible(output: &Path, directory: &Path, workspace: &Path) -> bool {
    if output == workspace || output == directory || directory.starts_with(output) {
        return false;
    }
    let Ok(relative) = output.strip_prefix(workspace) else {
        return false;
    };
    if relative.as_os_str().is_empty() {
        return false;
    }
    let mut reached = workspace.to_path_buf();
    for part in relative.components() {
        let name = part.as_os_str().to_string_lossy();
        if name.starts_with('.') || name == "node_modules" {
            return false;
        }
        reached.push(part);
        if let Ok(metadata) = std::fs::symlink_metadata(&reached) {
            let kind = metadata.file_type();
            if kind.is_symlink() || !kind.is_dir() {
                return false;
            }
        }
        if reached.join("package.json").exists() {
            return false;
        }
    }
    built_assets_only(output)
}

fn built_assets_only(output: &Path) -> bool {
    const ASSETS: &[&str] = &[
        "avif",
        "br",
        "css",
        "eot",
        "gif",
        "gz",
        "htm",
        "html",
        "ico",
        "jpeg",
        "jpg",
        "js",
        "json",
        "map",
        "mjs",
        "mp3",
        "mp4",
        "otf",
        "png",
        "svg",
        "ttf",
        "txt",
        "wasm",
        "wav",
        "webm",
        "webmanifest",
        "webp",
        "woff",
        "woff2",
        "xml",
    ];
    if !output.exists() {
        return true;
    }
    let mut visited = 0usize;
    let mut pending = vec![output.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            // `os.walk(..., followlinks=False)` lists a link to a directory as a
            // directory and does not descend. A link to a file is a file.
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if kind.is_symlink() && entry.path().is_dir() {
                continue;
            }
            visited += 1;
            if visited > 20_000 {
                return false;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "package.json" {
                return false;
            }
            if name == ".gitkeep" || name == ".DS_Store" {
                continue;
            }
            let Some(extension) = Path::new(name.as_ref()).extension() else {
                return false;
            };
            let extension = extension.to_string_lossy().to_lowercase();
            if !ASSETS.contains(&extension.as_str()) {
                return false;
            }
        }
    }
    true
}
