//! `rustfmt` rewriting named Rust source files in place.
//!
//! rustfmt rewrites each file operand and every out-of-line child module it
//! declares (`mod name;`, optionally redirected with `#[path = ...]`). Each
//! operand must pass the same bounded write proof as a native file write, and
//! a file that declares any out-of-line module stays reviewed, because its
//! children would be rewritten without that proof. The rustup proxy that
//! starts rustfmt must only be able to pick an official toolchain. rustfmt's
//! own configuration files select formatting options and run no code.

use std::io::Read;

const MAX_TARGETS: usize = 16;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const EDITIONS: [&str; 4] = ["2015", "2018", "2021", "2024"];

pub(super) fn safe_rustfmt_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut targets = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "--check" | "-l" | "--files-with-diff" | "-q" | "--quiet" => {}
            "--edition" => {
                index += 1;
                if !arguments
                    .get(index)
                    .is_some_and(|edition| EDITIONS.contains(&edition.as_str()))
                {
                    return false;
                }
            }
            _ => {
                if let Some(edition) = argument.strip_prefix("--edition=") {
                    if !EDITIONS.contains(&edition) {
                        return false;
                    }
                } else if argument.starts_with(['-', '+']) {
                    // rustup reads a leading `+name` as a toolchain selector,
                    // even when a file of that name exists.
                    return false;
                } else {
                    targets.push(argument.as_str());
                }
            }
        }
        index += 1;
    }
    (1..=MAX_TARGETS).contains(&targets.len())
        && super::rust_toolchain::rustfmt_proxy_is_official(context)
        && targets.iter().all(|target| {
            target.ends_with(".rs")
                && super::safe_reads::bounded_native_file_write_target(
                    target,
                    context.home_dir,
                    context.cwd,
                )
                && source_without_child_modules(target, context.cwd)
        })
}

fn source_without_child_modules(target: &str, cwd: Option<&str>) -> bool {
    let path = std::path::Path::new(target);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = cwd.filter(|cwd| std::path::Path::new(cwd).is_absolute()) {
        std::path::Path::new(cwd).join(path)
    } else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return false;
    }
    let mut source = String::new();
    std::fs::File::open(&path)
        .and_then(|file| file.take(MAX_SOURCE_BYTES + 1).read_to_string(&mut source))
        .is_ok_and(|read| read as u64 <= MAX_SOURCE_BYTES)
        && !declares_out_of_line_module(&source)
}

/// Rust permits comments anywhere ordinary whitespace is permitted.
/// Skip comments conservatively, including nested block comments. An
/// unterminated block is untrusted, so callers refuse formatting.
fn skip_trivia(source: &str, mut offset: usize) -> Option<usize> {
    loop {
        let remaining = source.get(offset..)?;
        if remaining.starts_with("//") {
            offset += remaining.find('\n').unwrap_or(remaining.len());
            continue;
        }
        if remaining.starts_with("/*") {
            offset += 2;
            let mut depth = 1_usize;
            while depth != 0 {
                let next = source.get(offset..)?;
                if next.starts_with("/*") {
                    depth += 1;
                    offset += 2;
                } else if next.starts_with("*/") {
                    depth -= 1;
                    offset += 2;
                } else {
                    offset += next.chars().next()?.len_utf8();
                }
            }
            continue;
        }
        if let Some(ch) = remaining.chars().next().filter(|ch| ch.is_whitespace()) {
            offset += ch.len_utf8();
            continue;
        }
        return Some(offset);
    }
}

/// Over-approximates out-of-line declarations, including comments as trivia.
/// Matching inside a string or a comment may conservatively trigger review.
fn declares_out_of_line_module(source: &str) -> bool {
    let identifier = |character: char| character.is_alphanumeric() || character == '_';
    source.match_indices("mod").any(|(start, _)| {
        if source[..start].chars().next_back().is_some_and(identifier) {
            return false;
        }
        let after_keyword = start + 3;
        let Some(after) = source.get(after_keyword..) else {
            return true;
        };
        if !after.starts_with(char::is_whitespace)
            && !after.starts_with("//")
            && !after.starts_with("/*")
        {
            return false;
        }
        let Some(name_start) = skip_trivia(source, after_keyword) else {
            return true;
        };
        let rest = &source[name_start..];
        let name_end = rest
            .find(|character: char| !(identifier(character) || character == '#'))
            .unwrap_or(rest.len());
        // Rust identifiers include Unicode XID_Start characters. If we cannot
        // recognize a name after `mod`, fail closed instead of allowing a
        // formatter to rewrite an unverified child module.
        if name_end == 0 {
            return true;
        }
        match skip_trivia(source, name_start + name_end) {
            // Only `mod name { ... }` is demonstrably in-line. Unknown
            // Unicode identifier continuation or punctuation stays reviewed.
            Some(next) => !source[next..].starts_with('{'),
            None => true,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::declares_out_of_line_module;

    #[test]
    fn child_module_screen() {
        for source in [
            "mod child;",
            "pub mod child ;\nfn main() {}",
            "#[path = \"/tmp/x.rs\"]\nmod r#type;",
            "mod outer {\n    mod inner;\n}",
            "pub(crate)\tmod\nchild\n;",
            "mod child /**/;",
            "mod child // comment\n;",
            "mod /* outer /* nested */ remaining */ child;",
            "#[path = \"../.github/workflows/check.rs\"] mod child /**/;",
            "mod /* unterminated",
            "#[path = \"../.github/workflows/check.rs\"] mod ℘;",
            "#[path = \"../.github/workflows/check.rs\"] mod a·b;",
            "#[path = \"../.github/workflows/check.rs\"] mod a‿b;",
            "#[path = \"../.github/workflows/check.rs\"] mod e\u{301}x;",
        ] {
            assert!(declares_out_of_line_module(source), "{source}");
        }
        for source in [
            "pub fn name() -> &'static str {\n    \"fixture\"\n}\n",
            "mod tests {\n    #[test]\n    fn ok() {}\n}",
            "fn module(); let model = 1;",
            "mod nested { mod helper {} }",
            "fn modern() {}",
            "",
        ] {
            assert!(!declares_out_of_line_module(source), "{source}");
        }
    }
}
