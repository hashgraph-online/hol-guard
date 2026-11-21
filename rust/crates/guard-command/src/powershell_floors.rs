//! Raw-text destructive and exfiltration floors for PowerShell commands.
//!
//! The text floors look for POSIX spellings (`rm -rf`, `curl --data`), which
//! PowerShell spells differently. For the PowerShell dialect the same checks
//! also run over the canonical POSIX-shaped segments, and recursive deletes of
//! a drive or home root are recognized explicitly.

use crate::CanonicalCommandV1;

fn canonical_text(model: &CanonicalCommandV1) -> Option<String> {
    (model.dialect == "powershell").then(|| {
        model
            .segments
            .iter()
            .map(|segment| segment.tokens.join(" "))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn is_root_target(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase().replace('\\', "/");
    let trimmed = lowered.trim_end_matches('/');
    let mut chars = trimmed.chars();
    let drive = matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(letter), Some(':'), None) if letter.is_ascii_alphabetic()
    );
    drive
        || (trimmed.is_empty() && !lowered.is_empty())
        || matches!(trimmed, "~" | "$home" | "%userprofile%" | "%systemdrive%")
}

fn recursive_root_delete(model: &CanonicalCommandV1) -> bool {
    model.dialect == "powershell"
        && model.segments.iter().any(|segment| {
            segment.executable.as_deref() == Some("rm")
                && segment
                    .arguments
                    .iter()
                    .any(|argument| argument.starts_with('-') && argument.contains('r'))
                && segment
                    .arguments
                    .iter()
                    .any(|argument| !argument.starts_with('-') && is_root_target(argument))
        })
}

pub(crate) fn destructive(model: &CanonicalCommandV1, check: fn(&str) -> bool) -> bool {
    check(&model.normalized_text)
        || recursive_root_delete(model)
        || canonical_text(model).is_some_and(|text| check(&text))
}

pub(crate) fn sensitive_exfiltration(
    model: &CanonicalCommandV1,
    sensitive: fn(&str) -> bool,
    exfiltration: fn(&str) -> bool,
) -> bool {
    let both = |text: &str| sensitive(text) && exfiltration(text);
    both(&model.normalized_text) || canonical_text(model).is_some_and(|text| both(&text))
}
