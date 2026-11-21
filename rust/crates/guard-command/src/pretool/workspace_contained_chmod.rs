//! `chmod` forms the workspace sandbox can contain. Making a workspace
//! script executable (`chmod +x scripts/run.sh`) is routine and changes
//! nothing the sandbox does not already allow: Seatbelt counts a mode change
//! as a write, so the same rules that keep `.git/hooks` and helper paths
//! unwritable also keep their modes fixed. Setuid, setgid and sticky bits,
//! write access for other users, recursive or reference forms, and any
//! other option keep their review.

/// Whether `arguments` (after `chmod`) are one plain permission mode and at
/// least one path.
pub(super) fn plain_mode(arguments: &[String]) -> bool {
    match arguments.split_first() {
        Some((mode, paths)) => {
            !paths.is_empty()
                && paths
                    .iter()
                    .all(|path| !path.is_empty() && !path.starts_with('-'))
                && (numeric(mode) || mode.split(',').all(symbolic))
        }
        None => false,
    }
}

/// `755` or `0644`: no special bits and no write bit for other users.
fn numeric(mode: &str) -> bool {
    let digits = mode
        .strip_prefix('0')
        .filter(|rest| rest.len() == 3)
        .unwrap_or(mode);
    digits.len() == 3
        && digits.bytes().all(|digit| (b'0'..=b'7').contains(&digit))
        && (digits.as_bytes()[2] - b'0') & 2 == 0
}

/// `+x`, `u+x`, `go-w` or `a=r`: read, write and execute bits only. A
/// clause that could grant other users write access (`o+w`, `a=rw`, or `+w`
/// under a permissive umask) is refused.
fn symbolic(clause: &str) -> bool {
    let operations = clause.trim_start_matches(['u', 'g', 'o', 'a']);
    let who = &clause[..clause.len() - operations.len()];
    let others = who.is_empty() || who.contains(['o', 'a']);
    let mut characters = operations.chars().peekable();
    let mut any = false;
    while let Some(operator) = characters.next() {
        if !matches!(operator, '+' | '-' | '=') {
            return false;
        }
        let mut permissions = 0;
        while let Some(permission) = characters.next_if(|c| matches!(c, 'r' | 'w' | 'x' | 'X')) {
            if permission == 'w' && others && operator != '-' {
                return false;
            }
            permissions += 1;
        }
        if permissions == 0 && operator != '=' {
            return false;
        }
        any = true;
    }
    any
}

#[cfg(test)]
mod tests {
    use super::plain_mode;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn plain_modes_are_contained() {
        for text in [
            "+x scripts/run.sh",
            "755 a b",
            "0644 f",
            "u+x,go-w f",
            "-x f",
            "a=r f",
            "u+w f",
            "775 f",
            "a-w f",
        ] {
            assert!(plain_mode(&words(text)), "{text}");
        }
    }

    #[test]
    fn special_bits_options_and_bare_modes_keep_review() {
        for text in [
            "u+s f",
            "4755 f",
            "1777 d",
            "g+s d",
            "+t d",
            "-R 755 d",
            "755",
            "--reference=a b",
            "777 f",
            "0666 f",
            "o+w f",
            "a=rw f",
            "+w f",
            "u+x,o+w f",
            "755 -f",
            "o+rwxs f",
            "+ f",
            "8755 f",
            "77 f",
        ] {
            assert!(!plain_mode(&words(text)), "{text}");
        }
    }
}
