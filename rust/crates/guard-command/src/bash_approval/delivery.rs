//! Framing for a native-owned frozen source pipe.
//!
//! The native owner writes the reviewed bytes first and releases the trailing
//! NUL only after its grant/policy launch gate commits. EOF, an early marker or
//! a truncated write must not execute even a syntactically valid source prefix.

use super::{Uncertainty, MAX_SOURCE_BYTES};

/// The caller preserves the original script's $0 and exact positional argv.
/// `source_fd` must be a native-owned read-only pipe, not a caller pathname.
pub fn bootstrap(source_bytes: usize, source_fd: u32) -> Result<String, Uncertainty> {
    if source_bytes > 4 * MAX_SOURCE_BYTES || source_fd > 255 {
        return Err(Uncertainty {
            reason: "bash_delivery_bounds",
            line: 1,
        });
    }
    Ok(format!(
        "__HOL_GUARD_READ() {{ local LC_ALL=C; \
         IFS= read -r -d '' __HOL_GUARD_CODE <&{source_fd} || return 125; \
         [ \"${{#__HOL_GUARD_CODE}}\" -eq {source_bytes} ]; }}; \
         __HOL_GUARD_READ || exit 125; eval \"$__HOL_GUARD_CODE\""
    ))
}

/// Two-frame delivery. The native owner receives `R` only after Bash has read
/// the complete source. It releases the second NUL after policy/grant commit;
/// `S` acknowledges dispatch, and is not a completion receipt.
pub fn acknowledged_bootstrap(
    source_bytes: usize,
    source_fd: u32,
    ack_fd: u32,
) -> Result<String, Uncertainty> {
    if !(6..=255).contains(&ack_fd) || ack_fd == source_fd {
        return Err(Uncertainty {
            reason: "bash_delivery_bounds",
            line: 1,
        });
    }
    if source_bytes > 4 * MAX_SOURCE_BYTES || source_fd > 255 {
        return Err(Uncertainty {
            reason: "bash_delivery_bounds",
            line: 1,
        });
    }
    Ok(format!(
        "__HOL_GUARD_READ() {{ local LC_ALL=C; \
         IFS= read -r -d '' __HOL_GUARD_CODE <&{source_fd} || return 125; \
         [ \"${{#__HOL_GUARD_CODE}}\" -eq {source_bytes} ]; }}; \
         __HOL_GUARD_READ || exit 125; printf R >&{ack_fd} || exit 125; \
         IFS= read -r -d '' __HOL_GUARD_AUTH <&{source_fd} || exit 125; \
         [ -z \"$__HOL_GUARD_AUTH\" ] || exit 125; \
         printf S >&{ack_fd} || exit 125; exec {ack_fd}>&-; eval \"$__HOL_GUARD_CODE\""
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::*;

    #[test]
    fn acknowledged_bootstrap_requires_complete_source_and_empty_authorization() {
        let source = b"printf executed";
        for (frame, allowed) in [
            ([source.as_slice(), b"\0\0"].concat(), true),
            ([source.as_slice(), b"\0"].concat(), false),
            ([source.as_slice(), b"\0not-authorized\0"].concat(), false),
            (b"printf bad\0\0".to_vec(), false),
            (source.to_vec(), false),
        ] {
            let mut command = Command::new("/bin/bash");
            command.args([
                "--noprofile",
                "--norc",
                "-c",
                &format!(
                    "exec 6>&2; {}",
                    acknowledged_bootstrap(source.len(), 0, 6).unwrap()
                ),
            ]);
            command
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // Test-only ACK channel: fd6 is a duplicate of the child's captured
            // stderr. Production uses a native-owned, bounded handshake pipe.
            let mut child = command.spawn().unwrap();
            child.stdin.take().unwrap().write_all(&frame).unwrap();
            let result = child.wait_with_output().unwrap();
            if allowed {
                assert!(result.status.success());
                assert_eq!(result.stderr, b"RS");
                assert_eq!(result.stdout, b"executed");
            } else {
                assert_eq!(result.status.code(), Some(125));
                assert!(result.stdout.is_empty());
                assert!(!result.stderr.contains(&b'S'));
            }
        }
    }

    fn run(source: &[u8], sent: &[u8]) -> std::process::Output {
        let mut child = Command::new("/bin/bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                &bootstrap(source.len(), 0).unwrap(),
                "original-script",
                "two words*",
            ])
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        // An invalid early NUL may close the pipe before a long remainder.
        let written = input.write_all(sent);
        drop(input);
        let result = child.wait_with_output().unwrap();
        if result.status.success() {
            written.unwrap();
        }
        result
    }

    #[test]
    fn committed_large_frame_preserves_positional_arguments_and_full_source() {
        let source = format!("#{}\nprintf '%s\\n%s' \"$0\" \"$1\"\n", "x".repeat(300_000));
        let mut frame = source.as_bytes().to_vec();
        frame.push(0);
        let result = run(source.as_bytes(), &frame);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"original-script\ntwo words*");
    }

    #[test]
    fn every_uncommitted_or_incomplete_frame_runs_no_prefix() {
        let source = b"printf 'must not run'\n# frozen source follows\nprintf 'complete'\n";
        let mut shortened = source[..25].to_vec();
        shortened.push(0);
        let mut early_marker = b"printf 'must not run'\n\0".to_vec();
        early_marker.extend(source);
        for frame in [Vec::new(), source.to_vec(), shortened, early_marker] {
            let result = run(source, &frame);
            assert_eq!(result.status.code(), Some(125));
            assert!(result.stdout.is_empty(), "partial source executed");
        }
    }
}
