//! Oh My Pi references to content the host holds: session artifacts, skills,
//! background jobs, scratch files and tool docs. None of them names a
//! filesystem path, so a read of one is answered from the host's own tables.

/// `skill://<name>[/<relative.md>]` names a skill the host resolves from its
/// own registered skill roots; the name is a bounded token, never a path.
fn skill_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("skill://") else {
        return false;
    };
    rest.len() <= 512 && rest.split('/').all(host_name_token)
}

/// One `/`-separated part of a `skill://` or `local://` name: a bounded,
/// non-hidden run of letters, digits, `-`, `_` and `.`.
fn host_name_token(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 128
        && !part.starts_with('.')
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Reason code for host-held reference selectors, `None` for real paths.
pub(in crate::pretool) fn host_reference_reason(value: &str) -> Option<&'static str> {
    if artifact_reference(value) {
        Some("native_omp_artifact_read")
    } else if skill_reference(value) {
        Some("native_omp_skill_read")
    } else if proc_reference(value) {
        Some("native_omp_proc_read")
    } else if local_reference(value) {
        Some("native_omp_local_read")
    } else if device_docs_reference(value) {
        Some("native_omp_device_docs_read")
    } else {
        None
    }
}

/// `local://` lists the session's scratch root and `local://<name>` reads one
/// file in it, such as the `paste-N.md` a large paste becomes or a plan the
/// session wrote. The host resolves the name under that root and refuses any
/// target outside it; the name here is also bounded tokens joined by `/`, so
/// `..`, absolute, hidden, `~` and percent-encoded names stay reviewed. An
/// optional line range or `raw` follows, as for `artifact://`.
fn local_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("local://") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut chunks = rest.split(':');
    let name = chunks.next().unwrap_or_default();
    rest.len() <= 512 && name.split('/').all(host_name_token) && selector_chunks_ok(chunks)
}

/// `artifact://<digits>` names an Oh My Pi session artifact, never a path.
/// It may carry an `N-M` line range, `raw`, or one of each in either order;
/// `raw` only drops line formatting from the same artifact.
fn artifact_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("artifact://") else {
        return false;
    };
    let mut chunks = rest.split(':');
    let id = chunks.next().unwrap_or_default();
    let number = |part: &str| {
        !part.is_empty() && part.len() <= 9 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    number(id) && selector_chunks_ok(chunks)
}

/// `proc://` lists the session's own background jobs and `proc://<id>` shows
/// one job's status and output, with an optional line window. The host serves
/// both from its job table, never from a path. `proc://<id>/streams[/<n>]`
/// reads one job's pipe streams the same way, and any other part after the id
/// is a URL the host refuses with its usage text, so a model that guesses
/// `proc://<id>/output` gets that answer instead of an approval wait.
/// `proc://<id>/kill` and `/mode` are write targets, so they stay out.
fn proc_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("proc://") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut chunks = rest.split(':');
    let target = chunks.next().unwrap_or_default();
    let mut parts = target.split('/');
    let id = parts.next().unwrap_or_default();
    let below: Vec<&str> = parts.collect();
    rest.len() <= 512
        && host_name_token(id)
        && below.len() <= 2
        && below.iter().copied().all(host_name_token)
        && !matches!(below.first(), Some(&"kill" | &"mode"))
        && selector_chunks_ok(chunks)
}

/// `xd://` lists the session's mounted tool devices, `xd://<tool>` shows one
/// tool's docs and parameter schema, and `xd://<tool>/<topic>` one named doc
/// topic. A read of any of them returns text the host holds in memory; only a
/// write to `xd://<tool>` runs the tool, and that goes through the write tool.
fn device_docs_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("xd://") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let parts: Vec<&str> = rest.split('/').collect();
    rest.len() <= 256 && parts.len() <= 2 && parts.iter().copied().all(host_name_token)
}

/// The `:`-separated tail the host peels from a reference: at most one `N-M`
/// line range and one `raw`, in either order.
fn selector_chunks_ok<'a>(mut chunks: impl Iterator<Item = &'a str>) -> bool {
    let number = |part: &str| {
        !part.is_empty() && part.len() <= 9 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    let (mut raw, mut range) = (false, false);
    chunks.all(|chunk| {
        if chunk.eq_ignore_ascii_case("raw") && !raw {
            raw = true;
            return true;
        }
        let is_range = chunk
            .split_once('-')
            .is_some_and(|(start, end)| number(start) && number(end));
        let fresh = is_range && !range;
        range |= is_range;
        fresh
    })
}
