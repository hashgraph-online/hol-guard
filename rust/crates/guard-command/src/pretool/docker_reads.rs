//! Container and image listings from the local Docker client.
//!
//! `docker ps` and `docker images` (and their `container ls` / `image ls`
//! spellings) print the same summary the daemon already exposes to `ps`:
//! names, images, ports, status and the container command. They create,
//! start, pull and change nothing. Every option is allowlisted. Starting an
//! existing container is proven in `docker_start`.
//!
//! `docker version` and `docker compose version` print the client banner and,
//! for the first, the daemon's version line. Neither starts a container or
//! reads a project file.
//!
//! `docker buildx ls` prints the builder instances named in the client's own
//! configuration directory, with their endpoints and platforms. It bootstraps
//! nothing: only `buildx inspect --bootstrap` starts a builder, and that stays
//! reviewed. `docker compose ls` prints the projects the daemon already labels
//! its running containers with, so unlike `compose ps` it never resolves a
//! compose file, its `.env` or its `include` sources.
//!
//! Still reviewed:
//! - any option before the subcommand. `-H`/`--host`, `--context` and
//!   `--config` move the client to another daemon or configuration, and
//!   `--tls*` options read local key files.
//! - `inspect`, which prints each container's environment, and `compose ps`,
//!   which loads the project's `.env` and `include` sources. Both also sit
//!   under the critical container-state floor.
//! - `logs`, which is application output that often carries credentials.
//! - every other subcommand, including plugin commands that run a
//!   `docker-<name>` binary.
//!
//! The inherited `DOCKER_HOST` and `DOCKER_CONTEXT` are host trust inputs,
//! like the default kubeconfig. An environment prefix or an `export` in the
//! same command keeps the review through the generic segment checks.

/// No-value options shared by both listings.
const LISTING_FLAGS: [&str; 6] = ["-a", "--all", "-q", "--quiet", "--no-trunc", "--help"];

/// Container-listing flags that take no value.
const CONTAINER_FLAGS: [&str; 4] = ["-s", "--size", "-l", "--latest"];

/// Image-listing flags that take no value.
const IMAGE_FLAGS: [&str; 1] = ["--digests"];

/// Builder and project listings print a fixed summary and take no flag of
/// their own beyond the shared ones.
const NO_FLAGS: [&str; 0] = [];

/// Options whose value only filters, bounds or formats the printed summary.
const CONTAINER_VALUES: [&str; 5] = ["-n", "--last", "-f", "--filter", "--format"];
const IMAGE_VALUES: [&str; 3] = ["-f", "--filter", "--format"];
/// A builder listing's `--format` is not a summary option: `--format json`
/// serializes each builder's nodes, and a node carries the proxy
/// configuration it was created with, which the default table omits. A proxy
/// URL is written with its credentials in it, so the printed summary stays
/// the fixed one.
const BUILDER_VALUES: [&str; 0] = [];
/// `docker compose ls` gives `--filter` no short form, so Cobra reads `-f` as
/// the root `--file` and the value names a compose file to resolve. Only the
/// long spelling filters.
const PROJECT_VALUES: [&str; 2] = ["--filter", "--format"];

/// Single-letter flags that may be clustered (`-aq`).
const CONTAINER_SHORT: &str = "aqsl";
const IMAGE_SHORT: &str = "aq";
const BUILDER_SHORT: &str = "";
const PROJECT_SHORT: &str = "aq";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    Containers,
    Images,
    Builders,
    Projects,
}

pub(super) fn safe_docker_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_docker_arguments(&segment.arguments)
}

/// A whole `docker` segment, generic checks included, that the native proof
/// accepts as a container or image listing or as a start of existing
/// containers. The compatibility layer uses it so it does not treat
/// the same command as a possibly sensitive operation.
pub(crate) fn proven_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("docker")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

pub(super) fn safe_docker_arguments(arguments: &[String]) -> bool {
    if arguments
        .iter()
        .any(|argument| argument.contains(['$', '`', '\n', '\r']))
    {
        return false;
    }
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    // A version banner prints the client's own build, and the server line it
    // asks the daemon for is the same connection `docker ps` already uses. The
    // Compose plugin prints its banner without loading a project file.
    if matches!(
        words.as_slice(),
        ["version"]
            | ["compose", "version"]
            | ["compose", "version", "--short"]
            | ["buildx", "version"]
    ) {
        return true;
    }
    let (listing, rest) = match words.as_slice() {
        ["ps", rest @ ..] => (Listing::Containers, rest),
        ["container", "ls" | "list" | "ps", rest @ ..] => (Listing::Containers, rest),
        ["images", rest @ ..] => (Listing::Images, rest),
        ["image", "ls" | "list", rest @ ..] => (Listing::Images, rest),
        ["buildx", "ls", rest @ ..] => (Listing::Builders, rest),
        ["compose", "ls" | "list", rest @ ..] => (Listing::Projects, rest),
        _ => return super::docker_start::safe_start_arguments(&words),
    };
    listing_options_safe(listing, rest)
}

fn listing_options_safe(listing: Listing, words: &[&str]) -> bool {
    let (flags, values, short): (&[&str], &[&str], &str) = match listing {
        Listing::Containers => (&CONTAINER_FLAGS[..], &CONTAINER_VALUES[..], CONTAINER_SHORT),
        Listing::Images => (&IMAGE_FLAGS[..], &IMAGE_VALUES[..], IMAGE_SHORT),
        Listing::Builders => (&NO_FLAGS[..], &BUILDER_VALUES[..], BUILDER_SHORT),
        Listing::Projects => (&NO_FLAGS[..], &PROJECT_VALUES[..], PROJECT_SHORT),
    };
    let mut positionals = 0usize;
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        index += 1;
        if !word.starts_with('-') {
            positionals += 1;
            if !image_reference(word) {
                return false;
            }
            continue;
        }
        if LISTING_FLAGS.contains(&word) || flags.contains(&word) {
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        if values.contains(&name) {
            let value = match inline {
                Some(value) => value,
                None => match words.get(index) {
                    Some(value) => {
                        index += 1;
                        *value
                    }
                    None => return false,
                },
            };
            if !option_value_safe(name, value) {
                return false;
            }
            continue;
        }
        if !short_cluster(word, short) {
            return false;
        }
    }
    // `docker images <repository[:tag]>` filters by one reference; the
    // container listing takes none.
    match listing {
        Listing::Containers | Listing::Builders | Listing::Projects => positionals == 0,
        Listing::Images => positionals <= 1,
    }
}

fn short_cluster(word: &str, allowed: &str) -> bool {
    word.strip_prefix('-').is_some_and(|flags| {
        !flags.is_empty()
            && !flags.starts_with('-')
            && flags.chars().all(|flag| allowed.contains(flag))
    })
}

fn option_value_safe(name: &str, value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    match name {
        "-n" | "--last" => value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit()),
        // A filter is `key=value`; a format is a Go template or a named
        // layout, evaluated over the listing summary only.
        "-f" | "--filter" => value.contains('=') && !value.starts_with('-'),
        "--format" => true,
        _ => false,
    }
}

/// `name[:tag]` or `name@digest` with registry path characters only.
fn image_reference(word: &str) -> bool {
    word.len() <= 256
        && word
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        })
}

#[cfg(test)]
#[path = "docker_reads_tests.rs"]
mod tests;
