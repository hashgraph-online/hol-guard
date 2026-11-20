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
//! `docker context ls` prints the contexts kept in the client's own
//! configuration directory: each name, description, Docker endpoint and the
//! current marker. It contacts no daemon, switches nothing and reads no TLS
//! key material, and `--format` evaluates over that same summary. `docker
//! context show` prints only the current context's name. `context use`,
//! `create`, `update`, `rm`, `import` and `export` change or copy the store,
//! and `context inspect` prints each endpoint's full metadata and TLS storage
//! paths, so they stay reviewed.
//!
//! `docker buildx imagetools inspect <image>` asks the image's registry for the
//! manifest (or manifest list) it publishes and prints its digest, platforms and
//! attestations. It is registry metadata, the same kind of query as `npm view`:
//! it pulls no layer, loads no project file, builds nothing and writes nothing
//! locally. Exactly one image reference is allowed, and the only options are
//! `--raw` and `--format`. A `--format` template may read only the image name,
//! the manifest and the index (`{{.Manifest.Digest}}`, `{{json .Manifest}}`):
//! `.Image` is the image's configuration, whose `Env` can hold a credential the
//! image was built with, so a template naming it, or any other field, function
//! or control action, stays reviewed. `--builder` points the query at another
//! builder's configuration, and every other `imagetools` verb stays reviewed,
//! `create` most of all, because it pushes a new manifest to a registry.
//!
//! `docker logs <container>` prints the output a workload already wrote. It
//! starts nothing, pulls nothing and resolves no project file, which is the
//! read `kubectl logs` is proven as in `kubectl_logs`. The output stays in the
//! session: a later step that sends it anywhere still has to pass on its own.
//! Only options that bound the printed lines or stamp them are allowed, so
//! `--follow` stays out, and so does `--details`, which prints the extra
//! attributes a logging driver was given.
//!
//! `docker volume ls`, `docker network ls`, `docker system df` and
//! `docker stats --no-stream` are the daemon's own summaries over the
//! connection `docker ps` already uses. They resolve no compose project, read
//! no `.env`, print no container environment and start nothing. A volume
//! listing is the one that cannot take `--format`: the default table prints a
//! driver and a name, while `--format json` serializes the driver options a
//! volume was created with, and a CIFS or NFS volume carries its credentials
//! there. A stats reading must say `--no-stream`, because the streaming form
//! never returns, which is why `logs --follow` is out as well.
//!
//! Still reviewed:
//! - any option before the subcommand. `-H`/`--host`, `--context` and
//!   `--config` move the client to another daemon or configuration, and
//!   `--tls*` options read local key files.
//! - `docker info`, whose output names the proxy the daemon was configured
//!   with, and a proxy URL is written with its credentials in it. `top` prints
//!   a container's process command lines and `history` the commands an image
//!   was built from, both of which routinely hold a secret in an argument.
//!   `search`, `manifest inspect` and `trust inspect` each query a registry.
//! - `inspect`, which prints each container's environment, and every `compose`
//!   verb that resolves the project, `compose ps` and `compose logs` among
//!   them: resolution reads the project's `.env`, `COMPOSE_FILE`,
//!   `COMPOSE_PROFILES` and `include` sources, which may be remote git or OCI
//!   references. They also sit under the critical container-state floor.
//! - every other subcommand, including plugin commands that run a
//!   `docker-<name>` binary.
//!
//! The inherited `DOCKER_HOST` and `DOCKER_CONTEXT` are host trust inputs,
//! like the default kubeconfig. An environment prefix or an `export` in the
//! same command keeps the review through the generic segment checks.

#[path = "docker_logs.rs"]
mod logs;

/// No-value options shared by the container, image, builder and project
/// listings.
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
/// A context listing takes only `--quiet`, `--format` and `--help`. It has
/// no `--all` or `--no-trunc` of its own, so the shared flags do not apply.
const CONTEXT_FLAGS: [&str; 3] = ["-q", "--quiet", "--help"];
/// A context listing's `--format` reads the same summary the table prints.
const CONTEXT_VALUES: [&str; 1] = ["--format"];
/// A registry manifest query prints the manifest as published (`--raw`) or
/// through a Go template over that one document (`--format`).
const REGISTRY_FLAGS: [&str; 1] = ["--raw"];
const REGISTRY_VALUES: [&str; 1] = ["--format"];

/// A volume listing filters and may print names alone. It has no `--format`:
/// the default table prints only a driver and a name, while `--format json`
/// serializes the `--opt` values the volume was created with, and a CIFS or
/// NFS volume is created with its credentials among them.
const VOLUME_FLAGS: [&str; 3] = ["-q", "--quiet", "--help"];
const VOLUME_VALUES: [&str; 2] = ["-f", "--filter"];
/// A network listing prints an id, name, driver and scope. It has no `--all`
/// of its own, and a `--format` template is held to those four fields: the
/// record behind a row also carries the labels the network was created with.
const NETWORK_FLAGS: [&str; 4] = ["-q", "--quiet", "--no-trunc", "--help"];
const NETWORK_VALUES: [&str; 3] = ["-f", "--filter", "--format"];
/// A disk-usage summary counts images, containers, volumes and the build
/// cache. `--verbose` names each row the totals are made of, so a `--format`
/// template is held to the totals: `.Volumes` reaches the verbose rows and
/// the labels and creation options a volume carries.
const DISK_FLAGS: [&str; 3] = ["-v", "--verbose", "--help"];
const DISK_VALUES: [&str; 1] = ["--format"];
/// A stats reading prints each container's CPU, memory, network and block
/// counters. `--no-stream` is required, not optional: without it the command
/// redraws until it is interrupted and never returns a result.
const STATS_FLAGS: [&str; 5] = ["-a", "--all", "--no-stream", "--no-trunc", "--help"];
const STATS_VALUES: [&str; 1] = ["--format"];

/// Single-letter flags that may be clustered (`-aq`).
const CONTAINER_SHORT: &str = "aqsl";
const IMAGE_SHORT: &str = "aq";
const BUILDER_SHORT: &str = "";
const PROJECT_SHORT: &str = "aq";
const CONTEXT_SHORT: &str = "q";
const REGISTRY_SHORT: &str = "";
const VOLUME_SHORT: &str = "q";
const NETWORK_SHORT: &str = "q";
const DISK_SHORT: &str = "v";
const STATS_SHORT: &str = "a";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    Containers,
    Images,
    Builders,
    Projects,
    Contexts,
    Manifest,
    Volumes,
    Networks,
    Disk,
    Stats,
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
            | ["context", "show"]
    ) {
        return true;
    }
    // One container's recorded output, bounded and not followed.
    if let ["logs", rest @ ..] | ["container", "logs", rest @ ..] = words.as_slice() {
        return logs::safe_container_logs(rest);
    }
    let (listing, rest) = match words.as_slice() {
        ["ps", rest @ ..] => (Listing::Containers, rest),
        ["container", "ls" | "list" | "ps", rest @ ..] => (Listing::Containers, rest),
        ["images", rest @ ..] => (Listing::Images, rest),
        ["image", "ls" | "list", rest @ ..] => (Listing::Images, rest),
        ["buildx", "ls", rest @ ..] => (Listing::Builders, rest),
        ["compose", "ls" | "list", rest @ ..] => (Listing::Projects, rest),
        ["context", "ls" | "list", rest @ ..] => (Listing::Contexts, rest),
        ["buildx", "imagetools", "inspect", rest @ ..] => (Listing::Manifest, rest),
        ["volume", "ls" | "list", rest @ ..] => (Listing::Volumes, rest),
        ["network", "ls" | "list", rest @ ..] => (Listing::Networks, rest),
        ["system", "df", rest @ ..] => (Listing::Disk, rest),
        // The streaming form never returns, so the word that bounds it has to
        // be in the text. Whether it is a flag of its own, rather than the
        // value of a preceding option, is settled while the options are read.
        ["stats", rest @ ..] => (Listing::Stats, rest),
        _ => return super::docker_start::safe_start_arguments(&words),
    };
    listing_options_safe(listing, rest)
}

fn listing_options_safe(listing: Listing, words: &[&str]) -> bool {
    let shared: &[&str] = match listing {
        Listing::Contexts
        | Listing::Volumes
        | Listing::Networks
        | Listing::Disk
        | Listing::Stats => &[],
        _ => &LISTING_FLAGS[..],
    };
    let (flags, values, short): (&[&str], &[&str], &str) = match listing {
        Listing::Containers => (&CONTAINER_FLAGS[..], &CONTAINER_VALUES[..], CONTAINER_SHORT),
        Listing::Images => (&IMAGE_FLAGS[..], &IMAGE_VALUES[..], IMAGE_SHORT),
        Listing::Builders => (&NO_FLAGS[..], &BUILDER_VALUES[..], BUILDER_SHORT),
        Listing::Projects => (&NO_FLAGS[..], &PROJECT_VALUES[..], PROJECT_SHORT),
        Listing::Contexts => (&CONTEXT_FLAGS[..], &CONTEXT_VALUES[..], CONTEXT_SHORT),
        Listing::Manifest => (&REGISTRY_FLAGS[..], &REGISTRY_VALUES[..], REGISTRY_SHORT),
        Listing::Volumes => (&VOLUME_FLAGS[..], &VOLUME_VALUES[..], VOLUME_SHORT),
        Listing::Networks => (&NETWORK_FLAGS[..], &NETWORK_VALUES[..], NETWORK_SHORT),
        Listing::Disk => (&DISK_FLAGS[..], &DISK_VALUES[..], DISK_SHORT),
        Listing::Stats => (&STATS_FLAGS[..], &STATS_VALUES[..], STATS_SHORT),
    };
    let mut positionals = 0usize;
    let mut bounded = false;
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
        if shared.contains(&word) || flags.contains(&word) {
            bounded |= word == "--no-stream";
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
            // Only a `--format` value is a template evaluated over the record
            // behind a row. A filter value selects rows and prints nothing of
            // its own, so the named-field rule does not apply to it.
            if name == "--format" && !format_fields_safe(listing, value) {
                return false;
            }
            continue;
        }
        if !short_cluster(word, short) {
            return false;
        }
    }
    // `docker images <repository[:tag]>` filters by one reference; the
    // container listing takes none. A manifest query names exactly one image.
    match listing {
        Listing::Containers
        | Listing::Builders
        | Listing::Projects
        | Listing::Contexts
        | Listing::Volumes
        | Listing::Networks
        | Listing::Disk => positionals == 0,
        Listing::Images => positionals <= 1,
        Listing::Manifest => positionals == 1,
        // A stats reading names the containers to count, or all of them, and
        // only once a `--no-stream` of its own has bounded it.
        Listing::Stats => bounded,
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

/// A `--format` template is evaluated over the whole record behind a row, not
/// over the summary the listing prints, so a listing whose records carry
/// labels or creation options admits only the fields its summary names.
///
/// A manifest query reads the published name, manifest and index. The image
/// configuration (`.Image`) can carry a build-time credential in its
/// environment, so it is not among them. A network row carries the labels it
/// was created with, and a verbose disk summary reaches the volumes and their
/// labels through `.Volumes`; both are left outside the named fields.
fn format_fields_safe(listing: Listing, value: &str) -> bool {
    let fields: &[&str] = match listing {
        Listing::Manifest => &["Name", "Manifest", "Index"],
        Listing::Networks => &["ID", "Name", "Driver", "Scope"],
        Listing::Disk => &["Type", "TotalCount", "Active", "Size", "Reclaimable"],
        _ => return true,
    };
    template_fields_safe(value, fields)
}

/// A format with no action at all is a named layout, and `json` serializes the
/// whole record, so a template has to name the fields it prints.
fn template_fields_safe(value: &str, fields: &[&str]) -> bool {
    if !value.contains("{{") {
        return false;
    }
    let mut rest = value;
    while let Some(start) = rest.find("{{") {
        if rest[..start].contains("}}") {
            return false;
        }
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return false;
        };
        if !template_action_safe(after[..end].trim(), fields) {
            return false;
        }
        rest = &after[end + 2..];
    }
    !rest.contains("}}")
}

fn template_action_safe(action: &str, fields: &[&str]) -> bool {
    let field = match action.strip_prefix("json") {
        Some(after) if after.starts_with(char::is_whitespace) => after.trim_start(),
        _ => action,
    };
    let Some(path) = field.strip_prefix('.') else {
        return false;
    };
    let mut segments = path.split('.');
    segments.next().is_some_and(|root| fields.contains(&root))
        && segments.all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
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
