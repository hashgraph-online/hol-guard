//! Read-only DigitalOcean `doctl` invocations.
//!
//! Only `version`, help and the `list`/`get` style reads in `READ_PATHS` are
//! admitted. Each table row is one command path; `|` separates the command
//! name from the aliases doctl accepts for it.
//!
//! Some reads stay on the normal review path even though they do not change
//! anything, because they print or store a credential: `auth token`,
//! `registry login`, `registry docker-config`, `kubernetes cluster kubeconfig`
//! and every `databases` read (connection URIs and user passwords). These are
//! simply absent from the table.
//!
//! `auth list` is the one `auth` path that is present. It names the contexts
//! the stored configuration holds and prints no part of their tokens, so it
//! says less about the account than `account get` -- already in the table --
//! which prints the account's email and UUID. Every other `auth` verb either
//! writes the credential store or reads a token out of it, and none is
//! listed.
//!
//! One `databases` shape is admitted beside the table, by
//! [`databases_list_arguments`]: a cluster listing whose columns the command
//! text itself names, and which are all inventory. See that function for why
//! the columns have to be spelled out. The declarative
//! `command.cloud.digitalocean.credential-exposure` rule covers the whole
//! `databases` group, so that listing also needs [`settle`] to lift the
//! review that rule puts on it.
//!
//! The flags `--access-token`/`-t`, `--api-url`/`-u`, `--config`/`-c`,
//! `--trace` and `--show` are never admitted. They put a token on the command
//! line, send the stored token to another endpoint, load another account,
//! log the request traffic or unmask secret values.

const READ_PATHS: &str = "\
account get|g
apps|app|a get|g
apps|app|a list|ls
apps|app|a get-deployment|gd
apps|app|a list-deployments|lsd
apps|app|a list-job-invocations|lsji
apps|app|a get-job-invocation|gji
apps|app|a list-events|lse
apps|app|a get-event|ge
apps|app|a list-instances|i
apps|app|a list-regions
apps|app|a list-alerts|la
apps|app|a list-buildpacks
apps|app|a tier list|ls
apps|app|a tier get
apps|app|a tier instance-size list|ls
apps|app|a tier instance-size get
auth list|ls
balance get|g
billing-history|bh list|ls
invoice get|g
invoice list|ls
invoice summary|s
compute action get|g
compute action list|ls
compute cdn list|ls
compute cdn get|g
compute certificate get|g
compute certificate list|ls
compute droplet-action|da get|g
compute droplet|d get|g
compute droplet|d list|ls
compute droplet|d 1-click list|ls
compute droplet|d backup-policies get
compute droplet|d backup-policies list|ls
compute droplet|d backup-policies list-supported
compute droplet-autoscale|das get
compute droplet-autoscale|das list|ls
compute droplet-autoscale|das list-members
compute droplet-autoscale|das list-history
compute domain list|ls
compute domain get|g
compute domain records list|ls
compute microvm list|ls
compute microvm get|g
compute microvm checkpoint|checkpoints|cp list|ls
compute microvm checkpoint|checkpoints|cp get|g
compute vpc-nat-gateway|vng get
compute vpc-nat-gateway|vng list|ls
compute firewall get|g
compute firewall list|ls
compute firewall list-by-droplet
compute reserved-ip|fip|floating-ip|floating-ips|reserved-ips get|g
compute reserved-ip|fip|floating-ip|floating-ips|reserved-ips list|ls
compute reserved-ip-action|fipa|floating-ip-action|floating-ip-actions|reserved-ip-actions get
compute reserved-ipv6|reserved-ipv6s get|g
compute reserved-ipv6|reserved-ipv6s list|ls
compute image list|ls
compute image list-distribution
compute image list-application
compute image list-user
compute image get
compute image-action get
compute load-balancer|lb get|g
compute load-balancer|lb list|ls
compute plugin|p list|ls
compute region list|ls
compute size list|ls
compute snapshot|s list|ls
compute snapshot|s get|g
compute ssh-key|k list|ls
compute ssh-key|k get|g
compute tag get
compute tag list|ls
compute volume list|ls
compute volume get|g
compute volume-action get
compute volume-action list|ls
kubernetes|kube|k8s|k cluster|clusters|c get|g
kubernetes|kube|k8s|k cluster|clusters|c list|ls
kubernetes|kube|k8s|k cluster|clusters|c get-upgrades|gu
kubernetes|kube|k8s|k cluster|clusters|c list-associated-resources|ar
kubernetes|kube|k8s|k cluster|clusters|c node-pool|node-pools|nodepool|nodepools|pool|pools|np|p get|g
kubernetes|kube|k8s|k cluster|clusters|c node-pool|node-pools|nodepool|nodepools|pool|pools|np|p list|ls
kubernetes|kube|k8s|k options|opts|o versions|v
kubernetes|kube|k8s|k options|opts|o regions|r
kubernetes|kube|k8s|k options|opts|o sizes|s
kubernetes|kube|k8s|k 1-click list|ls
projects list|ls
projects get|g
projects resources list|ls
projects resources get|g
version
registry|reg|r get|g
registry|reg|r repository|repo|r list|ls
registry|reg|r repository|repo|r list-v2|ls2
registry|reg|r repository|repo|r list-tags|lt
registry|reg|r repository|repo|r list-manifests|lm
registry|reg|r garbage-collection|gc|g get-active|ga|g
registry|reg|r garbage-collection|gc|g list|ls|l
registry|reg|r options|opts|o subscription-tiers|tiers
registry|reg|r options|opts|o available-regions|regions
registries|regs|rs list|ls
registries|regs|rs get|g
registries|regs|rs repository|repo|r list|ls
registries|regs|rs repository|repo|r list-v2|ls2
registries|regs|rs repository|repo|r list-tags|lt
registries|regs|rs repository|repo|r list-manifests|lm
registries|regs|rs garbage-collection|gc|g get-active|ga|g
registries|regs|rs garbage-collection|gc|g list|ls|l
registries|regs|rs options|opts|o subscription-tiers|tiers
registries|regs|rs options|opts|o available-regions|regions
vpcs get|g
vpcs list|ls
vpcs peerings get|g
vpcs peerings list|ls
network attachment get|g
network attachment list|ls
network attachment list-routes|ls-routes
network byoip-prefix|byoip-prefixes get|g
network byoip-prefix|byoip-prefixes list|ls
1-click list|ls
monitoring alert|alerts|a get
monitoring alert|alerts|a list|ls
monitoring uptime get|g
monitoring uptime list|ls
monitoring uptime alert|alerts get|g
monitoring uptime alert|alerts list|ls
nfs get
nfs list|ls
nfs snapshot get
nfs snapshot list|ls
nfs access-point get
nfs access-point list|ls";

/// Global value flags that may precede the command path.
const GLOBAL_VALUE_FLAGS: [&str; 6] = [
    "-o",
    "--output",
    "--context",
    "--http-retry-max",
    "--http-retry-wait-max",
    "--http-retry-wait-min",
];

/// Long flags that are never admitted, wherever they appear.
const DENIED_LONG_FLAGS: [&str; 5] = [
    "--access-token",
    "--api-url",
    "--config",
    "--trace",
    "--show",
];

/// The declarative rule that reviews every `doctl` command printing or
/// storing a credential. It covers the `databases` group as a whole, because
/// a cluster's connection string and its users' passwords are read through
/// that group.
const CREDENTIAL_EXPOSURE_RULE: &str = "command.cloud.digitalocean.credential-exposure";

pub(crate) const SETTLE_REASON: &str = "native_exact_safe_doctl_cluster_listing";

/// Lifts the review `command.cloud.digitalocean.credential-exposure` puts on
/// the `databases` group once every segment it covers is a cluster listing
/// that names its own columns and they are all inventory
/// ([`databases_list_arguments`]). The rule is right about the group: a
/// connection string and a user password are both read through it. It is read
/// off the command path alone, though, so it cannot see that this particular
/// listing asked for identifiers, engines and regions and nothing else.
///
/// Only that rule's own review is lifted. Another rule effective on the
/// command, an extension permission the user keeps under review, an uncertain
/// match, a failed evaluation or a sensitive target all keep their verdict,
/// and a command the rule does not review is left as it is.
pub(super) fn settle(
    result: &mut guard_contracts::PreToolResultV1,
    model: Option<&crate::CanonicalCommandV1>,
    controls: Option<&crate::native_command_controls::CompiledNativeCommandControls>,
) {
    if result.minimum_action != "review"
        || result.reason_code != "native_command_extension_review"
        || result.action.action_type != guard_contracts::PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let (Some(model), Some(extensions)) = (model, result.command_extensions.as_ref()) else {
        return;
    };
    if extensions.evaluation_error.is_some() || extensions.binding.uncertainty_count != 0 {
        return;
    }
    if !extensions
        .permission_observations
        .iter()
        .all(|observation| {
            observation.uncertainty_reasons.is_empty()
                && controls.is_some_and(|controls| {
                    controls.permission_settles_at_allow(
                        &observation.extension_id,
                        &observation.permission_id,
                    )
                })
        })
    {
        return;
    }
    let mut listing_seen = false;
    for observation in &extensions.observations {
        if !observation.uncertainty_reasons.is_empty() {
            return;
        }
        // A rule that matched without becoming effective asks for nothing, so
        // it holds nothing back.
        if observation.effective_segment_indexes.is_empty() {
            continue;
        }
        if observation.rule_id != CREDENTIAL_EXPOSURE_RULE {
            if controls.is_some_and(|controls| controls.rule_settles_at_allow(&observation.rule_id))
            {
                continue;
            }
            return;
        }
        for index in &observation.effective_segment_indexes {
            match model.segments.get(*index) {
                Some(segment) if cluster_listing(segment) => listing_seen = true,
                _ => return,
            }
        }
    }
    if !listing_seen {
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = SETTLE_REASON.into();
    result.reason = concat!(
        "The Rust command authority proved this lists DigitalOcean database clusters with the ",
        "columns the command itself names, and that every one of them is cluster inventory ",
        "rather than a connection string or a password.",
    )
    .into();
}

/// A `doctl` segment that is a cluster listing of named inventory columns and
/// nothing else: no wrapper, no leading environment assignment and no `PATH`
/// of its own, since each of those decides which program actually runs.
///
/// A trailing `2>&1` only joins the listing's own stderr to its stdout, so the
/// proof reads the segment without it, the way the exact-safe pass does.
fn cluster_listing(segment: &crate::CommandSegmentV1) -> bool {
    let stripped = super::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    matches!(segment.executable.as_deref(), Some("doctl" | "doctl.exe"))
        && segment.environment_names.is_empty()
        && !segment.path_overridden
        && segment.wrapper_chain.is_empty()
        && !super::sensitive_command(&segment.text)
        && databases_list_arguments(&segment.arguments)
}

pub(super) fn safe_doctl_arguments(arguments: &[String]) -> bool {
    help_arguments(arguments) || read_arguments(arguments) || databases_list_arguments(arguments)
}

/// The spellings `doctl databases` answers to.
const DATABASE_GROUPS: [&str; 5] = ["databases", "database", "dbs", "db", "d"];

/// Columns of `doctl databases list` that name only cluster inventory. The
/// command's own `--format` vocabulary adds `URI`, which is the connection
/// string, so that one is absent here.
const INVENTORY_COLUMNS: [&str; 10] = [
    "id",
    "name",
    "engine",
    "version",
    "numnodes",
    "region",
    "status",
    "size",
    "created",
    "storagemib",
];

/// A cluster listing whose columns are all inventory: which clusters exist,
/// what they run and where. Nothing in that output names a credential, so
/// asking about it interrupts ordinary infrastructure work for nothing.
///
/// The columns have to be named in the command. A bare `databases list`
/// leaves them to whatever `doctl` prints by default, which Guard cannot read
/// off the command text and which is free to change between releases, so that
/// spelling keeps its review. `-o`/`--output` is refused outright: the JSON
/// form prints the API object rather than the chosen columns, and a cluster
/// carries `connection`, `ui_connection`, `private_connection`,
/// `standby_connection` and `users`, each with a password in it.
fn databases_list_arguments(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-v" | "--verbose" => index += 1,
            "--context" if arguments.len() > index + 1 => index += 2,
            _ if argument.starts_with("--context=") => index += 1,
            _ => break,
        }
    }
    let Some(group) = arguments.get(index) else {
        return false;
    };
    if !DATABASE_GROUPS.contains(&group.as_str()) {
        return false;
    }
    if !arguments
        .get(index + 1)
        .is_some_and(|word| matches!(word.as_str(), "list" | "ls"))
    {
        return false;
    }
    named_inventory_columns(&arguments[index + 2..])
}

/// True when the listing's remaining words are `--no-header` and at least one
/// `--format` naming inventory columns only.
fn named_inventory_columns(arguments: &[String]) -> bool {
    let mut index = 0;
    let mut named = false;
    while let Some(argument) = arguments.get(index) {
        let columns = if argument == "--no-header" {
            index += 1;
            continue;
        } else if argument == "--format" {
            index += 2;
            match arguments.get(index - 1) {
                Some(value) => value.as_str(),
                None => return false,
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            index += 1;
            value
        } else {
            return false;
        };
        if !columns.split(',').all(inventory_column) {
            return false;
        }
        named = true;
    }
    named
}

fn inventory_column(column: &str) -> bool {
    INVENTORY_COLUMNS.contains(&column.to_ascii_lowercase().as_str())
}

fn help_arguments(arguments: &[String]) -> bool {
    match arguments {
        [path @ .., flag] if matches!(flag.as_str(), "--help" | "-h") => {
            path.len() <= 4 && path.iter().all(|word| subcommand_word(word))
        }
        _ => false,
    }
}

fn read_arguments(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if !argument.starts_with('-') {
            break;
        }
        match leading_flag_width(argument, arguments.get(index + 1).is_some()) {
            Some(width) => index += width,
            None => return false,
        }
    }
    let remaining = &arguments[index..];
    read_path_depth(remaining).is_some_and(|depth| trailing_arguments_safe(&remaining[depth..]))
}

fn leading_flag_width(argument: &str, has_value: bool) -> Option<usize> {
    if matches!(argument, "-v" | "--verbose") {
        return Some(1);
    }
    if GLOBAL_VALUE_FLAGS.contains(&argument) {
        return has_value.then_some(2);
    }
    let attached = argument
        .split_once('=')
        .is_some_and(|(name, _)| name.starts_with("--") && GLOBAL_VALUE_FLAGS.contains(&name));
    (attached || (argument.starts_with("-o") && argument.len() > 2)).then_some(1)
}

fn read_path_depth(arguments: &[String]) -> Option<usize> {
    READ_PATHS.lines().find_map(|row| {
        let words: Vec<&str> = row.split_whitespace().collect();
        let matched = arguments.len() >= words.len()
            && words.iter().zip(arguments).all(|(spellings, argument)| {
                spellings.split('|').any(|spelling| spelling == argument)
            });
        matched.then_some(words.len())
    })
}

fn trailing_arguments_safe(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        if argument == "--" || !argument.starts_with('-') {
            return true;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(name, _)| name);
            return !name.is_empty()
                && !DENIED_LONG_FLAGS
                    .iter()
                    .any(|denied| denied.trim_start_matches('-') == name);
        }
        matches!(argument.as_str(), "-h" | "-v") || argument.starts_with("-o")
    })
}

fn subcommand_word(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

#[cfg(test)]
mod tests {
    use super::{safe_doctl_arguments, READ_PATHS};

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn admits_version_help_and_list_get_reads() {
        for command in [
            "version",
            "--help",
            "-h",
            "compute droplet delete --help",
            "account get",
            "auth list",
            "auth ls",
            "auth list --format Name",
            "apps list",
            "apps get 0f1e --output json",
            "kubernetes cluster list",
            "k8s c ls -o json",
            "registry get",
            "registry repository list-manifests web --format Digest,UpdatedAt,Tags --no-header",
            "registry repository list-tags web",
            "--output json compute droplet list --tag-name web",
            "--context staging projects list",
            "-ojson vpcs list",
            "compute ssh-key list --format ID,Name",
            "databases list --format ID,Name,Engine,Status,Region",
            "databases list --format ID,Name,Engine,Status,Region --no-header",
            "databases ls --format=id,name",
            "db list --format Size,NumNodes,StorageMib,Created,Version",
            "--context staging dbs list --format ID",
            "-v database list --format ID",
            "d list --format ID",
        ] {
            assert!(safe_doctl_arguments(&arguments(command)), "{command}");
        }
    }

    /// The listing is admitted for what its own text proves it prints. A
    /// default column set, a connection string, the JSON object, another
    /// `databases` leaf and anything else carried along keep their review.
    #[test]
    fn a_cluster_listing_is_admitted_only_for_the_columns_it_names() {
        for command in [
            "databases list",
            "databases ls",
            "databases list --no-header",
            "databases list --format",
            "databases list --format ID,URI",
            "databases list --format=uri",
            "databases list --format ID,Name --output json",
            "databases list --format ID,Name -o json",
            "databases list --format ID,Name --show",
            "databases list --format ID,Name --trace",
            "databases list --format ID,Name mycluster",
            "-o json databases list --format ID,Name",
            "databases user list --format Name,Password",
            "databases connection db1 --format URI",
            "databases get db1 --format ID,Name",
            "databases list --format ID,Name,Password",
            "databases list --format ID,,Name",
            "dbx list --format ID",
            "--config other.yaml databases list --format ID",
        ] {
            assert!(!safe_doctl_arguments(&arguments(command)), "{command}");
        }
    }

    #[test]
    fn keeps_effects_secrets_and_token_flags_on_review() {
        for command in [
            "",
            "compute droplet delete web",
            "compute droplet create web",
            "kubernetes cluster delete prod",
            "kubernetes cluster kubeconfig show prod",
            "kubernetes cluster kubeconfig save prod",
            "registry login",
            "registry docker-config",
            "registry garbage-collection start",
            "auth token",
            "auth init",
            "auth switch --context prod",
            "auth remove --context prod",
            "auth list --access-token dop_v1_x",
            "databases get db1",
            "databases connection db1",
            "apps list --access-token dop_v1_x",
            "apps list -t dop_v1_x",
            "-t dop_v1_x apps list",
            "--access-token=dop_v1_x apps list",
            "--api-url https://example.invalid apps list",
            "apps list -u https://example.invalid",
            "apps list --config other.yaml",
            "apps list --trace",
            "apps list --show",
            "--show apps list",
            "apps list -x",
            "--unknown apps list",
            "compute --verbose droplet list",
            "Apps list",
            "apps --help list",
            "a b c d e --help",
        ] {
            assert!(!safe_doctl_arguments(&arguments(command)), "{command}");
        }
    }

    #[test]
    fn read_table_only_names_list_get_and_metadata_leaves() {
        for row in READ_PATHS.lines() {
            let leaf = row.split_whitespace().last().unwrap_or_default();
            let name = leaf.split('|').next().unwrap_or_default();
            assert!(
                matches!(
                    name,
                    "list" | "get" | "version" | "versions" | "regions" | "sizes" | "summary"
                ) || name.starts_with("list-")
                    || name.starts_with("get-")
                    || name == "subscription-tiers"
                    || name == "available-regions",
                "{row}"
            );
            for denied in [
                "databases",
                "kubeconfig",
                "docker-config",
                "login",
                "key",
            ] {
                assert!(
                    !row.split_whitespace().any(|word| word.starts_with(denied)),
                    "{row}"
                );
            }
            // The `auth` group is the credential store itself. Listing the
            // contexts it holds prints no token; every other verb there
            // writes the store or reads a token out of it.
            assert!(
                !row.starts_with("auth ") || row == "auth list|ls",
                "{row}"
            );
        }
    }
}
