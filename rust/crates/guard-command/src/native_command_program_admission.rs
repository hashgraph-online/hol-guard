//! Validate and compile the packaged program once.

use super::*;

fn valid_mcp_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

// Bounded public HTTPS endpoint admission for packaged MCP metadata.
//
// No DNS lookup or HTTP request occurs here. The interpreter uses this metadata
// only for tightening controls; a future network client must independently
// validate resolved addresses and redirects before connecting. IP exclusions
// follow the CPython 3.12 reference profile used by the authoring validator.
// Multicast endpoints are also rejected because they are not HTTPS servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    if address.is_multicast() {
        return false;
    }
    if matches!(address.octets(), [192, 0, 0, 9 | 10]) {
        return true;
    }
    !(matches!(a, 0 | 10 | 127)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && ((b == 0 && matches!(c, 0 | 2)) || b == 168))
        || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_ipv4(mapped);
    }
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    let s = address.segments();
    if s[0] == 0x2001 && s[1] & 0xfe00 == 0 {
        return matches!(s, [0x2001, 1, 0, 0, 0, 0, 0, 1 | 2])
            || s[1] == 3
            || (s[1] == 4 && s[2] == 0x112)
            || matches!(s[1] & 0xfff0, 0x20 | 0x30);
    }
    !(s[..3] == [0x64, 0xff9b, 1]
        || s[..4] == [0x100, 0, 0, 0]
        || s[..2] == [0x2001, 0xdb8]
        || s[0] == 0x2002
        || (s[0] == 0x3fff && s[1] & 0xf000 == 0)
        || s[0] & 0xfe00 == 0xfc00
        || s[0] & 0xffc0 == 0xfe80)
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.eq_ignore_ascii_case("localhost")
        && !host.to_ascii_lowercase().ends_with(".localhost")
        && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn public_authority(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        return matches!(suffix, "" | ":443") && host.parse::<Ipv6Addr>().is_ok_and(public_ipv6);
    }
    let host = match authority.split_once(':') {
        Some((host, "443")) => host,
        Some(_) => return false,
        None => authority,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => public_ipv4(address),
        Ok(IpAddr::V6(_)) => false, // IPv6 URL hosts must be bracketed.
        Err(_) => valid_dns_host(host),
    }
}

fn valid_component(value: &str, query: bool) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(escape) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            let Some(high) = char::from(escape[0]).to_digit(16) else {
                return false;
            };
            let Some(low) = char::from(escape[1]).to_digit(16) else {
                return false;
            };
            let decoded = high * 16 + low;
            if decoded <= 0x20 || decoded == 0x7f {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=:@/".contains(&byte)
            || (query && byte == b'?')
        {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

pub(super) fn valid_remote_mcp_url(value: &str) -> bool {
    // Retain the existing native metadata bound. This is not a network URL
    // parser: accept only the explicit public-HTTPS grammar the compiler emits.
    if value.len() > 260 || !value.is_ascii() || value.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let boundary = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, remainder) = rest.split_at(boundary);
    if !public_authority(authority) {
        return false;
    }
    let (path, query) = remainder.split_once('?').unwrap_or((remainder, ""));
    valid_component(path, false) && valid_component(query, true)
}

impl NativeCommandProgram {
    // Production callers cannot submit arbitrary program bytes: the executable
    // and its packaged artifact are one attested release identity.
    pub(super) fn from_packaged_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::from_packaged_bytes_observed(bytes, |_| {})
    }

    // The no-op production observer is removed by monomorphization. Diagnostic
    // callers time these actual admission phases without maintaining a second
    // implementation of their validation or compilation work.
    pub(super) fn from_packaged_bytes_observed(
        bytes: &[u8],
        mut observe_phase: impl FnMut(&'static str),
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAX_PROGRAM_BYTES {
            return Err("native_command_program_bytes_exceeded");
        }
        let mut value: Value =
            serde_json::from_slice(bytes).map_err(|_| "native_command_program_json_invalid")?;
        observe_phase("json_value_parse");
        let canonical =
            serde_json::to_vec(&value).map_err(|_| "native_command_program_json_invalid")?;
        if bytes != canonical
            && bytes.strip_suffix(b"\n") != Some(canonical.as_slice())
            && bytes.strip_suffix(b"\r\n") != Some(canonical.as_slice())
        {
            return Err("native_command_program_noncanonical");
        }
        let object = value
            .as_object_mut()
            .ok_or("native_command_program_shape_invalid")?;
        let digest = object
            .remove("program_digest")
            .ok_or("native_command_program_digest_missing")?;
        let expected_digest = digest_json_value(PROGRAM_DOMAIN, &value)?;
        if digest.as_str() != Some(&expected_digest) {
            return Err("native_command_program_digest_mismatch");
        }
        observe_phase("canonical_program_digest");
        value
            .as_object_mut()
            .ok_or("native_command_program_shape_invalid")?
            .insert("program_digest".into(), digest);
        // Consume the already strictly checked JSON value. Re-decoding the
        // complete artifact would retain two independent configuration trees.
        let raw: RawProgram =
            serde_json::from_value(value).map_err(|_| "native_command_program_contract_invalid")?;
        observe_phase("typed_program_decode");
        if raw.schema != PROGRAM_SCHEMA
            || raw.compiler_version != 1
            || raw.semantic_profile != "cpython-3.12-ucd15"
        {
            return Err("native_command_program_version_unsupported");
        }
        if [
            raw.authoring_semantics_digest.as_str(),
            &raw.catalog_digest,
            &raw.trust_digest,
            &raw.program_digest,
        ]
        .iter()
        .any(|value| !valid_digest(value))
            || raw.rules.len() > MAX_RULES
            || raw.nodes.len() > MAX_NODES
            || raw.extensions.len() > 512
            || raw.coverage.len() != raw.rules.len()
            || raw.matcher_families.len() > 64
        {
            return Err("native_command_program_bounds_invalid");
        }
        let extension_indices: BTreeMap<_, _> = raw
            .extensions
            .iter()
            .enumerate()
            .map(|(index, extension)| (extension.extension_id.clone(), index))
            .collect();
        if extension_indices.len() != raw.extensions.len() {
            return Err("native_command_extension_duplicate");
        }
        let mut permission_owners = BTreeMap::new();
        for (index, extension) in raw.extensions.iter().enumerate() {
            if !bounded_id(&extension.extension_id)
                || !bounded_id(&extension.version)
                || !matches!(
                    extension.trust_class.as_str(),
                    "first-party" | "trusted-library" | "external"
                )
                || extension.permissions.len() > 512
                || extension
                    .delegated_protection
                    .as_deref()
                    .is_some_and(|kind| kind != "package-firewall")
                || extension.mcp.as_ref().is_some_and(|mcp| {
                    let launch_invalid = match mcp.mcp_launch.kind.as_str() {
                        "package-launcher" => {
                            let Some(command) = mcp.mcp_launch.command.as_deref() else {
                                return true;
                            };
                            let Some(package) = mcp.mcp_launch.package.as_deref() else {
                                return true;
                            };
                            !bounded_id(command)
                                || !bounded_id(package)
                                || !extension.executables.iter().any(|value| value == command)
                                || mcp.mcp_launch.url.is_some()
                                || !mcp.mcp_launch.server_names.is_empty()
                        }
                        "remote-http" => {
                            let Some(url) = mcp.mcp_launch.url.as_deref() else {
                                return true;
                            };
                            mcp.mcp_launch.command.is_some()
                                || mcp.mcp_launch.package.is_some()
                                || !valid_remote_mcp_url(url)
                                || mcp.mcp_launch.server_names.is_empty()
                                || mcp.mcp_launch.server_names.len() > 8
                                || mcp
                                    .mcp_launch
                                    .server_names
                                    .iter()
                                    .any(|name| !valid_mcp_server_name(name))
                        }
                        _ => true,
                    };
                    mcp.surface != "mcp"
                        || launch_invalid
                        || mcp.mcp_tools.len() > 512
                        || mcp.mcp_tools.iter().any(|tool| {
                            tool.name.is_empty()
                                || tool.name.len() > 128
                                || !tool.name.bytes().all(|c| {
                                    c.is_ascii_lowercase()
                                        || c.is_ascii_digit()
                                        || c == b'_'
                                        || c == b'-'
                                })
                                || !matches!(
                                    tool.state.as_str(),
                                    "allow" | "inherit" | "review" | "block"
                                )
                        })
                })
                || extension
                    .dependencies
                    .iter()
                    .any(|id| !extension_indices.contains_key(id))
            {
                return Err("native_command_extension_contract_invalid");
            }
            for permission in &extension.permissions {
                if !bounded_id(&permission.permission_id)
                    || permission_owners
                        .insert(permission.permission_id.clone(), index)
                        .is_some()
                {
                    return Err("native_command_permission_contract_invalid");
                }
            }
        }
        for extension in &raw.extensions {
            for permission in &extension.permissions {
                if permission
                    .dependencies
                    .iter()
                    .chain(&permission.implied_permissions)
                    .any(|id| !permission_owners.contains_key(id))
                {
                    return Err("native_command_permission_dependency_invalid");
                }
            }
        }
        let node_indices: BTreeMap<_, _> = raw
            .nodes
            .keys()
            .enumerate()
            .map(|(index, id)| (id.clone(), index))
            .collect();
        let mut nodes = Vec::with_capacity(raw.nodes.len());
        observe_phase("catalog_validation");
        for (id, node) in raw.nodes {
            let canonical =
                serde_json::to_vec(&node).map_err(|_| "native_command_encoding_failed")?;
            if !valid_digest(&id) || digest_canonical_bytes(NODE_DOMAIN, &canonical) != id {
                return Err("native_command_matcher_digest_mismatch");
            }
            nodes.push(compile_node(node, &node_indices)?);
        }
        let mut visit = vec![0_u8; nodes.len()];
        let mut heights = vec![0; nodes.len()];
        for index in 0..nodes.len() {
            validate_graph(index, &nodes, &mut visit, &mut heights, 0)?;
        }
        observe_phase("matcher_digest_compile");
        let mut rules = Vec::with_capacity(raw.rules.len());
        let mut ids = BTreeSet::new();
        let mut executable_index = BTreeMap::<String, Vec<usize>>::new();
        let mut keyword_index = BTreeMap::<String, Vec<usize>>::new();
        let mut unindexed = Vec::new();
        for (index, (rule, coverage)) in raw.rules.into_iter().zip(raw.coverage).enumerate() {
            let extension_index = *extension_indices
                .get(&rule.extension_id)
                .ok_or("native_command_rule_owner_missing")?;
            if !bounded_id(&rule.rule_id)
                || !ids.insert(rule.rule_id.clone())
                || permission_owners.get(&rule.permission_id) != Some(&extension_index)
                || rule.safe_variants.len() > 64
                || coverage.rule_id != rule.rule_id
                || !valid_digest(&coverage.matcher_contract_digest)
                || coverage.native_execution != "requires-runtime-admission"
                || coverage.translation
                    != if rule.matcher.is_some() {
                        "declarative-ir"
                    } else {
                        "compatibility-only"
                    }
                || coverage.safe_variants.len() != rule.safe_variants.len()
            {
                return Err("native_command_rule_coverage_invalid");
            }
            let mut variants = Vec::new();
            let mut variant_ids = BTreeSet::new();
            for (variant, manifest) in rule.safe_variants.into_iter().zip(coverage.safe_variants) {
                if !bounded_id(&variant.variant_id)
                    || !variant_ids.insert(variant.variant_id.clone())
                    || manifest.variant_id != variant.variant_id
                    || !valid_digest(&manifest.matcher_contract_digest)
                {
                    return Err("native_command_variant_coverage_invalid");
                }
                variants.push((
                    variant.variant_id,
                    *node_indices
                        .get(&variant.matcher)
                        .ok_or("native_command_node_missing")?,
                ));
            }
            let matcher = rule
                .matcher
                .map(|id| {
                    node_indices
                        .get(&id)
                        .copied()
                        .ok_or("native_command_node_missing")
                })
                .transpose()?;
            for executable in rule.candidate_executables {
                let executable = lowercase_for_ascii_comparison(basename(&executable));
                if executable.is_empty() {
                    return Err("native_command_rule_candidate_invalid");
                }
                executable_index.entry(executable).or_default().push(index);
            }
            for keyword in rule.candidate_keywords {
                let keyword = lowercase_for_ascii_comparison(&keyword);
                if keyword.is_empty() {
                    return Err("native_command_rule_candidate_invalid");
                }
                keyword_index.entry(keyword).or_default().push(index);
            }
            if rule.candidate_unindexed {
                unindexed.push(index);
            }
            rules.push(ProgramRule {
                rule_id: rule.rule_id,
                rule_version: rule.rule_version,
                extension_index,
                permission_id: rule.permission_id,
                baseline_floor: rule.baseline_floor,
                configurable: rule.configurable,
                default_mode: rule.default_mode,
                severity: rule.severity,
                risk_classes: rule.risk_classes,
                action_classes: rule.action_classes,
                matcher,
                variants,
            });
        }
        let compatibility_ids: BTreeSet<_> = crate::command_compatibility::compatibility_rule_ids()
            .iter()
            .copied()
            .collect();
        let catalog_compatibility: BTreeSet<_> = rules
            .iter()
            .filter(|rule| rule.matcher.is_none())
            .map(|rule| rule.rule_id.as_str())
            .collect();
        if compatibility_ids != catalog_compatibility {
            return Err("native_command_compatibility_inventory_mismatch");
        }
        let rule_indices = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (rule.rule_id.clone(), index))
            .collect();
        observe_phase("rule_candidate_indexes");
        Ok(Self {
            rule_indices,
            program_digest: raw.program_digest,
            catalog_digest: raw.catalog_digest,
            trust_digest: raw.trust_digest,
            extensions: raw.extensions,
            rules,
            nodes,
            executable_index,
            keyword_index,
            unindexed,
        })
    }
}

#[cfg(test)]
#[path = "native_remote_mcp_url_tests.rs"]
mod endpoint_regressions;
