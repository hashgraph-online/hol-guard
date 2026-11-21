//! A delivery capability derived from the existing curl read proof, never
//! policy permission. Restrict this owner to stdout, disabled config and
//! literal HTTP IPv4 peers; DNS, TLS configuration and additional file effects
//! need their own bound delivery before they can use this route.
use std::collections::BTreeSet;
use std::net::SocketAddrV4;

use crate::pretool::PathContext;

pub fn bound_curl_read_destinations(
    argv: &[String],
    context: PathContext<'_>,
) -> Option<BTreeSet<SocketAddrV4>> {
    let (executable, arguments) = argv.split_first()?;
    if std::path::Path::new(executable).file_name()?.to_str()? != "curl"
        || !matches!(arguments.first()?.as_str(), "-q" | "--disable")
    {
        return None;
    }
    let urls = super::read_urls(arguments, context)?;
    let mut index = 1;
    let mut options = true;
    while index < arguments.len() {
        let argument = &arguments[index];
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if !options || !argument.starts_with('-') {
            index += 1;
            continue;
        }
        let name = argument.split('=').next()?;
        if name == "--ssl-reqd" {
            return None;
        }
        let plain = super::PLAIN_FLAGS.contains(&name)
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..]
                    .chars()
                    .all(|flag| super::SHORT_FLAGS.contains(flag)));
        if !plain && !super::NUMERIC_OPTIONS.contains(&name) && name != "--url" {
            return None;
        }
        index += super::option_consumed(arguments, index, context)?;
    }
    urls.into_iter()
        .map(|raw| {
            let url = url::Url::parse(raw).ok()?;
            if url.scheme() != "http"
                || url.query_pairs().any(|(name, _)| {
                    let name = name.to_ascii_lowercase();
                    super::CREDENTIAL_TERMS
                        .iter()
                        .any(|term| name.contains(term))
                })
            {
                return None;
            }
            let url::Host::Ipv4(address) = url.host()? else {
                return None;
            };
            // Avoid differences between URL parsers for numeric aliases, omitted
            // schemes and unusual port spellings. The kernel receives this peer.
            let authority = raw.strip_prefix("http://")?.split(['/', '?', '#']).next()?;
            let canonical = match url.port() {
                Some(port) => format!("{address}:{port}"),
                None => address.to_string(),
            };
            if authority != canonical {
                return None;
            }
            Some(SocketAddrV4::new(address, url.port_or_known_default()?))
        })
        .collect()
}

#[cfg(test)]
#[path = "curl_reads_bound_tests.rs"]
mod tests;
