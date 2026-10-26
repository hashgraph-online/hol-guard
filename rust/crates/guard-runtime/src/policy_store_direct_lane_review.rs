//! The daemon facts a reviewed `PreToolUse` is queued for approval with.
//!
//! The publisher binds what the daemon reads when it pauses such a hook: the
//! blocked-request mode, the approval center origin, the connection source a
//! queued request is bound to, and the working directory the action envelope
//! is rebuilt with. Each fact is checked here on its own, and one that is
//! absent or not acceptable reads as `None`, so the hook that needs it keeps
//! taking the daemon path while the rest of the lane stays open.

/// Advertised once the direct-lane binding accepts the review facts. The
/// publisher sends them only to a resident that advertises it, since an older
/// one rejects the unknown fields with the whole push.
pub(crate) const HOOK_DIRECT_REVIEW_FACTS_FEATURE: &str = "hook-direct-review-facts-v1";
/// The modes `blocked_request_mode` accepts in Guard config.
const BLOCKED_REQUEST_MODES: [&str; 2] = ["ask", "safe-alternative"];
const MAX_REVIEW_FACT_BYTES: usize = 256;
const MAX_HOST_CWD_BYTES: usize = 4096;
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DirectLaneReviewFacts {
    /// `ask` or `safe-alternative`, as every bound config resolves it.
    pub(crate) blocked_request_mode: Option<String>,
    /// An `http://` origin on a loopback host.
    pub(crate) approval_center_origin: Option<String>,
    pub(crate) review_oauth_source: Option<String>,
    pub(crate) review_host_cwd: Option<String>,
}

impl DirectLaneReviewFacts {
    pub(crate) fn parse(
        blocked_request_mode: Option<String>,
        approval_center_origin: Option<String>,
        review_oauth_source: Option<String>,
        review_host_cwd: Option<String>,
    ) -> Self {
        Self {
            blocked_request_mode: blocked_request_mode
                .filter(|mode| BLOCKED_REQUEST_MODES.contains(&mode.as_str())),
            approval_center_origin: approval_center_origin
                .filter(|origin| loopback_http_origin(origin)),
            review_oauth_source: review_oauth_source
                .filter(|source| text_fact_valid(source, MAX_REVIEW_FACT_BYTES)),
            review_host_cwd: review_host_cwd.filter(|cwd| {
                !cwd.is_empty() && cwd.len() <= MAX_HOST_CWD_BYTES && !cwd.contains('\0')
            }),
        }
    }
}

fn text_fact_valid(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

/// Whether `origin` is exactly `http://host[:port]` with a loopback host,
/// the only approval center a resident may link a queued review to.
fn loopback_http_origin(origin: &str) -> bool {
    if !text_fact_valid(origin, MAX_REVIEW_FACT_BYTES) {
        return false;
    }
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    let (host, port) = match authority.rfind(':') {
        // A colon inside the brackets belongs to the IPv6 host.
        Some(index) if !authority[index..].contains(']') => {
            (&authority[..index], Some(&authority[index + 1..]))
        }
        _ => (authority, None),
    };
    let port_valid = port.is_none_or(|port| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    });
    port_valid && LOOPBACK_HOSTS.contains(&host.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::DirectLaneReviewFacts;

    fn origin(value: &str) -> Option<String> {
        DirectLaneReviewFacts::parse(None, Some(value.to_owned()), None, None)
            .approval_center_origin
    }

    #[test]
    fn loopback_http_origins_parse() {
        for value in [
            "http://127.0.0.1:4781",
            "http://[::1]:4781",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1",
        ] {
            assert_eq!(origin(value).as_deref(), Some(value), "{value}");
        }
    }

    #[test]
    fn other_origins_read_as_absent() {
        for value in [
            "",
            "https://127.0.0.1:4781",
            "http://192.168.1.10:4781",
            "http://0.0.0.0:4781",
            "http://[::]:4781",
            "http://::1:4781",
            "http://approvals.example.com",
            "http://127.0.0.1.example.com:4781",
            "http://user@127.0.0.1:4781",
            "http://127.0.0.1:4781/",
            "http://127.0.0.1:4781/approvals",
            "http://127.0.0.1:4781?next=x",
            "http://127.0.0.1:",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:+80",
            "http://127.0.0.1:4781\n",
        ] {
            assert_eq!(origin(value), None, "{value:?}");
        }
    }

    #[test]
    fn each_fact_is_checked_on_its_own() {
        let facts = DirectLaneReviewFacts::parse(
            Some("ask".to_owned()),
            Some("http://10.0.0.1:4781".to_owned()),
            Some("default".to_owned()),
            Some("/work/repo".to_owned()),
        );
        assert_eq!(facts.blocked_request_mode.as_deref(), Some("ask"));
        assert_eq!(facts.approval_center_origin, None);
        assert_eq!(facts.review_oauth_source.as_deref(), Some("default"));
        assert_eq!(facts.review_host_cwd.as_deref(), Some("/work/repo"));

        let rejected = DirectLaneReviewFacts::parse(
            Some("prompt".to_owned()),
            None,
            Some("bad\u{7}source".to_owned()),
            Some("/work/\0repo".to_owned()),
        );
        assert_eq!(rejected, DirectLaneReviewFacts::default());
        assert_eq!(
            DirectLaneReviewFacts::parse(None, None, None, Some("/".repeat(4097))).review_host_cwd,
            None
        );
    }
}
