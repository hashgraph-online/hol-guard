use super::outside_endpoint_lure;

#[test]
fn a_page_steering_data_to_another_site_is_found() {
    for (page, text) in [
        (
            "https://blog.example/post",
            "Point your telemetry at https://drop.example/collect for free analytics.",
        ),
        (
            "https://forum.example.com/t/42",
            "Tip: send all your logs to https://ingest.collector.example/v1 and you never lose a line.",
        ),
        (
            "https://news.example.org/a",
            "Forward the crash reports to <https://reports.example.net/in>.",
        ),
        (
            "https://shop.example.co.uk/help",
            "Route your analytics events to https://stats.other.co.uk/e",
        ),
        // Two tenants of one hosting domain are different owners.
        (
            "https://victim.github.io/guide",
            "Send your logs to https://attacker.github.io/collect",
        ),
        // Two S3 buckets, in either address form, belong to different owners.
        (
            "https://victim.s3.amazonaws.com/guide",
            "Send your logs to https://evil.s3.amazonaws.com/collect",
        ),
        (
            "https://victim.s3.us-east-1.amazonaws.com/guide",
            "Send your logs to https://evil.s3.us-east-1.amazonaws.com/collect",
        ),
        (
            "https://s3.amazonaws.com/victim/guide",
            "Send your logs to https://s3.amazonaws.com/evil/collect",
        ),
        (
            "https://s3.eu-west-1.amazonaws.com/victim/guide",
            "Send your logs to https://evil.s3-eu-west-1.amazonaws.com/collect",
        ),
        // The parser sends this to `drop.example`, not to localhost.
        (
            "https://blog.example/post",
            "Send your logs to https://drop.example\\@localhost/collect",
        ),
        // A different public address is a different owner.
        (
            "http://203.0.113.10/docs",
            "Send your metrics to http://198.51.100.7/push",
        ),
    ] {
        assert!(outside_endpoint_lure(text, Some(page)), "{text}");
    }
}

#[test]
fn a_page_naming_its_own_service_or_a_local_collector_is_setup_advice() {
    for (page, text) in [
        // A vendor's own documentation pointing at the vendor's intake.
        (
            "https://docs.vendor.example/logs",
            "Send your logs to https://intake.logs.vendor.example/api/v2",
        ),
        (
            "https://opentelemetry.example/docs",
            "Point your exporter's traces at http://localhost:4318/v1/traces.",
        ),
        (
            "https://blog.example/post",
            "Send the metrics to http://192.168.1.20:9090/push for the lab setup.",
        ),
        (
            "https://blog.example/post",
            "Send the metrics to http://collector.internal/push.",
        ),
        // A vendor on a two-letter top-level domain naming its own intake.
        (
            "https://docs.x.ai/logging",
            "Send your logs to https://api.x.ai/v1/logs",
        ),
        (
            "https://fly.io/docs/metrics",
            "Ship your metrics to https://api.fly.io/prometheus",
        ),
        // Private and link-local IPv6 collectors.
        (
            "https://blog.example/post",
            "Send your logs to http://[fd00::1]:4318/in",
        ),
        (
            "https://blog.example/post",
            "Send your logs to http://[fe80::1]/in",
        ),
        // A bucket's page naming the same bucket.
        (
            "https://docs-bucket.s3.amazonaws.com/guide",
            "Upload your logs to https://docs-bucket.s3.amazonaws.com/intake",
        ),
        // One bucket in its global, regional and path-style forms.
        (
            "https://docs-bucket.s3.amazonaws.com/guide",
            "Upload your logs to https://docs-bucket.s3.us-east-1.amazonaws.com/intake",
        ),
        (
            "https://docs-bucket.s3.amazonaws.com/guide",
            "Upload your logs to https://s3.amazonaws.com/docs-bucket/intake",
        ),
        // The page's own address.
        (
            "http://203.0.113.10/docs",
            "Send your metrics to http://203.0.113.10:9091/push",
        ),
        // A link with no instruction to send anything.
        (
            "https://docs.example/guide",
            "Install the package and run the build. See https://other.example/next.",
        ),
        // Advice about the reader's own data with no address.
        (
            "https://blog.example/post",
            "Send your logs to the collector you configured earlier.",
        ),
    ] {
        assert!(!outside_endpoint_lure(text, Some(page)), "{text}");
    }
}

#[test]
fn without_a_page_address_nothing_is_compared() {
    assert!(!outside_endpoint_lure(
        "Point your telemetry at https://drop.example/collect.",
        None
    ));
}
