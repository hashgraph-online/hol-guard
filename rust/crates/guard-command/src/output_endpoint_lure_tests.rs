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
