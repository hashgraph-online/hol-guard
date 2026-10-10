//! Native catalog read-model benchmark over one corpus envelope.
//!
//! `cargo run --release -p guard-command --example catalog_read_bench -- CORPUS.json [ITERATIONS]`
//!
//! Prints one JSON object: snapshot build time and retained bytes, then
//! timings for full index traversal, every detail, every collection traversal,
//! catalog-wide permission search and unchanged revalidation. Corpora come from
//! `scripts/catalog_delivery_corpus.py`.

use std::time::{Duration, Instant};

use guard_command::catalog_read_model::{CatalogReadRequestV1, CatalogReadSnapshot};
use serde_json::{json, Value};

fn request(route: &str, query: &str, etag: Option<&str>, digest: &str) -> CatalogReadRequestV1 {
    CatalogReadRequestV1 {
        schema: "guard-catalog-read-request.v1".into(),
        route: route.into(),
        query: query.into(),
        if_none_match: etag.map(str::to_owned),
        expected_catalog_digest: digest.into(),
    }
}

struct Traversal {
    pages: usize,
    bytes: usize,
    ids: Vec<String>,
}

fn traverse(snapshot: &CatalogReadSnapshot, route: &str, limit: usize, id_key: &str) -> Traversal {
    traverse_query(snapshot, route, &format!("limit={limit}"), id_key)
}

fn traverse_query(
    snapshot: &CatalogReadSnapshot,
    route: &str,
    base: &str,
    id_key: &str,
) -> Traversal {
    let digest = snapshot.catalog_digest();
    let (mut pages, mut bytes, mut ids, mut cursor) = (0, 0, Vec::new(), None::<String>);
    loop {
        let query = match &cursor {
            Some(cursor) => format!("{base}&cursor={cursor}"),
            None => base.to_owned(),
        };
        let result = snapshot.read(&request(route, &query, None, digest));
        let body = result
            .body
            .unwrap_or_else(|| panic!("{route}: {:?}", result.error_code));
        pages += 1;
        bytes += body.len();
        let page: Value = serde_json::from_str(&body).expect("page json");
        for item in page["items"].as_array().expect("items") {
            ids.push(item[id_key].as_str().expect("id").to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Traversal { pages, bytes, ids },
        }
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: catalog_read_bench CORPUS.json [ITERATIONS]");
    let iterations: usize = args
        .next()
        .map_or(5, |value| value.parse().expect("iterations"));
    let bytes = std::fs::read(&path).expect("read corpus");

    let started = Instant::now();
    let snapshot = match CatalogReadSnapshot::from_catalog_bytes(&bytes) {
        Ok(snapshot) => snapshot,
        Err(code) => {
            println!(
                "{}",
                json!({"corpus": path, "corpus_bytes": bytes.len(), "admitted": false, "error": code})
            );
            return;
        }
    };
    let build_ms = millis(started.elapsed());
    let mut builds = vec![build_ms];
    for _ in 1..iterations {
        let started = Instant::now();
        let _ = CatalogReadSnapshot::from_catalog_bytes(&bytes).expect("rebuild");
        builds.push(millis(started.elapsed()));
    }
    let digest = snapshot.catalog_digest().to_owned();

    let mut index_runs = Vec::new();
    let mut index = traverse(&snapshot, "index", 100, "extension_id");
    for _ in 0..iterations {
        let started = Instant::now();
        index = traverse(&snapshot, "index", 100, "extension_id");
        index_runs.push(millis(started.elapsed()));
    }
    let first = snapshot.read(&request("index", "limit=50", None, &digest));
    let first_page_bytes = first.body.as_ref().map_or(0, String::len);
    let mut first_page_runs = Vec::new();
    let mut revalidate_runs = Vec::new();
    for _ in 0..iterations * 20 {
        let started = Instant::now();
        let _ = snapshot.read(&request("index", "limit=50", None, &digest));
        first_page_runs.push(millis(started.elapsed()));
        let started = Instant::now();
        let unchanged = snapshot.read(&request(
            "index",
            "limit=50",
            first.etag.as_deref(),
            &digest,
        ));
        revalidate_runs.push(millis(started.elapsed()));
        assert_eq!(unchanged.http_status, 304);
    }

    let (mut detail_bytes, mut collection_bytes, mut collection_pages) = (0, 0, 0);
    let mut detail_runs = Vec::new();
    let mut everything_runs = Vec::new();
    for round in 0..iterations {
        let everything = Instant::now();
        let mut detail_elapsed = Duration::ZERO;
        for id in &index.ids {
            let route = format!("extensions/{id}");
            let started = Instant::now();
            let detail = snapshot.read(&request(&route, "", None, &digest));
            detail_elapsed += started.elapsed();
            let body = detail.body.expect("detail body");
            let parsed: Value = serde_json::from_str(&body).expect("detail json");
            let collections = parsed["collections"].as_object().expect("collections");
            for (name, id_key) in [
                ("permissions", "permission_id"),
                ("rules", "rule_id"),
                ("mcp_tools", "name"),
            ] {
                if !collections.contains_key(name) {
                    continue;
                }
                let segment = if name == "mcp_tools" {
                    "mcp-tools"
                } else {
                    name
                };
                let traversal = traverse(&snapshot, &format!("{route}/{segment}"), 100, id_key);
                if round == 0 {
                    collection_bytes += traversal.bytes;
                    collection_pages += traversal.pages;
                }
            }
            if round == 0 {
                detail_bytes += body.len();
            }
        }
        detail_runs.push(millis(detail_elapsed));
        everything_runs.push(millis(everything.elapsed()));
    }

    // Catalog-wide permission search (`permissions?q=`), as `extensions patterns`
    // issues it: one selective phrase and one broad single term.
    let mut search = serde_json::Map::new();
    for (label, base) in [
        ("git_push", "limit=100&q=git+push"),
        ("broad_term_run", "limit=100&q=run"),
        ("unfiltered", "limit=100"),
    ] {
        let mut runs = Vec::new();
        let mut traversal = traverse_query(&snapshot, "permissions", base, "permission_id");
        for _ in 0..iterations {
            let started = Instant::now();
            traversal = traverse_query(&snapshot, "permissions", base, "permission_id");
            runs.push(millis(started.elapsed()));
        }
        search.insert(
            label.into(),
            json!({"matches": traversal.ids.len(), "pages": traversal.pages, "bytes": traversal.bytes, "median_ms": median(runs)}),
        );
    }

    println!(
        "{}",
        json!({
            "corpus": path,
            "corpus_bytes": bytes.len(),
            "admitted": true,
            "extensions": index.ids.len(),
            "iterations": iterations,
            "snapshot_encoded_bytes": snapshot.encoded_bytes(),
            "snapshot_build_ms": {"first": build_ms, "median": median(builds)},
            "index_first_page_limit50": {"bytes": first_page_bytes, "median_ms": median(first_page_runs)},
            "index_revalidate_304_median_ms": median(revalidate_runs),
            "index_traversal_limit100": {"pages": index.pages, "bytes": index.bytes, "median_ms": median(index_runs)},
            "all_details": {"bytes": detail_bytes, "median_ms": median(detail_runs)},
            "all_collections": {"pages": collection_pages, "bytes": collection_bytes},
            "full_export_equivalent_median_ms": median(everything_runs),
            "permission_search_limit100": search,
        })
    );
}
