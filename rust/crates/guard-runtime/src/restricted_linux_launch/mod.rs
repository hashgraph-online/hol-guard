//! The private namespace launcher executes only the fixed, hash-bound plan.
#[cfg(target_os = "linux")]
mod argv;
#[cfg(target_os = "linux")]
mod json;
mod mapping_records;
mod mounts;
#[cfg(target_os = "linux")]
mod plan;
mod socket;
type BoundaryResult<T> = Result<T, &'static str>;
#[cfg(target_os = "linux")]
mod admission;
#[cfg(all(test, target_os = "linux"))]
mod boundary_tests;
#[cfg(target_os = "linux")]
mod capabilities;
#[cfg(unix)]
mod elf;
#[cfg(unix)]
mod index_snapshot;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod mapping_copy;
#[cfg(target_os = "linux")]
mod mappings;
#[cfg(unix)]
mod paths;
#[cfg(target_os = "linux")]
mod pipeline;
#[cfg(target_os = "linux")]
mod prepare;
#[cfg(target_os = "linux")]
mod read;
#[cfg(all(test, target_os = "linux"))]
mod tests;

pub(crate) fn evaluate(
    operation: &str,
    input: &serde_json::Value,
    deadline: std::time::Instant,
) -> serde_json::Value {
    if operation == "linux_socket_filter" {
        return match input["machine"]
            .as_str()
            .ok_or("Unsupported Linux socket-filter architecture.")
            .and_then(socket::instructions)
        {
            Ok(instructions) => serde_json::json!({"value":{"instructions":instructions}}),
            Err(message) => {
                serde_json::json!({"reason_code":"pytest_restricted_sandbox_unavailable","message":message})
            }
        };
    }
    if operation == "linux_mount_targets" {
        let result = input["raw_hex"]
            .as_str()
            .ok_or("Malformed namespace mount snapshot.")
            .and_then(|v| hex::decode(v).map_err(|_| "Malformed namespace mount snapshot."))
            .and_then(|v| mounts::targets(&v))
            .map(|targets| serde_json::json!({"targets":targets}));
        return reply(result);
    }
    if operation == "linux_validate_records" {
        let result = serde_json::from_value::<std::collections::BTreeSet<std::path::PathBuf>>(input["approved_paths"].clone())
            .map_err(|_| "Unbound executable mapping.")
            .and_then(|approved| mapping_records::validate(&input["records"],&approved))
            .map(|v| serde_json::json!({"records":v.into_iter().map(|v| (v.path,v.identity,v.digest,v.aliases)).collect::<Vec<_>>()}));
        return reply(result);
    }
    #[cfg(unix)]
    if operation == "linux_read_grants" {
        let result = input["root"]
            .as_str()
            .and_then(|root| input["max_entries"].as_u64().map(|limit| (root, limit)))
            .ok_or("Invalid Linux workspace discovery boundary.")
            .and_then(|(root, limit)| {
                usize::try_from(limit)
                    .map_err(|_| "Invalid Linux workspace discovery boundary.")
                    .and_then(|limit| paths::collect(std::path::Path::new(root), limit, deadline))
            })
            .and_then(|value| {
                input["result_snapshot"]
                    .as_str()
                    .ok_or("Linux workspace index transport is unavailable.")
                    .and_then(|path| {
                        index_snapshot::write(std::path::Path::new(path), &value, deadline)
                    })
            });
        return reply(result);
    }
    #[cfg(unix)]
    if operation == "linux_elf_loader" {
        return reply(
            input["executable"]
                .as_str()
                .ok_or("Invalid Linux executable.")
                .and_then(|path| elf::resolve(std::path::Path::new(path)))
                .map(|v| serde_json::json!(v)),
        );
    }
    #[cfg(target_os = "linux")]
    let result = match operation {
        "linux_readonly_argv" => prepare::argv(input, deadline),
        _ => Err("Unsupported Linux execution operation."),
    };
    #[cfg(not(target_os = "linux"))]
    let result: Result<serde_json::Value, &str> = {
        let _ = (operation, input, deadline);
        Err("No native Linux execution boundary is available.")
    };
    reply(result)
}

fn reply(result: BoundaryResult<serde_json::Value>) -> serde_json::Value {
    match result {
        Ok(value) => serde_json::json!({"value":value}),
        Err(message) => {
            serde_json::json!({"reason_code":"pytest_restricted_sandbox_unavailable","message":message})
        }
    }
}

#[cfg(target_os = "linux")]
fn enter(digest: &str) -> plan::Result<()> {
    pipeline::enter(read::load(digest)?)
}

pub(crate) fn launch(digest: &str) -> i32 {
    #[cfg(target_os = "linux")]
    let result = enter(digest);
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), &str> = {
        let _ = digest;
        Err("Unsupported Linux boundary.")
    };
    if result.is_err() {
        eprintln!("HOL Guard could not enforce the validated Linux execution boundary. Execution was not started.");
    }
    126
}
