//! Compile node configurations and validate graph relationships.

use super::*;

fn child_index(
    children: &BTreeMap<String, Value>,
    key: &str,
    indices: &BTreeMap<String, usize>,
) -> Result<usize, &'static str> {
    children
        .get(key)
        .and_then(Value::as_str)
        .and_then(|id| indices.get(id))
        .copied()
        .ok_or("native_command_node_missing")
}

pub(super) fn compile_node(
    node: RawNode,
    indices: &BTreeMap<String, usize>,
) -> Result<Node, &'static str> {
    if matches!(
        node.op.as_str(),
        "executable.v1" | "executable-path-set.v1" | "arguments.v1"
    ) && !ascii_configuration(&node.config)
    {
        return Err("native_command_ascii_configuration_required");
    }
    let matcher = match node.op.as_str() {
        "any.v1" | "all.v1" => {
            if node
                .config
                .as_object()
                .is_none_or(|value| !value.is_empty())
                || node.children.len() != 1
            {
                return Err("native_command_combinator_invalid");
            }
            let children = node
                .children
                .get("matchers")
                .and_then(Value::as_array)
                .ok_or("native_command_combinator_invalid")?;
            if children.is_empty() || children.len() > 4_096 {
                return Err("native_command_combinator_invalid");
            }
            let children = children
                .iter()
                .map(|id| {
                    id.as_str()
                        .and_then(|id| indices.get(id))
                        .copied()
                        .ok_or("native_command_node_missing")
                })
                .collect::<Result<Vec<_>, _>>()?;
            if node.op == "any.v1" {
                Matcher::Any(children)
            } else {
                Matcher::All(children)
            }
        }
        "pipeline.v1" => {
            if node
                .config
                .as_object()
                .is_none_or(|value| !value.is_empty())
                || node.children.len() != 2
            {
                return Err("native_command_combinator_invalid");
            }
            Matcher::Pipeline(
                child_index(&node.children, "producer", indices)?,
                child_index(&node.children, "consumer", indices)?,
            )
        }
        operation => {
            if !node.children.is_empty() {
                return Err("native_command_unexpected_children");
            }
            match operation {
                "executable.v1" | "executable-path-set.v1" => {
                    Matcher::Executable(compile_executable(operation, node.config)?)
                }
                "arguments.v1" => Matcher::Arguments(
                    serde_json::from_value(node.config)
                        .map_err(|_| "native_command_arguments_invalid")?,
                ),
                "leading-operand-count.v1"
                | "subcommand-operand-prefix.v1"
                | "option-value-key.v1"
                | "environment-name.v1" => {
                    Matcher::Structured(StructuredMatcher::from_config(operation, node.config)?)
                }
                "operand-gated-flags.v1"
                | "trailing-operand-prefix.v1"
                | "trailing-operand-host-target.v1"
                | "trailing-operand-remote-alias.v1" => {
                    Matcher::Operand(OperandMatcher::from_config(operation, node.config)?)
                }
                "argument-command.v1" | "command-sequence.v1" | "leading-subcommand.v1" => {
                    Matcher::Database(DatabaseMatcher::from_config(operation, node.config)?)
                }
                "zero-operand-flags.v1"
                | "php-artisan-script.v1"
                | "curl-elasticsearch-delete.v1"
                | "repo2nb-expansion.v1"
                | "errand-command.v1"
                | "reviewed-literal.v1" => {
                    Matcher::Specialized(SpecializedMatcher::from_config(operation, node.config)?)
                }
                "ansible-execution.v1"
                | "sql-option-mutation.v1"
                | "dotnet-project-package.v1"
                | "mongo-eval-mutation.v1"
                | "sqlite-mutation.v1"
                | "openshift-delete-drain.v1"
                | "openshift-mutation.v1" => {
                    Matcher::CommonCli(CommonCliMatcher::from_config(operation, node.config)?)
                }
                _ => return Err("native_command_operation_unknown"),
            }
        }
    };
    Ok(Node {
        operation: node.op,
        matcher,
    })
}

fn compile_executable(operation: &str, mut config: Value) -> Result<ExecutableNode, &'static str> {
    let object = config
        .as_object_mut()
        .ok_or("native_command_executable_invalid")?;
    let mut paths: Vec<Vec<String>> = if operation == "executable.v1" {
        vec![serde_json::from_value(
            object
                .remove("subcommands")
                .ok_or("native_command_subcommands_missing")?,
        )
        .map_err(|_| "native_command_subcommands_invalid")?]
    } else {
        serde_json::from_value(
            object
                .remove("paths")
                .ok_or("native_command_paths_missing")?,
        )
        .map_err(|_| "native_command_paths_invalid")?
    };
    if paths.is_empty()
        || paths.len() > 4_096
        || paths.iter().any(|path| {
            path.len() > 4_096
                || path
                    .iter()
                    .any(|token| token.is_empty() || token.len() > 4_096)
        })
    {
        return Err("native_command_paths_invalid");
    }
    if operation == "executable-path-set.v1" && paths.iter().any(Vec::is_empty) {
        return Err("native_command_paths_invalid");
    }
    paths.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    let contract: ExecutableFlagContract =
        serde_json::from_value(config).map_err(|_| "native_command_executable_invalid")?;
    contract.validate()?;
    let all_value_options = contract.all_value_options();
    let proof_known_flags = contract
        .interspersed_flags
        .iter()
        .chain(&contract.required_flags)
        .chain(&contract.forbidden_flags)
        .chain(
            contract
                .inverse_flag_pairs
                .iter()
                .flat_map(|(positive, negative)| [positive, negative]),
        )
        .cloned()
        .collect();
    Ok(ExecutableNode {
        contract,
        paths,
        all_value_options,
        proof_known_flags,
    })
}

fn graph_children(matcher: &Matcher) -> Vec<usize> {
    match matcher {
        Matcher::Any(children) | Matcher::All(children) => children.clone(),
        Matcher::Pipeline(producer, consumer) => vec![*producer, *consumer],
        _ => Vec::new(),
    }
}

pub(super) fn validate_graph(
    index: usize,
    nodes: &[Node],
    visit: &mut [u8],
    heights: &mut [usize],
    depth: usize,
) -> Result<usize, &'static str> {
    if depth > MAX_DEPTH || visit[index] == 1 {
        return Err("native_command_matcher_cycle_or_depth");
    }
    if visit[index] == 2 {
        return if depth + heights[index] > MAX_DEPTH {
            Err("native_command_matcher_cycle_or_depth")
        } else {
            Ok(heights[index])
        };
    }
    visit[index] = 1;
    let mut height = 0;
    for child in graph_children(&nodes[index].matcher) {
        height = height.max(validate_graph(child, nodes, visit, heights, depth + 1)? + 1);
        if height > MAX_DEPTH {
            return Err("native_command_matcher_cycle_or_depth");
        }
    }
    visit[index] = 2;
    heights[index] = height;
    Ok(height)
}

fn ascii_configuration(value: &Value) -> bool {
    match value {
        Value::String(value) => value.is_ascii() && value.len() <= 4_096,
        Value::Array(values) => values.len() <= 4_096 && values.iter().all(ascii_configuration),
        Value::Object(values) => values.len() <= 4_096 && values.values().all(ascii_configuration),
        Value::Bool(_) => true,
        _ => false,
    }
}
