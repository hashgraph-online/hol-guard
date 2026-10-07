//! Exact, side-effect-free parsing for the supported Unix `env` contract
//! (`runtime/env_wrapper.py`, 340 lines — verbatim).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::home_path_text::normalize_path;
use crate::shell_tokens;

pub const ENV_SPLIT_MAX_BYTES: usize = 8192;
pub const ENV_SPLIT_MAX_EXPANSIONS: usize = 4;
pub const ENV_TOKEN_MAX_COUNT: usize = 256;

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct EnvEnvironmentDelta {
    pub clear: bool,
    pub unset_names: Vec<String>,
    pub assignments: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct EnvOptionEffects {
    pub ignore_environment: bool,
    pub unset_names: Vec<String>,
    pub chdir: Option<String>,
    pub search_path: Option<String>,
    pub verbose: bool,
    pub null_output: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct EnvSplitExpansion {
    pub payload: String,
    pub source_index: usize,
    pub tokens: Vec<String>,
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct EnvWrapperParseResult {
    pub complete: bool,
    pub error: Option<String>,
    pub original_tokens: Vec<String>,
    pub expanded_tokens: Vec<String>,
    pub option_effects: EnvOptionEffects,
    pub environment_delta: EnvEnvironmentDelta,
    pub effective_environment: Option<Vec<(String, String)>>,
    pub effective_cwd: Option<PathBuf>,
    pub command_index: Option<usize>,
    pub executable_argv: Vec<String>,
    pub split_expansions: Vec<EnvSplitExpansion>,
}

#[derive(Clone, Debug)]
struct SourcedToken {
    value: String,
    source_index: usize,
}

/// `parse_env_wrapper` (:66-289).
pub fn parse_env_wrapper(
    tokens: &[String],
    inherited_environment: Option<&BTreeMap<String, String>>,
    cwd: Option<&Path>,
) -> EnvWrapperParseResult {
    let original_tokens: Vec<String> = tokens.to_vec();
    let mut working: Vec<SourcedToken> = original_tokens
        .iter()
        .enumerate()
        .map(|(i, v)| SourcedToken {
            value: v.clone(),
            source_index: i,
        })
        .collect();
    let mut environment: Option<BTreeMap<String, String>> = inherited_environment.cloned();
    let mut ignore_environment = false;
    let mut unset_names: Vec<String> = Vec::new();
    let mut assignments: Vec<(String, String)> = Vec::new();
    let mut chdir_operand: Option<String> = None;
    let mut search_path: Option<String> = None;
    let mut verbose = false;
    let mut null_output = false;
    let mut split_expansions: Vec<EnvSplitExpansion> = Vec::new();
    let mut options = true;
    let mut index = 0usize;

    macro_rules! result {
        ($complete:expr, $error:expr, $command_index:expr) => {{
            let effective_cwd = effective_cwd(cwd, chdir_operand.as_deref());
            let executable_argv = match $command_index {
                Some(ci) if ci < working.len() => {
                    working[ci..].iter().map(|t| t.value.clone()).collect()
                }
                _ => Vec::new(),
            };
            EnvWrapperParseResult {
                complete: $complete,
                error: $error,
                original_tokens: original_tokens.clone(),
                expanded_tokens: working.iter().map(|t| t.value.clone()).collect(),
                option_effects: EnvOptionEffects {
                    ignore_environment,
                    unset_names: unset_names.clone(),
                    chdir: chdir_operand.clone(),
                    search_path: search_path.clone(),
                    verbose,
                    null_output,
                },
                environment_delta: EnvEnvironmentDelta {
                    clear: ignore_environment,
                    unset_names: unset_names.clone(),
                    assignments: assignments.clone(),
                },
                effective_environment: environment
                    .as_ref()
                    .map(|e| e.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                effective_cwd,
                command_index: $command_index,
                executable_argv,
                split_expansions: split_expansions.clone(),
            }
        }};
    }
    macro_rules! fail {
        ($error:expr) => {
            result!(false, Some($error.to_owned()), None::<usize>)
        };
    }

    while index < working.len() {
        if working.len() > ENV_TOKEN_MAX_COUNT {
            return fail!("token_limit_exceeded");
        }
        let token = working[index].value.clone();
        let source_index = working[index].source_index;
        if token.contains('\0') {
            return fail!("nul_token");
        }
        let assignment = env_assignment(&token);
        if !options {
            if token == "--" {
                index += 1;
                return result!(
                    true,
                    None::<String>,
                    if index < working.len() {
                        Some(index)
                    } else {
                        None
                    }
                );
            }
            if let Some((name, value)) = assignment {
                assignments.push((name.clone(), value.clone()));
                if let Some(env) = environment.as_mut() {
                    env.insert(name, value);
                }
                index += 1;
                continue;
            }
            return result!(true, None::<String>, Some(index));
        }
        if token == "--" {
            options = false;
            index += 1;
            continue;
        }
        if token == "-" {
            ignore_environment = true;
            if let Some(env) = environment.as_mut() {
                env.clear();
            }
            index += 1;
            continue;
        }
        if !token.starts_with('-') {
            if let Some((name, value)) = assignment {
                options = false;
                assignments.push((name.clone(), value.clone()));
                if let Some(env) = environment.as_mut() {
                    env.insert(name, value);
                }
                index += 1;
                continue;
            }
            return result!(true, None::<String>, Some(index));
        }

        if token.starts_with("--") {
            let (option_name, separator, attached) = {
                let mut it = token.splitn(2, '=');
                let name = it.next().unwrap_or("").to_owned();
                let attached = it.next();
                (name, attached.is_some(), attached.unwrap_or("").to_owned())
            };
            if option_name == "--ignore-environment" && !separator {
                ignore_environment = true;
                if let Some(env) = environment.as_mut() {
                    env.clear();
                }
                index += 1;
                continue;
            }
            if option_name == "--debug" && !separator {
                verbose = true;
                index += 1;
                continue;
            }
            if option_name == "--null" && !separator {
                null_output = true;
                index += 1;
                continue;
            }
            if !["--unset", "--chdir", "--split-string"].contains(&option_name.as_str()) {
                return fail!("unsupported_option");
            }
            let (operand, consumed, operand_source) = if separator {
                (attached, 1usize, source_index)
            } else {
                if index + 1 >= working.len() {
                    return fail!(missing_operand_error(&option_name));
                }
                (
                    working[index + 1].value.clone(),
                    2usize,
                    working[index + 1].source_index,
                )
            };
            if option_name == "--unset" {
                if operand.is_empty() || operand.contains('=') || operand.contains('\0') {
                    return fail!("invalid_unset_operand");
                }
                unset_names.push(operand.clone());
                if let Some(env) = environment.as_mut() {
                    env.remove(&operand);
                }
                index += consumed;
                continue;
            }
            if option_name == "--chdir" {
                if operand.is_empty() || operand.contains('\0') {
                    return fail!("invalid_chdir_operand");
                }
                chdir_operand = Some(operand);
                index += consumed;
                continue;
            }
            let expansion = match split_expansion(&operand, operand_source) {
                SplitOutcome::Ok(e) => e,
                SplitOutcome::Err(e) => return fail!(e),
            };
            if split_expansions.len() >= ENV_SPLIT_MAX_EXPANSIONS {
                return fail!("split_string_limit_exceeded");
            }
            let repl_tokens = expansion.tokens.clone();
            split_expansions.push(expansion);
            working.splice(
                index..index + consumed,
                repl_tokens.into_iter().map(|v| SourcedToken {
                    value: v,
                    source_index: operand_source,
                }),
            );
            continue;
        }

        // short option cluster.
        let chars: Vec<char> = token.chars().collect();
        let mut short_index = 1usize;
        let mut tokens_consumed = 1usize;
        let mut replace_with_split: Option<(usize, EnvSplitExpansion)> = None;
        while short_index < chars.len() {
            let flag = chars[short_index];
            if flag == '0' {
                null_output = true;
                short_index += 1;
                continue;
            }
            if flag == 'i' {
                ignore_environment = true;
                if let Some(env) = environment.as_mut() {
                    env.clear();
                }
                short_index += 1;
                continue;
            }
            if flag == 'v' {
                verbose = true;
                short_index += 1;
                continue;
            }
            if !['u', 'C', 'S', 'P'].contains(&flag) {
                return fail!("unsupported_option");
            }
            let attached_operand: String = chars[short_index + 1..].iter().collect();
            let (operand, consumed, operand_source) = if !attached_operand.is_empty() {
                (attached_operand, 1usize, source_index)
            } else {
                if index + 1 >= working.len() {
                    return fail!(missing_operand_error(&format!("-{flag}")));
                }
                (
                    working[index + 1].value.clone(),
                    2usize,
                    working[index + 1].source_index,
                )
            };
            tokens_consumed = consumed;
            if flag == 'u' {
                if operand.is_empty() || operand.contains('=') || operand.contains('\0') {
                    return fail!("invalid_unset_operand");
                }
                unset_names.push(operand.clone());
                if let Some(env) = environment.as_mut() {
                    env.remove(&operand);
                }
            } else if flag == 'C' {
                if operand.is_empty() || operand.contains('\0') {
                    return fail!("invalid_chdir_operand");
                }
                chdir_operand = Some(operand);
            } else if flag == 'P' {
                if operand.contains('\0') {
                    return fail!("invalid_search_path_operand");
                }
                search_path = Some(operand);
            } else {
                let expansion = match split_expansion(&operand, operand_source) {
                    SplitOutcome::Ok(e) => e,
                    SplitOutcome::Err(e) => return fail!(e),
                };
                if split_expansions.len() >= ENV_SPLIT_MAX_EXPANSIONS {
                    return fail!("split_string_limit_exceeded");
                }
                split_expansions.push(expansion.clone());
                replace_with_split = Some((consumed, expansion));
            }
            // Python ends the option cluster after any operand-consuming flag
            // with `short_index = len(token)`. Without this the loop re-reads
            // the same flag until ENV_SPLIT_MAX_EXPANSIONS trips.
            short_index = chars.len();
        }
        if let Some((consumed, expansion)) = replace_with_split {
            let repl = expansion.tokens.clone();
            working.splice(
                index..index + consumed,
                repl.into_iter().map(|v| SourcedToken {
                    value: v,
                    source_index: expansion.source_index,
                }),
            );
            continue;
        }
        index += tokens_consumed;
    }

    result!(true, None::<String>, None::<usize>)
}

/// `_env_assignment` (:291-295).
fn env_assignment(token: &str) -> Option<(String, String)> {
    let (name, sep, value) = match token.find('=') {
        Some(i) => (&token[..i], true, &token[i + 1..]),
        None => (token, false, ""),
    };
    if !sep || name.is_empty() || name.contains('\0') {
        return None;
    }
    Some((name.to_owned(), value.to_owned()))
}

/// `_missing_operand_error` (:298-305).
fn missing_operand_error(option: &str) -> String {
    match option {
        "-u" | "--unset" => "missing_unset_operand".to_owned(),
        "-C" | "--chdir" => "missing_chdir_operand".to_owned(),
        "-P" => "missing_search_path_operand".to_owned(),
        _ => "missing_split_string_operand".to_owned(),
    }
}

enum SplitOutcome {
    Ok(EnvSplitExpansion),
    Err(String),
}

/// `_split_expansion` (:308-319).
fn split_expansion(payload: &str, source_index: usize) -> SplitOutcome {
    if payload.len() > ENV_SPLIT_MAX_BYTES {
        return SplitOutcome::Err("split_string_byte_limit_exceeded".to_owned());
    }
    if payload.contains('\0') {
        return SplitOutcome::Err("split_string_nul".to_owned());
    }
    let tokens = match shell_tokens(payload, false) {
        Ok(t) => t,
        Err(_) => return SplitOutcome::Err("split_string_syntax_error".to_owned()),
    };
    if tokens.len() > ENV_TOKEN_MAX_COUNT {
        return SplitOutcome::Err("token_limit_exceeded".to_owned());
    }
    SplitOutcome::Ok(EnvSplitExpansion {
        payload: payload.to_owned(),
        source_index,
        tokens,
    })
}

/// `_effective_cwd` (:322-328).
fn effective_cwd(cwd: Option<&Path>, operand: Option<&str>) -> Option<PathBuf> {
    let operand = match operand {
        Some(o) => o,
        None => return cwd.map(Path::to_path_buf),
    };
    let candidate = Path::new(operand);
    if candidate.is_absolute() || cwd.is_none() {
        return Some(PathBuf::from(normalize_path(operand, None)));
    }
    let joined = cwd.unwrap().join(candidate).to_string_lossy().into_owned();
    Some(PathBuf::from(normalize_path(&joined, None)))
}
