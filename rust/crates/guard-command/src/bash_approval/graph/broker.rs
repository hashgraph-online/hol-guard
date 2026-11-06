use super::{Result, Uncertainty, MAX_RENDERED_BYTES};

pub(super) const MAX_HELPER_ARGUMENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDelivery {
    ReadonlySystem,
    HardenedBroker,
}

pub(super) fn render(source: String, enabled: bool) -> Result<String> {
    if !enabled {
        return Ok(source);
    }
    let prefix = r#"__guard_broker_call() {
  builtin local __guard_id="$1" __guard_stdin="$2" __guard_status __guard_stdout __guard_stderr
  shift 2
  builtin printf '%s\n' "$__guard_id" >&7 || return 126
  if [ "$__guard_stdin" = 1 ]; then
    /usr/bin/base64 >&7 || return 126
    builtin printf '\n.\n' >&7 || return 126
  fi
  IFS= builtin read -r __guard_status <&7 || return 126
  IFS= builtin read -r __guard_stdout <&7 || return 126
  IFS= builtin read -r __guard_stderr <&7 || return 126
  case "$__guard_status" in ''|*[!0-9]*) return 126;; esac
  [ "$__guard_status" -le 255 ] || return 126
  builtin printf '%b' "$__guard_stdout"
  builtin printf '%b' "$__guard_stderr" >&2
  return "$__guard_status"
}
"#;
    if prefix.len().saturating_add(source.len()) > MAX_RENDERED_BYTES {
        return Err(Uncertainty {
            reason: "bash_rendered_source_bounds",
            line: 1,
        });
    }
    Ok(format!("{prefix}{source}"))
}
